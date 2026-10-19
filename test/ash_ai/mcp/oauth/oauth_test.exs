# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.OAuthTest do
  use ExUnit.Case, async: true

  alias AshAi.Mcp.OAuth
  alias AshAi.Mcp.OAuth.{Client, Pending, Token}
  alias AshAi.Test.{FakeOAuthServer, OAuthMemoryStore}

  @server "https://mcp.example.com/mcp"
  @redirect_uri "https://app.example.com/oauth/callback"
  @metadata_url "https://app.example.com/oauth/client.json"

  setup do
    {:ok, as} = FakeOAuthServer.start_link()
    {:ok, store} = OAuthMemoryStore.start_link()

    opts = [
      store: {OAuthMemoryStore, pid: store},
      redirect_uri: @redirect_uri,
      client_name: "Test App",
      req_options: [plug: {FakeOAuthServer, as}]
    ]

    %{as: as, store: store, opts: opts}
  end

  describe "client selection" do
    test "prefers pre-registered credentials", %{as: as, opts: opts} do
      opts =
        opts
        |> Keyword.put(:pre_registered, %{
          "https://MCP.example.com/mcp" => [issuer: "https://auth.example.com", client_id: "pre"]
        })
        |> Keyword.put(:client_metadata_url, @metadata_url)

      put_as_metadata(as, %{"client_id_metadata_document_supported" => true})

      assert {:ok, url, %Pending{client_id: "pre"}} = OAuth.authorize_url(@server, "u1", opts)
      assert query(url)["client_id"] == "pre"
      refute Enum.any?(FakeOAuthServer.requests(as), &(&1.path == "/register"))
    end

    test "uses pre-registered credentials only for their server", %{as: as, opts: opts} do
      other = "https://other.example.com/mcp"
      add_mcp_server(as, "other.example.com")

      opts =
        Keyword.put(opts, :pre_registered, %{
          @server => [issuer: "https://auth.example.com", client_id: "pre"]
        })

      # The other server names the same authorization server, but registers its own client
      assert {:ok, _url, %Pending{client_id: "dcr-" <> _}} =
               OAuth.authorize_url(other, "u1", opts)
    end

    test "refuses pre-registered credentials when the server names another issuer", %{
      as: as,
      opts: opts
    } do
      opts =
        Keyword.put(opts, :pre_registered, fn
          @server -> [issuer: "https://honest-auth.example.com", client_id: "pre"]
          _ -> nil
        end)

      assert {:error,
              {:pre_registered_issuer_mismatch, "https://honest-auth.example.com",
               "https://auth.example.com"}} = OAuth.authorize_url(@server, "u1", opts)

      refute Enum.any?(FakeOAuthServer.requests(as), &(&1.path == "/register"))
    end

    test "uses a Client ID Metadata Document when the server supports them", %{as: as, opts: opts} do
      put_as_metadata(as, %{"client_id_metadata_document_supported" => true})
      opts = Keyword.put(opts, :client_metadata_url, @metadata_url)

      assert {:ok, url, %Pending{client_id: @metadata_url}} =
               OAuth.authorize_url(@server, "u1", opts)

      assert query(url)["client_id"] == @metadata_url
      refute Enum.any?(FakeOAuthServer.requests(as), &(&1.path == "/register"))
    end

    test "registers dynamically otherwise, and reuses the registration", %{
      as: as,
      store: store,
      opts: opts
    } do
      opts = Keyword.put(opts, :client_metadata_url, @metadata_url)

      assert {:ok, _url, %Pending{client_id: "dcr-" <> _ = client_id}} =
               OAuth.authorize_url(@server, "u1", opts)

      assert {:ok, _url, %Pending{client_id: ^client_id}} =
               OAuth.authorize_url(@server, "u2", opts)

      assert [%{params: params}] =
               Enum.filter(FakeOAuthServer.requests(as), &(&1.path == "/register"))

      assert params["redirect_uris"] == [@redirect_uri]
      assert params["application_type"] == "web"
      assert params["grant_types"] == ["authorization_code", "refresh_token"]

      assert %{"client_id" => ^client_id} =
               OAuthMemoryStore.state(store).clients[{@server, "https://auth.example.com"}]

      # Another MCP server using the same authorization server registers its
      # own client, so consent given for this one doesn't carry over
      add_mcp_server(as, "other.example.com")

      assert {:ok, _url, %Pending{client_id: "dcr-" <> _ = other_client_id}} =
               OAuth.authorize_url("https://other.example.com/mcp", "u1", opts)

      assert other_client_id != client_id
    end

    test "asks for credentials when nothing else works", %{as: as, opts: opts} do
      put_as_metadata(as, %{"registration_endpoint" => nil})
      assert {:error, :client_registration_required} = OAuth.authorize_url(@server, "u1", opts)
    end
  end

  describe "authorize_url/3" do
    test "builds a PKCE authorization request for the server's resource", %{
      store: store,
      opts: opts
    } do
      assert {:ok, url, pending} = OAuth.authorize_url(@server, "u1", opts)

      assert String.starts_with?(url, "https://auth.example.com/authorize?")
      params = query(url)
      assert params["response_type"] == "code"
      assert params["redirect_uri"] == @redirect_uri
      assert params["state"] == pending.state
      assert params["code_challenge_method"] == "S256"

      assert params["code_challenge"] ==
               Base.url_encode64(:crypto.hash(:sha256, pending.code_verifier), padding: false)

      assert params["resource"] == @server
      # scopes_supported from the resource, plus offline_access the AS offers
      assert params["scope"] == "mcp:read offline_access"

      assert pending.issuer == "https://auth.example.com"
      assert pending.iss_parameter_supported
      assert Map.has_key?(OAuthMemoryStore.state(store).pending, pending.state)
    end

    test "prefers the challenge's scope", %{opts: opts} do
      opts = Keyword.merge(opts, challenge: ~s(Bearer scope="mcp:write"), offline_access: false)
      assert {:ok, url, _} = OAuth.authorize_url(@server, "u1", opts)
      assert query(url)["scope"] == "mcp:write"
    end

    test "refuses plain-HTTP MCP servers off loopback", %{opts: opts} do
      assert {:error, {:insecure_url, "http://mcp.example.com/mcp"}} =
               OAuth.authorize_url("http://mcp.example.com/mcp", "u1", opts)

      assert {:error, {:insecure_url, "http://mcp.example.com/mcp"}} =
               OAuth.headers("http://mcp.example.com/mcp", Keyword.put(opts, :owner, "u1"))

      assert {:error, {:authorization_required, _}} =
               OAuth.headers("http://localhost:4000/mcp", Keyword.put(opts, :owner, "u1"))
    end

    test "requires a secure redirect URI", %{opts: opts} do
      assert {:error, {:insecure_url, _}} =
               OAuth.authorize_url(
                 @server,
                 "u1",
                 Keyword.put(opts, :redirect_uri, "http://app.example.com/cb")
               )

      assert {:ok, _, _} =
               OAuth.authorize_url(
                 @server,
                 "u1",
                 Keyword.put(opts, :redirect_uri, "http://localhost:4000/cb")
               )
    end
  end

  describe "handle_callback/3" do
    test "exchanges the code and stores the token", %{as: as, store: store, opts: opts} do
      {:ok, url, pending} = OAuth.authorize_url(@server, "u1", opts)
      code = FakeOAuthServer.approve(as, url)

      assert {:ok, %Token{} = token, %Pending{owner: "u1"}} =
               OAuth.handle_callback(
                 %{"code" => code, "state" => pending.state, "iss" => "https://auth.example.com"},
                 "u1",
                 opts
               )

      assert token.access_token == "at-1"
      assert token.refresh_token == "rt-1"
      assert token.scope == "mcp:read offline_access"
      assert token.resource == @server
      assert DateTime.diff(token.expires_at, DateTime.utc_now()) in 3590..3600
      assert {:ok, %Token{access_token: "at-1"}} = OAuth.access_token(@server, "u1", opts)
      assert OAuthMemoryStore.state(store).pending == %{}

      # The pending authorization is single-use
      assert {:error, :invalid_state} =
               OAuth.handle_callback(
                 %{"code" => code, "state" => pending.state, "iss" => "https://auth.example.com"},
                 "u1",
                 opts
               )
    end

    test "refuses a callback completed by someone other than the owner", %{
      as: as,
      store: store,
      opts: opts
    } do
      {:ok, url, pending} = OAuth.authorize_url(@server, "attacker", opts)
      code = FakeOAuthServer.approve(as, url)
      params = %{"code" => code, "state" => pending.state, "iss" => "https://auth.example.com"}

      assert {:error, :owner_mismatch} = OAuth.handle_callback(params, "victim", opts)

      refute Enum.any?(FakeOAuthServer.requests(as), &(&1.path == "/token"))
      assert OAuthMemoryStore.state(store).tokens == %{}

      # The pending authorization is spent, so the URL can't be completed later
      assert {:error, :invalid_state} = OAuth.handle_callback(params, "attacker", opts)
    end

    test "rejects an unknown state", %{opts: opts} do
      assert {:error, :invalid_state} =
               OAuth.handle_callback(%{"code" => "c", "state" => "nope"}, "u1", opts)

      assert {:error, :missing_state} = OAuth.handle_callback(%{"code" => "c"}, "u1", opts)
    end

    test "validates iss before using the code or the error", %{as: as, opts: opts} do
      {:ok, url, pending} = OAuth.authorize_url(@server, "u1", opts)
      code = FakeOAuthServer.approve(as, url)

      assert {:error, {:issuer_mismatch, "https://auth.example.com", "https://evil.example"}} =
               OAuth.handle_callback(
                 %{"code" => code, "state" => pending.state, "iss" => "https://evil.example"},
                 "u1",
                 opts
               )

      refute Enum.any?(FakeOAuthServer.requests(as), &(&1.path == "/token"))

      {:ok, _url, pending} = OAuth.authorize_url(@server, "u1", opts)

      assert {:error, {:issuer_mismatch, _, _}} =
               OAuth.handle_callback(
                 %{
                   "error" => "access_denied",
                   "state" => pending.state,
                   "iss" => "https://evil.example"
                 },
                 "u1",
                 opts
               )

      {:ok, _url, pending} = OAuth.authorize_url(@server, "u1", opts)

      # The server advertises iss, so a response without one is rejected
      assert {:error, :missing_issuer} =
               OAuth.handle_callback(%{"code" => code, "state" => pending.state}, "u1", opts)

      {:ok, _url, pending} = OAuth.authorize_url(@server, "u1", opts)

      assert {:error, {:authorization_denied, %{error: "access_denied"}}} =
               OAuth.handle_callback(
                 %{
                   "error" => "access_denied",
                   "state" => pending.state,
                   "iss" => "https://auth.example.com"
                 },
                 "u1",
                 opts
               )
    end

    test "accepts a missing iss when the server doesn't advertise it", %{as: as, opts: opts} do
      put_as_metadata(as, %{"authorization_response_iss_parameter_supported" => false})
      {:ok, url, pending} = OAuth.authorize_url(@server, "u1", opts)
      code = FakeOAuthServer.approve(as, url)

      assert {:ok, _token, _pending} =
               OAuth.handle_callback(%{"code" => code, "state" => pending.state}, "u1", opts)
    end

    test "authenticates confidential clients with HTTP Basic", %{as: as, opts: opts} do
      FakeOAuthServer.update(
        as,
        &put_in(&1, [:clients, "conf id"], %{secret: "s3cr:t", method: "basic"})
      )

      opts =
        Keyword.put(opts, :pre_registered, fn
          @server ->
            [issuer: "https://auth.example.com", client_id: "conf id", client_secret: "s3cr:t"]

          _ ->
            nil
        end)

      {:ok, url, pending} = OAuth.authorize_url(@server, "u1", opts)
      code = FakeOAuthServer.approve(as, url)

      assert {:ok, _token, _pending} =
               OAuth.handle_callback(
                 %{"code" => code, "state" => pending.state, "iss" => "https://auth.example.com"},
                 "u1",
                 opts
               )

      token_request = Enum.find(FakeOAuthServer.requests(as), &(&1.path == "/token"))
      refute Map.has_key?(token_request.params, "client_secret")
      assert List.keyfind(token_request.headers, "authorization", 0)
    end
  end

  describe "access_token/3" do
    test "returns a fresh token without refreshing", %{as: as, opts: opts} do
      put_token(opts, expires_in: 3600)
      assert {:ok, %Token{access_token: "stale"}} = OAuth.access_token(@server, "u1", opts)
      refute Enum.any?(FakeOAuthServer.requests(as), &(&1.path == "/token"))
    end

    test "refreshes an expiring token, rotating the refresh token", %{
      as: as,
      store: store,
      opts: opts
    } do
      put_token(opts, expires_in: 30)
      FakeOAuthServer.put_refresh_token(as, "rt-old", "public-client")

      assert {:ok, %Token{access_token: "at-1", refresh_token: "rt-1", scope: "mcp:read"}} =
               OAuth.access_token(@server, "u1", opts)

      assert %{"refresh_token" => "rt-1"} = OAuthMemoryStore.state(store).tokens[{@server, "u1"}]
      assert %{"refresh_token" => "rt-old", "resource" => @server} = token_request(as).params
    end

    test "keeps the refresh token when the response omits one", %{as: as, opts: opts} do
      FakeOAuthServer.update(as, &%{&1 | omit_refresh_token: true, rotate_refresh_tokens: false})
      put_token(opts, expires_in: -10)
      FakeOAuthServer.put_refresh_token(as, "rt-old", "public-client")

      assert {:ok, %Token{access_token: "at-1", refresh_token: "rt-old"}} =
               OAuth.access_token(@server, "u1", opts)
    end

    test "invalid_grant deletes the token and asks for authorization", %{store: store, opts: opts} do
      put_token(opts, expires_in: -10)

      assert {:error, {:authorization_required, %{server_url: @server}}} =
               OAuth.access_token(@server, "u1", opts)

      assert OAuthMemoryStore.state(store).tokens == %{}
    end

    test "concurrent refreshes spend the refresh token once", %{as: as, opts: opts} do
      FakeOAuthServer.update(as, &%{&1 | refresh_delay: 100})
      put_token(opts, expires_in: -10)
      FakeOAuthServer.put_refresh_token(as, "rt-old", "public-client")

      results =
        1..3
        |> Enum.map(fn _ -> Task.async(fn -> OAuth.access_token(@server, "u1", opts) end) end)
        |> Task.await_many()

      assert Enum.all?(results, &match?({:ok, %Token{access_token: "at-1"}}, &1))
      assert Enum.count(FakeOAuthServer.requests(as), &(&1.path == "/token")) == 1
    end

    test "without a token, asks for authorization", %{opts: opts} do
      assert {:error, {:authorization_required, %{server_url: @server}}} =
               OAuth.access_token(@server, "nobody", opts)
    end
  end

  describe "AshAi.Mcp.Client.Auth" do
    test "headers/2 sends the bearer token", %{opts: opts} do
      put_token(opts, expires_in: 3600)
      opts = Keyword.put(opts, :owner, "u1")

      assert {:ok, [{"authorization", "Bearer stale"}]} = OAuth.headers(@server, opts)

      assert {:error, {:authorization_required, %{server_url: @server}}} =
               OAuth.headers(@server, Keyword.put(opts, :owner, "u2"))
    end

    test "a 401 refreshes and retries", %{as: as, opts: opts} do
      put_token(opts, expires_in: 3600)
      FakeOAuthServer.put_refresh_token(as, "rt-old", "public-client")
      opts = Keyword.put(opts, :owner, "u1")

      assert :retry = OAuth.handle_challenge(@server, %{status: 401, www_authenticate: nil}, opts)
      assert {:ok, [{"authorization", "Bearer at-1"}]} = OAuth.headers(@server, opts)
    end

    test "a 401 that refreshing can't fix asks for authorization", %{opts: opts} do
      put_token(opts, expires_in: 3600, refresh_token: nil)
      opts = Keyword.put(opts, :owner, "u1")
      header = ~s(Bearer resource_metadata="https://mcp.example.com/prm", scope="mcp:read")

      assert {:error,
              {:authorization_required,
               %{
                 server_url: @server,
                 resource_metadata: "https://mcp.example.com/prm",
                 scope: "mcp:read",
                 www_authenticate: ^header
               }}} =
               OAuth.handle_challenge(@server, %{status: 401, www_authenticate: header}, opts)
    end

    test "insufficient_scope steps up with the union of scopes", %{opts: opts} do
      put_token(opts, expires_in: 3600)
      opts = Keyword.merge(opts, owner: "u1", offline_access: false)
      header = ~s(Bearer error="insufficient_scope", scope="mcp:write")

      assert {:error,
              {:insufficient_scope,
               %{scope: "mcp:read mcp:write", required_scope: "mcp:write"} = info}} =
               OAuth.handle_challenge(@server, %{status: 403, www_authenticate: header}, opts)

      assert {:ok, url, _} =
               OAuth.authorize_url(
                 @server,
                 "u1",
                 Keyword.put(opts, :challenge, info.www_authenticate)
               )

      assert query(url)["scope"] == "mcp:read mcp:write"

      assert {:error, {:forbidden, _}} =
               OAuth.handle_challenge(@server, %{status: 403, www_authenticate: nil}, opts)
    end
  end

  describe "untrustworthy authorization server responses" do
    test "a refresh rejected with invalid_client asks for authorization again", %{
      store: store,
      opts: opts
    } do
      put_token(opts, expires_in: 30)

      # A confidential client the authorization server no longer knows
      {module, store_opts} = opts[:store]

      module.put_client(
        @server,
        %Client{
          issuer: "https://auth.example.com",
          client_id: "public-client",
          client_secret: "revoked",
          token_endpoint_auth_method: "client_secret_basic",
          source: :dcr,
          redirect_uris: [@redirect_uri]
        },
        store_opts
      )

      assert {:error, {:authorization_required, _}} = OAuth.access_token(@server, "u1", opts)
      assert OAuthMemoryStore.state(store).tokens == %{}
    end

    test "a client whose secret expired isn't used", %{as: as, store: store, opts: opts} do
      put_token(opts, expires_in: 30)
      {module, store_opts} = opts[:store]

      module.put_client(
        @server,
        %Client{
          issuer: "https://auth.example.com",
          client_id: "public-client",
          client_secret: "s",
          client_secret_expires_at: DateTime.add(DateTime.utc_now(), -60, :second),
          token_endpoint_auth_method: "client_secret_basic",
          source: :dcr,
          redirect_uris: [@redirect_uri]
        },
        store_opts
      )

      assert {:error, {:authorization_required, _}} = OAuth.access_token(@server, "u1", opts)
      refute Enum.any?(FakeOAuthServer.requests(as), &(&1.path == "/token"))
      assert OAuthMemoryStore.state(store).tokens == %{}
    end

    test "malformed token responses are errors, and odd fields are ignored", %{
      as: as,
      opts: opts
    } do
      FakeOAuthServer.update(as, &%{&1 | overrides: %{"/token" => %{"token_type" => %{}}}})
      {:ok, url, pending} = OAuth.authorize_url(@server, "u1", opts)
      params = %{"code" => FakeOAuthServer.approve(as, url), "state" => pending.state}

      assert {:error, {:unsupported_token_type, %{}}} =
               OAuth.handle_callback(
                 Map.put(params, "iss", "https://auth.example.com"),
                 "u1",
                 opts
               )

      overrides = %{"refresh_token" => 5, "scope" => ["a"], "expires_in" => 10 ** 20}
      FakeOAuthServer.update(as, &%{&1 | overrides: %{"/token" => overrides}})
      {:ok, url, pending} = OAuth.authorize_url(@server, "u1", opts)
      code = FakeOAuthServer.approve(as, url)

      assert {:ok, token, _pending} =
               OAuth.handle_callback(
                 %{"code" => code, "state" => pending.state, "iss" => "https://auth.example.com"},
                 "u1",
                 opts
               )

      assert token.refresh_token == nil
      assert token.scope == pending.scope
      assert token.expires_at == nil
    end

    test "malformed registration responses don't crash", %{as: as, store: store, opts: opts} do
      overrides = %{
        "client_secret_expires_at" => 10 ** 20,
        "redirect_uris" => "nope",
        "client_secret" => 5
      }

      FakeOAuthServer.update(as, &%{&1 | overrides: %{"/register" => overrides}})

      assert {:ok, _url, _pending} = OAuth.authorize_url(@server, "u1", opts)

      assert %{"redirect_uris" => [@redirect_uri], "client_secret" => nil} =
               OAuthMemoryStore.state(store).clients[{@server, "https://auth.example.com"}]
    end

    test "error text from servers is cut short and stripped of control characters" do
      fields =
        AshAi.Mcp.OAuth.HTTP.error_fields(400, %{
          "error" => "invalid_grant",
          "error_description" => "line\nbreak" <> String.duplicate("x", 500),
          "secret" => "not kept"
        })

      assert fields.error == "invalid_grant"
      assert String.length(fields.error_description) == 256
      refute fields.error_description =~ "\n"
      refute Map.has_key?(fields, :secret)
    end
  end

  describe "disconnect/3" do
    test "revokes the refresh and access tokens, then deletes them", %{
      as: as,
      store: store,
      opts: opts
    } do
      put_token(opts, expires_in: 3600)
      FakeOAuthServer.put_refresh_token(as, "rt-old", "public-client")

      assert {:ok, :revoked} = OAuth.disconnect(@server, "u1", opts)

      assert FakeOAuthServer.get(as, :revoked) == [
               {"refresh_token", "rt-old"},
               {"access_token", "stale"}
             ]

      assert %{"client_id" => "public-client"} =
               Enum.find(FakeOAuthServer.requests(as), &(&1.path == "/revoke")).params

      assert OAuthMemoryStore.state(store).tokens == %{}
      assert {:error, {:authorization_required, _}} = OAuth.access_token(@server, "u1", opts)
    end

    test "deletes the tokens when the server doesn't offer revocation", %{
      as: as,
      store: store,
      opts: opts
    } do
      put_as_metadata(as, %{"revocation_endpoint" => nil})
      put_token(opts, expires_in: 3600)

      assert {:ok, :unsupported} = OAuth.disconnect(@server, "u1", opts)
      refute Enum.any?(FakeOAuthServer.requests(as), &(&1.path == "/revoke"))
      assert OAuthMemoryStore.state(store).tokens == %{}
    end

    test "deletes the tokens even when revoking them fails", %{
      as: as,
      store: store,
      opts: opts
    } do
      FakeOAuthServer.update(as, &%{&1 | revoke_status: 503})
      put_token(opts, expires_in: 3600)

      assert {:error, {:revocation_failed, {:revocation_error, %{status: 503}}}} =
               OAuth.disconnect(@server, "u1", opts)

      assert OAuthMemoryStore.state(store).tokens == %{}
    end

    test "authenticates confidential clients", %{as: as, opts: opts} do
      FakeOAuthServer.update(
        as,
        &put_in(&1, [:clients, "conf id"], %{secret: "s3cr:t", method: "basic"})
      )

      opts =
        Keyword.put(opts, :pre_registered, %{
          @server => [
            issuer: "https://auth.example.com",
            client_id: "conf id",
            client_secret: "s3cr:t"
          ]
        })

      {:ok, url, pending} = OAuth.authorize_url(@server, "u1", opts)
      code = FakeOAuthServer.approve(as, url)

      {:ok, _token, _pending} =
        OAuth.handle_callback(
          %{"code" => code, "state" => pending.state, "iss" => "https://auth.example.com"},
          "u1",
          opts
        )

      assert {:ok, :revoked} = OAuth.disconnect(@server, "u1", opts)

      revoke = Enum.find(FakeOAuthServer.requests(as), &(&1.path == "/revoke"))
      assert List.keyfind(revoke.headers, "authorization", 0)
      refute Map.has_key?(revoke.params, "client_secret")
    end

    test "is a no-op without tokens", %{as: as, opts: opts} do
      assert {:ok, :not_connected} = OAuth.disconnect(@server, "u1", opts)
      assert FakeOAuthServer.requests(as) == []
    end
  end

  test "structs serialize to JSON-safe maps and hide secrets" do
    token = %Token{
      access_token: "secret-at",
      refresh_token: "secret-rt",
      expires_at: ~U[2026-01-01 00:00:00Z],
      server_url: @server,
      issuer: "https://auth.example.com",
      client_id: "c"
    }

    client = %Client{
      issuer: "https://auth.example.com",
      client_id: "c",
      client_secret: "secret-cs",
      source: :dcr
    }

    pending = %Pending{
      state: "s",
      code_verifier: "secret-cv",
      created_at: ~U[2026-01-01 00:00:00Z]
    }

    for struct <- [token, client, pending] do
      module = struct.__struct__
      map = module.to_map(struct)
      assert map |> Jason.encode!() |> Jason.decode!() |> module.from_map() == struct
      refute inspect(struct) =~ "secret-"
    end
  end

  test "client metadata document and plug" do
    opts = [
      client_metadata_url: @metadata_url,
      client_name: "Test App",
      redirect_uri: @redirect_uri
    ]

    assert %{
             "client_id" => @metadata_url,
             "client_name" => "Test App",
             "redirect_uris" => [@redirect_uri],
             "token_endpoint_auth_method" => "none"
           } = OAuth.client_metadata_document(opts)

    conn =
      Plug.Test.conn(:get, "/oauth/client.json")
      |> AshAi.Mcp.OAuth.ClientMetadataPlug.call(
        AshAi.Mcp.OAuth.ClientMetadataPlug.init(fn -> opts end)
      )

    assert conn.status == 200
    assert %{"client_id" => @metadata_url} = Jason.decode!(conn.resp_body)

    # Without a metadata URL, as in development over plain HTTP, there's no document
    conn =
      Plug.Test.conn(:get, "/oauth/client.json")
      |> AshAi.Mcp.OAuth.ClientMetadataPlug.call(
        AshAi.Mcp.OAuth.ClientMetadataPlug.init(Keyword.delete(opts, :client_metadata_url))
      )

    assert conn.status == 404

    assert_raise ArgumentError, fn ->
      OAuth.client_metadata_document(client_metadata_url: "https://app.example.com")
    end
  end

  defp put_token(opts, token_opts) do
    {store, store_opts} = opts[:store]

    store.put_client(
      @server,
      %Client{
        issuer: "https://auth.example.com",
        client_id: "public-client",
        source: :dcr,
        redirect_uris: [@redirect_uri]
      },
      store_opts
    )

    store.put_token(
      @server,
      "u1",
      %Token{
        access_token: "stale",
        refresh_token: Keyword.get(token_opts, :refresh_token, "rt-old"),
        expires_at: DateTime.add(DateTime.utc_now(), token_opts[:expires_in], :second),
        scope: "mcp:read",
        server_url: @server,
        resource: @server,
        issuer: "https://auth.example.com",
        client_id: "public-client",
        token_endpoint: "https://auth.example.com/token"
      },
      store_opts
    )
  end

  defp token_request(as), do: Enum.find(FakeOAuthServer.requests(as), &(&1.path == "/token"))

  defp put_as_metadata(as, overrides) do
    FakeOAuthServer.update(as, fn state ->
      put_in(
        state,
        [:docs, {"auth.example.com", "/.well-known/oauth-authorization-server"}],
        FakeOAuthServer.as_metadata(overrides)
      )
    end)
  end

  defp query(url), do: url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()

  # Another MCP server at https://<host>/mcp, using the same authorization server
  defp add_mcp_server(as, host) do
    FakeOAuthServer.update(as, fn state ->
      put_in(state, [:docs, {host, "/.well-known/oauth-protected-resource/mcp"}], %{
        "resource" => "https://#{host}/mcp",
        "authorization_servers" => ["https://auth.example.com"]
      })
    end)
  end
end
