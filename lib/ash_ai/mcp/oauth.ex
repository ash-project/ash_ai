# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

if Code.ensure_loaded?(Req) do
  defmodule AshAi.Mcp.OAuth do
    defmodule Options do
      @moduledoc false

      @schema [
        store: [
          type: {:or, [:atom, {:tuple, [:atom, :any]}]},
          required: true,
          doc: "The `AshAi.Mcp.OAuth.Store` as `module` or `{module, store_opts}`."
        ],
        owner: [
          type: :any,
          doc:
            "Whose tokens to use, such as a user id. Required by the `AshAi.Mcp.Client.Auth` callbacks."
        ],
        redirect_uri: [
          type: :string,
          doc:
            "Where the authorization server redirects back to. Must be HTTPS or a loopback URL. Required by `authorize_url/3`."
        ],
        redirect_uris: [
          type: {:list, :string},
          doc:
            "Every redirect URI to register or list in the Client ID Metadata Document. Defaults to `[redirect_uri]`."
        ],
        client_name: [
          type: :string,
          default: "AshAi MCP Client",
          doc: "Shown to users on consent screens."
        ],
        client_uri: [type: :string, doc: "Your application's home page."],
        logo_uri: [type: :string, doc: "Your application's logo."],
        client_metadata_url: [
          type: :string,
          doc:
            "The HTTPS URL where you serve `client_metadata_document/1` (see `AshAi.Mcp.OAuth.ClientMetadataPlug`). Enables Client ID Metadata Documents."
        ],
        pre_registered: [
          type: {:or, [{:map, :string, :any}, {:fun, 1}]},
          doc:
            "Client credentials you registered yourself, as `%{server_url => [issuer: ..., client_id: ..., client_secret: ...]}` or a function from an MCP server's URL to those credentials or `nil`. They're used only for that server, and only while it names `issuer` as its authorization server, so another server can't borrow them by naming the same authorization server."
        ],
        token_endpoint_auth_method: [
          type: {:in, ["none", "client_secret_basic", "client_secret_post"]},
          default: "none",
          doc: "The token endpoint authentication to request through Dynamic Client Registration."
        ],
        application_type: [
          type: {:in, ["web", "native"]},
          doc:
            "The application type to register. Defaults to `native` for loopback redirect URIs and `web` otherwise."
        ],
        challenge: [
          type: :any,
          doc:
            "A `WWW-Authenticate` header value (or a parsed challenge) from the server. `authorize_url/3` uses its `resource_metadata` and `scope`."
        ],
        scope: [
          type: {:or, [:string, {:list, :string}]},
          doc: "Extra scopes for `authorize_url/3` to request."
        ],
        offline_access: [
          type: :boolean,
          default: true,
          doc:
            "Whether to request `offline_access` (for a refresh token) when the authorization server lists it."
        ],
        refresh_skew: [
          type: :non_neg_integer,
          default: 60,
          doc: "Refresh tokens that expire within this many seconds."
        ],
        pending_ttl: [
          type: :pos_integer,
          default: 600,
          doc: "Seconds a pending authorization stays valid."
        ],
        allowed_private_hosts: [
          type: {:or, [{:list, :string}, {:literal, :all}]},
          default: [],
          doc:
            "Hosts that may resolve to loopback, private, or other non-public addresses, such as `[\"localhost\"]` in development or an internal authorization server's hostname. Loopback hosts listed here may also use plain HTTP. `:all` turns the check off, which a proxy, named `finch:` pool, or custom `adapter:` in `req_options` requires."
        ],
        req_options: [
          type: :keyword_list,
          default: [],
          doc:
            "Options merged into every `Req.new/1`, such as `plug:` in tests or `connect_options: [proxy: ...]` for an egress proxy."
        ]
      ]

      def schema, do: @schema
    end

    @moduledoc """
    An OAuth 2.1 client for MCP servers, following the MCP authorization spec
    (revision 2026-07-28).

    AshAi never stores credentials. Everything it needs to keep (registered
    clients, tokens, and authorizations in progress) goes through a
    `AshAi.Mcp.OAuth.Store` you implement, so you decide where it lives and how
    it is encrypted. `mix ash_ai.gen.mcp_oauth` generates one backed by
    `ash_postgres` and `ash_cloak`, with routes for the flow below. See the
    [MCP Client Authorization](mcp-client-authorization.md) guide.

    ## Flow

    1. Connect to an MCP server with `auth: {AshAi.Mcp.OAuth, opts}`, where
       `opts` includes `:owner`. The client asks `headers/2` for a token before
       each request.
    2. With no usable token, the request fails with
       `{:error, {:authorization_required, info}}`. Send the user to the URL from
       `authorize_url/3`, passing `challenge: info.www_authenticate` when it is
       set.
    3. On the redirect back, call `handle_callback/3` with the query params and
       the signed-in owner. It stores the token, and later requests use it.
    4. Tokens are refreshed before they expire, under the store's lock. When a
       refresh token stops working, requests fail with `:authorization_required`
       again.
    5. A server that needs more scopes answers 403, and the request fails with
       `{:error, {:insufficient_scope, info}}`. Send the user through
       `authorize_url/3` with `challenge: info.www_authenticate`; the new
       request includes the scopes already granted.
    6. `disconnect/3` revokes the tokens and deletes them, when the user
       disconnects or before their account is deleted.

    ## Requests to server-supplied URLs

    Discovery fetches URLs that the MCP server supplies, directly or through the
    metadata it points to. AshAi requires HTTPS for them and only connects to
    public addresses, checking every address a host resolves to as it connects,
    so a server can't aim requests at cloud metadata endpoints or other
    services on your network. List the exceptions, such as `"localhost"` in
    development, in `:allowed_private_hosts`.

    Responses are limited to 256 KiB and requests to 10 seconds. Redirects
    aren't followed.

    A proxy, a named `finch:` pool, or a custom `adapter:` in `req_options`
    takes requests out of the address check's reach, so they need
    `allowed_private_hosts: :all`, for example with an egress proxy that
    enforces it. Without it they raise rather than go unchecked.

    ## Options

    #{Spark.Options.docs(AshAi.Mcp.OAuth.Options.schema())}
    """

    @behaviour AshAi.Mcp.Client.Auth

    alias AshAi.Mcp.OAuth.{Discovery, Pending, Registration, Store, Token}

    @type opts :: keyword()

    @doc """
    Returns the authorization URL to send `owner` to for the MCP server at
    `server_url`, and the `AshAi.Mcp.OAuth.Pending` it stored.

    Discovers the authorization server, obtains a client ID, and selects scopes:
    those from `:challenge` and `:scope`, or else the server's
    `scopes_supported`, plus any scopes `owner` was already granted.
    """
    @spec authorize_url(String.t(), term(), opts()) ::
            {:ok, String.t(), Pending.t()} | {:error, term()}
    def authorize_url(server_url, owner, opts) do
      opts = validate!(opts)

      with :ok <- require_secure(server_url),
           {:ok, redirect_uri} <- redirect_uri(opts),
           {:ok, discovery} <- Discovery.discover(server_url, opts),
           metadata = discovery.authorization_server,
           {:ok, client} <-
             Registration.select_client(discovery.server, metadata, redirect_uri, opts) do
        verifier = random_token()
        scope = select_scope(discovery, owner, opts)

        pending = %Pending{
          state: random_token(),
          owner: owner,
          server_url: discovery.server,
          resource: discovery.resource,
          issuer: discovery.issuer,
          client_id: client.client_id,
          redirect_uri: redirect_uri,
          scope: scope,
          code_verifier: verifier,
          token_endpoint: metadata["token_endpoint"],
          created_at: DateTime.utc_now(),
          iss_parameter_supported:
            metadata["authorization_response_iss_parameter_supported"] == true
        }

        params =
          [
            response_type: "code",
            client_id: client.client_id,
            redirect_uri: redirect_uri,
            state: pending.state,
            code_challenge: code_challenge(verifier),
            code_challenge_method: "S256",
            resource: discovery.resource
          ] ++ if(scope, do: [scope: scope], else: [])

        with :ok <- Store.call(opts[:store], :put_pending, [pending]) do
          {:ok, append_query(metadata["authorization_endpoint"], params), pending}
        end
      end
    end

    @doc """
    Completes an authorization from the query params of the redirect back.

    `owner` is whoever completes the redirect, such as the signed-in user, and
    must be the owner the authorization was started for. Otherwise a user
    could start an authorization, get someone else to open its URL, and
    receive that person's tokens.

    Consumes the pending authorization for `state`, validates the response's
    `iss` (RFC 9207), exchanges the code, and stores the token.
    """
    @spec handle_callback(map(), term(), opts()) ::
            {:ok, Token.t(), Pending.t()} | {:error, term()}
    def handle_callback(params, owner, opts) do
      opts = validate!(opts)
      params = Map.new(params, fn {key, value} -> {to_string(key), value} end)

      with {:ok, state} <- fetch_param(params, "state", :missing_state),
           {:ok, pending} <- take_pending(state, opts),
           :ok <- check_owner(pending, owner),
           :ok <- check_expiry(pending, opts),
           :ok <- check_issuer(pending, params["iss"]),
           :ok <- check_error(params),
           {:ok, code} <- fetch_param(params, "code", :missing_code),
           {:ok, client} <-
             Registration.resolve_client(
               pending.server_url,
               pending.issuer,
               pending.client_id,
               opts
             ),
           {:ok, response} <-
             token_request(
               pending.token_endpoint,
               client,
               [
                 grant_type: "authorization_code",
                 code: code,
                 redirect_uri: pending.redirect_uri,
                 code_verifier: pending.code_verifier,
                 resource: pending.resource
               ],
               opts
             ),
           {:ok, token} <- build_token(response, pending, nil),
           :ok <-
             Store.call(opts[:store], :put_token, [pending.server_url, pending.owner, token]) do
        {:ok, token, pending}
      end
    end

    @doc """
    Returns a usable token for `owner` at the MCP server `server_url`,
    refreshing it first if it expires within `:refresh_skew` seconds.
    """
    @spec access_token(String.t(), term(), opts()) :: {:ok, Token.t()} | {:error, term()}
    def access_token(server_url, owner, opts) do
      opts = validate!(opts)

      with {:ok, server} <- Discovery.canonical_resource(server_url) do
        case Store.call(opts[:store], :get_token, [server, owner]) do
          {:ok, %Token{} = token} ->
            if Token.fresh?(token, opts[:refresh_skew]),
              do: {:ok, token},
              else: refresh_locked(server, owner, :if_stale, opts)

          :error ->
            {:error, authorization_required(server, nil)}
        end
      end
    end

    @doc """
    Refreshes `owner`'s token for `server_url` now, even if it hasn't expired.
    """
    @spec refresh(String.t(), term(), opts()) :: {:ok, Token.t()} | {:error, term()}
    def refresh(server_url, owner, opts) do
      opts = validate!(opts)

      with {:ok, server} <- Discovery.canonical_resource(server_url) do
        refresh_locked(server, owner, :force, opts)
      end
    end

    @doc """
    Disconnects `owner` from the MCP server at `server_url`: revokes their
    tokens at the authorization server (RFC 7009) when it supports
    revocation, and deletes them from the store.

    The tokens are deleted even when revoking them fails, so the owner is
    disconnected from your application either way.
    `{:error, {:revocation_failed, reason}}` means the authorization server may
    still consider the grant active, until it expires or the user revokes it
    there.

    Returns `{:ok, :revoked}`, `{:ok, :unsupported}` when the authorization
    server doesn't offer revocation, or `{:ok, :not_connected}` when `owner`
    had no tokens.
    """
    @spec disconnect(String.t(), term(), opts()) ::
            {:ok, :revoked | :unsupported | :not_connected} | {:error, term()}
    def disconnect(server_url, owner, opts) do
      opts = validate!(opts)

      with {:ok, server} <- Discovery.canonical_resource(server_url) do
        # Under the lock, a refresh running at the same time can't store new
        # tokens after these are deleted
        Store.call(opts[:store], :with_lock, [
          server,
          owner,
          fn ->
            case Store.call(opts[:store], :get_token, [server, owner]) do
              {:ok, %Token{} = token} ->
                result = revoke(server, token, opts)
                Store.call(opts[:store], :delete_token, [server, owner])
                result

              :error ->
                {:ok, :not_connected}
            end
          end
        ])
      end
    end

    @doc "See `AshAi.Mcp.OAuth.Discovery.discover/2`."
    defdelegate discover(server_url, opts \\ []), to: Discovery

    @doc "See `AshAi.Mcp.OAuth.Discovery.parse_www_authenticate/1`."
    defdelegate parse_www_authenticate(header), to: Discovery

    @doc "See `AshAi.Mcp.OAuth.Discovery.canonical_resource/1`."
    defdelegate canonical_resource(url), to: Discovery

    @doc "See `AshAi.Mcp.OAuth.Registration.client_metadata_document/1`."
    defdelegate client_metadata_document(opts), to: Registration

    @impl AshAi.Mcp.Client.Auth
    def headers(server_url, opts) do
      with :ok <- require_secure(server_url),
           {:ok, token} <- access_token(server_url, owner!(opts), opts) do
        {:ok, [{"authorization", "Bearer " <> token.access_token}]}
      end
    end

    @impl AshAi.Mcp.Client.Auth
    def handle_challenge(server_url, %{status: 401} = response, opts) do
      opts = validate!(opts)
      challenge = Discovery.parse_www_authenticate(response.www_authenticate)

      with {:ok, server} <- Discovery.canonical_resource(server_url) do
        # The server rejected the token it was sent, fresh or not, so refresh
        # regardless of its expiry. The refresh re-reads the token under the
        # lock, so a rotating refresh token is never spent twice.
        case refresh_locked(server, owner!(opts), :force, opts) do
          {:ok, _token} ->
            :retry

          {:error, {:authorization_required, _}} ->
            {:error, authorization_required(server, challenge)}

          {:error, reason} ->
            {:error, reason}
        end
      end
    end

    def handle_challenge(server_url, %{status: 403} = response, opts) do
      opts = validate!(opts)
      challenge = Discovery.parse_www_authenticate(response.www_authenticate)

      with {:ok, server} <- Discovery.canonical_resource(server_url) do
        info = challenge_info(server, challenge)

        case challenge do
          %{error: "insufficient_scope"} ->
            granted =
              case Store.call(opts[:store], :get_token, [server, owner!(opts)]) do
                {:ok, token} -> split_scope(token.scope)
                :error -> []
              end

            scope = Enum.uniq(granted ++ split_scope(challenge.scope))

            {:error,
             {:insufficient_scope,
              Map.merge(info, %{
                required_scope: challenge.scope,
                scope: join_scope(scope)
              })}}

          _ ->
            {:error, {:forbidden, info}}
        end
      end
    end

    defp refresh_locked(server, owner, mode, opts) do
      Store.call(opts[:store], :with_lock, [
        server,
        owner,
        fn ->
          case Store.call(opts[:store], :get_token, [server, owner]) do
            {:ok, %Token{} = token} ->
              # Another process may have refreshed while we waited for the lock
              if mode == :if_stale and Token.fresh?(token, opts[:refresh_skew]),
                do: {:ok, token},
                else: refresh_token(server, owner, token, opts)

            :error ->
              {:error, authorization_required(server, nil)}
          end
        end
      ])
    end

    defp refresh_token(server, owner, %Token{refresh_token: nil}, opts) do
      Store.call(opts[:store], :delete_token, [server, owner])
      {:error, authorization_required(server, nil)}
    end

    defp refresh_token(server, owner, %Token{} = token, opts) do
      with {:ok, client} <-
             Registration.resolve_client(server, token.issuer, token.client_id, opts),
           {:ok, response} <-
             token_request(
               token.token_endpoint,
               client,
               [
                 grant_type: "refresh_token",
                 refresh_token: token.refresh_token,
                 resource: token.resource
               ],
               opts
             ),
           {:ok, refreshed} <- build_token(response, token, token),
           :ok <- Store.call(opts[:store], :put_token, [server, owner, refreshed]) do
        {:ok, refreshed}
      else
        {:error, reason} when reason == :unknown_client ->
          Store.call(opts[:store], :delete_token, [server, owner])
          {:error, authorization_required(server, nil)}

        # The grant, or the client it was issued to, no longer works, so only a
        # new authorization helps. Keeping the token would fail every request.
        {:error, {:token_error, %{error: error}}}
        when error in ["invalid_grant", "invalid_client"] ->
          Store.call(opts[:store], :delete_token, [server, owner])
          {:error, authorization_required(server, nil)}

        {:error, reason} ->
          {:error, {:refresh_failed, reason}}
      end
    end

    # The revocation endpoint is the one the token's issuer advertises now
    defp revoke(server, token, opts) do
      with {:ok, metadata} <- Discovery.authorization_server_metadata(token.issuer, opts),
           endpoint when is_binary(endpoint) <- metadata["revocation_endpoint"],
           {:ok, client} <-
             Registration.resolve_client(server, token.issuer, token.client_id, opts),
           :ok <- revoke_token(endpoint, client, token.refresh_token, "refresh_token", opts),
           :ok <- revoke_token(endpoint, client, token.access_token, "access_token", opts) do
        {:ok, :revoked}
      else
        {:error, reason} -> {:error, {:revocation_failed, reason}}
        _no_endpoint -> {:ok, :unsupported}
      end
    end

    defp revoke_token(_endpoint, _client, nil, _hint, _opts), do: :ok

    # RFC 7009 section 2.2: 200 means the token was revoked or was already invalid
    defp revoke_token(endpoint, client, token, hint, opts) do
      {params, headers} = client_authentication(client, token: token, token_type_hint: hint)

      case AshAi.Mcp.OAuth.HTTP.post(endpoint, [form: params], headers, opts) do
        {:ok, 200, _body, _response} ->
          :ok

        {:ok, status, body, _response} ->
          {:error, {:revocation_error, AshAi.Mcp.OAuth.HTTP.error_fields(status, body)}}

        {:error, reason} ->
          {:error, reason}
      end
    end

    defp token_request(endpoint, client, params, opts) do
      {params, headers} = client_authentication(client, params)

      case AshAi.Mcp.OAuth.HTTP.post(endpoint, [form: params], headers, opts) do
        {:ok, 200, %{"access_token" => access_token} = response, _}
        when is_binary(access_token) ->
          {:ok, response}

        {:ok, status, body, _} ->
          {:error, {:token_error, AshAi.Mcp.OAuth.HTTP.error_fields(status, body)}}

        {:error, reason} ->
          {:error, reason}
      end
    end

    # Clients authenticate the same way at the token endpoint and the
    # revocation endpoint (RFC 7009 section 2.1)
    defp client_authentication(client, params) do
      case client.token_endpoint_auth_method do
        "client_secret_basic" ->
          credentials =
            form_encode(client.client_id) <> ":" <> form_encode(client.client_secret)

          {params, [{"authorization", "Basic " <> Base.encode64(credentials)}]}

        "client_secret_post" ->
          {params ++ [client_id: client.client_id, client_secret: client.client_secret], []}

        _none ->
          {params ++ [client_id: client.client_id], []}
      end
    end

    # `source` is the pending authorization or the token being refreshed, and
    # supplies what the response doesn't repeat.
    defp build_token(response, source, previous) do
      token_type = response["token_type"] || "Bearer"

      if is_binary(token_type) and String.downcase(token_type) == "bearer" do
        now = DateTime.utc_now()

        {:ok,
         %Token{
           access_token: response["access_token"],
           refresh_token:
             string(response["refresh_token"]) || (previous && previous.refresh_token),
           expires_at: expires_at(response["expires_in"], now),
           scope: string(response["scope"]) || source.scope,
           server_url: source.server_url,
           resource: source.resource,
           issuer: source.issuer,
           client_id: source.client_id,
           token_endpoint: source.token_endpoint,
           obtained_at: now
         }}
      else
        {:error, {:unsupported_token_type, token_type}}
      end
    end

    # Ten years at most: a larger value is nonsense, and past year 9999 it
    # can't be represented
    defp expires_at(seconds, now) when is_integer(seconds) and seconds in 0..315_360_000,
      do: DateTime.add(now, seconds, :second)

    defp expires_at(seconds, now) when is_binary(seconds) do
      case Integer.parse(seconds) do
        {seconds, ""} -> expires_at(seconds, now)
        _ -> nil
      end
    end

    defp expires_at(_seconds, _now), do: nil

    defp select_scope(discovery, owner, opts) do
      requested =
        split_scope(discovery.challenge && discovery.challenge.scope) ++ split_scope(opts[:scope])

      requested =
        if requested == [],
          do: List.wrap(discovery.protected_resource["scopes_supported"]),
          else: requested

      granted =
        case Store.call(opts[:store], :get_token, [discovery.server, owner]) do
          {:ok, token} -> split_scope(token.scope)
          :error -> []
        end

      scopes = Enum.uniq(granted ++ requested)

      scopes =
        if scopes != [] and opts[:offline_access] and
             "offline_access" in List.wrap(discovery.authorization_server["scopes_supported"]),
           do: Enum.uniq(scopes ++ ["offline_access"]),
           else: scopes

      join_scope(scopes)
    end

    defp take_pending(state, opts) do
      case Store.call(opts[:store], :take_pending, [state]) do
        {:ok, %Pending{} = pending} ->
          if secure_compare(pending.state, state),
            do: {:ok, pending},
            else: {:error, :invalid_state}

        :error ->
          {:error, :invalid_state}
      end
    end

    # The pending authorization is already consumed, so a URL someone was
    # tricked into opening can't be completed later by its rightful owner.
    defp check_owner(%Pending{owner: owner}, owner), do: :ok
    defp check_owner(_pending, _owner), do: {:error, :owner_mismatch}

    defp check_expiry(%Pending{created_at: created_at}, opts) do
      if DateTime.diff(DateTime.utc_now(), created_at, :second) <= opts[:pending_ttl],
        do: :ok,
        else: {:error, :expired_state}
    end

    # RFC 9207 section 2.4, as the MCP spec tabulates it: a present `iss` must
    # equal the recorded issuer exactly, and an absent one is only acceptable
    # when the server doesn't advertise sending it. On a mismatch the response's
    # error fields must not be acted on, so this runs before `check_error/1`.
    defp check_issuer(%Pending{issuer: issuer}, iss) when is_binary(iss) do
      if iss == issuer, do: :ok, else: {:error, {:issuer_mismatch, issuer, iss}}
    end

    defp check_issuer(%Pending{iss_parameter_supported: true}, _iss),
      do: {:error, :missing_issuer}

    defp check_issuer(_pending, _iss), do: :ok

    defp check_error(%{"error" => error} = params) when is_binary(error) do
      {:error, {:authorization_denied, AshAi.Mcp.OAuth.HTTP.error_fields(nil, params)}}
    end

    defp check_error(_params), do: :ok

    defp fetch_param(params, key, error) do
      case params[key] do
        value when is_binary(value) and value != "" -> {:ok, value}
        _ -> {:error, error}
      end
    end

    defp redirect_uri(opts) do
      case opts[:redirect_uri] do
        nil ->
          {:error, :redirect_uri_required}

        uri ->
          with :ok <- require_secure(uri), do: {:ok, uri}
      end
    end

    # Tokens are only obtained for and sent to HTTPS servers (or loopback ones,
    # in development), since plain HTTP carries the bearer token in the clear
    defp require_secure(url) do
      if AshAi.Mcp.OAuth.HTTP.secure_url?(url),
        do: :ok,
        else: {:error, {:insecure_url, url}}
    end

    defp authorization_required(server, challenge),
      do: {:authorization_required, challenge_info(server, challenge)}

    defp challenge_info(server, challenge) do
      challenge = challenge || %{}

      %{
        server_url: server,
        resource_metadata: challenge[:resource_metadata],
        scope: challenge[:scope],
        error: challenge[:error],
        error_description: challenge[:error_description],
        www_authenticate: challenge[:www_authenticate]
      }
    end

    defp owner!(opts) do
      case Keyword.fetch(opts, :owner) do
        {:ok, owner} -> owner
        :error -> raise ArgumentError, "AshAi.Mcp.OAuth needs an :owner option"
      end
    end

    defp validate!(opts), do: Spark.Options.validate!(opts, Options.schema())

    defp split_scope(scope) when is_binary(scope), do: String.split(scope, " ", trim: true)
    defp split_scope(scopes) when is_list(scopes), do: Enum.flat_map(scopes, &split_scope/1)
    # Absent, or not a scope at all in metadata a server wrote
    defp split_scope(_scope), do: []

    defp string(value) when is_binary(value), do: value
    defp string(_value), do: nil

    defp join_scope([]), do: nil
    defp join_scope(scopes), do: Enum.join(scopes, " ")

    defp append_query(url, params) do
      uri = URI.parse(url)
      query = URI.encode_query(params)
      URI.to_string(%{uri | query: if(uri.query, do: uri.query <> "&" <> query, else: query)})
    end

    # RFC 6749 section 2.3.1: Basic credentials are form-encoded first
    defp form_encode(value), do: URI.encode_www_form(value || "")

    defp random_token, do: Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)

    defp code_challenge(verifier),
      do: Base.url_encode64(:crypto.hash(:sha256, verifier), padding: false)

    defp secure_compare(left, right)
         when is_binary(left) and is_binary(right) and byte_size(left) == byte_size(right) do
      left
      |> :binary.bin_to_list()
      |> Enum.zip(:binary.bin_to_list(right))
      |> Enum.reduce(0, fn {a, b}, acc -> Bitwise.bor(acc, Bitwise.bxor(a, b)) end)
      |> Kernel.==(0)
    end

    defp secure_compare(_left, _right), do: false
  end
end
