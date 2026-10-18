# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.OAuth.DiscoveryTest do
  use ExUnit.Case, async: true

  alias AshAi.Mcp.OAuth.Discovery
  alias AshAi.Test.FakeOAuthServer

  @server "https://mcp.example.com/mcp"

  setup do
    {:ok, as} = FakeOAuthServer.start_link()
    %{as: as, opts: [req_options: [plug: {FakeOAuthServer, as}]]}
  end

  describe "parse_www_authenticate/1" do
    test "reads Bearer params, unescaping quoted values" do
      header =
        ~s(Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource", ) <>
          ~s(scope="files:read files:write", error=insufficient_scope, error_description="say \\"please\\"")

      assert %{
               resource_metadata: "https://mcp.example.com/.well-known/oauth-protected-resource",
               scope: "files:read files:write",
               error: "insufficient_scope",
               error_description: ~s(say "please"),
               www_authenticate: ^header
             } = Discovery.parse_www_authenticate(header)
    end

    test "finds the Bearer challenge among several, including token68 ones" do
      header = ~s(Basic abc==, Negotiate, bearer realm="mcp", Scope="a")

      assert %{params: %{"realm" => "mcp", "scope" => "a"}, scope: "a"} =
               Discovery.parse_www_authenticate(header)

      assert %{scope: "b"} =
               Discovery.parse_www_authenticate([~s(Basic realm="x"), ~s(Bearer scope="b")])
    end

    test "returns nil without a Bearer challenge" do
      assert Discovery.parse_www_authenticate(~s(Basic realm="x")) == nil
      assert Discovery.parse_www_authenticate(nil) == nil
    end
  end

  test "canonical_resource/1 normalizes scheme, host, port, fragment and a bare slash" do
    assert {:ok, "https://mcp.example.com"} =
             Discovery.canonical_resource("HTTPS://MCP.Example.com:443/")

    assert {:ok, "https://mcp.example.com:8443/mcp"} =
             Discovery.canonical_resource("https://mcp.example.com:8443/mcp#x")

    assert {:ok, "https://mcp.example.com/mcp/"} =
             Discovery.canonical_resource("https://mcp.example.com/mcp/")

    assert {:error, _} = Discovery.canonical_resource("mcp.example.com")
    assert {:error, _} = Discovery.canonical_resource("ftp://mcp.example.com")
  end

  test "well-known URLs follow the spec's order" do
    assert Discovery.protected_resource_metadata_urls("https://example.com/public/mcp") == [
             "https://example.com/.well-known/oauth-protected-resource/public/mcp",
             "https://example.com/.well-known/oauth-protected-resource"
           ]

    assert Discovery.protected_resource_metadata_urls("https://example.com/mcp?tenant=a") == [
             "https://example.com/.well-known/oauth-protected-resource/mcp?tenant=a",
             "https://example.com/.well-known/oauth-protected-resource"
           ]

    assert Discovery.authorization_server_metadata_urls("https://auth.example.com/tenant1") == [
             "https://auth.example.com/.well-known/oauth-authorization-server/tenant1",
             "https://auth.example.com/.well-known/openid-configuration/tenant1",
             "https://auth.example.com/tenant1/.well-known/openid-configuration"
           ]

    assert Discovery.authorization_server_metadata_urls("https://auth.example.com") == [
             "https://auth.example.com/.well-known/oauth-authorization-server",
             "https://auth.example.com/.well-known/openid-configuration"
           ]
  end

  describe "discover/2" do
    test "uses path-inserted protected resource metadata", %{as: as, opts: opts} do
      assert {:ok, discovery} = Discovery.discover(@server, opts)
      assert discovery.server == @server
      assert discovery.resource == @server
      assert discovery.issuer == "https://auth.example.com"
      assert discovery.authorization_server["token_endpoint"] == "https://auth.example.com/token"

      assert FakeOAuthServer.request_paths(as) == [
               {"GET", "mcp.example.com", "/.well-known/oauth-protected-resource/mcp"},
               {"GET", "auth.example.com", "/.well-known/oauth-authorization-server"}
             ]
    end

    test "falls back to root metadata, which may describe the origin", %{as: as, opts: opts} do
      move_prm(as, "/.well-known/oauth-protected-resource", %{
        "resource" => "https://mcp.example.com"
      })

      assert {:ok, %{resource: "https://mcp.example.com"}} = Discovery.discover(@server, opts)
    end

    test "rejects metadata for a different resource", %{as: as, opts: opts} do
      move_prm(as, "/.well-known/oauth-protected-resource", %{
        "resource" => "https://mcp.example.com/other"
      })

      assert {:error, {:resource_mismatch, _, _}} = Discovery.discover(@server, opts)
    end

    test "rejects a parent resource from metadata other than the origin's root", %{
      as: as,
      opts: opts
    } do
      # Path-inserted metadata describes the server itself, not its origin
      move_prm(as, "/.well-known/oauth-protected-resource/mcp", %{
        "resource" => "https://mcp.example.com"
      })

      assert {:error, {:resource_mismatch, "https://mcp.example.com", @server}} =
               Discovery.discover(@server, opts)

      # So does metadata a challenge points to anywhere else
      move_prm(as, "/tenants/attacker/prm", %{"resource" => "https://mcp.example.com"})
      challenge = ~s(Bearer resource_metadata="https://mcp.example.com/tenants/attacker/prm")

      assert {:error, {:resource_mismatch, _, _}} =
               Discovery.discover(@server, Keyword.put(opts, :challenge, challenge))
    end

    test "compares the query too", %{as: as, opts: opts} do
      move_prm(as, "/.well-known/oauth-protected-resource/mcp", %{
        "resource" => "https://mcp.example.com/mcp?tenant=victim"
      })

      assert {:error, {:resource_mismatch, _, _}} =
               Discovery.discover("https://mcp.example.com/mcp?tenant=attacker", opts)

      assert {"GET", "mcp.example.com", "/.well-known/oauth-protected-resource/mcp"} in FakeOAuthServer.request_paths(
               as
             )
    end

    test "uses the challenge's resource_metadata URL", %{as: as, opts: opts} do
      move_prm(as, "/custom-prm")

      challenge =
        ~s(Bearer resource_metadata="https://mcp.example.com/custom-prm", scope="mcp:write")

      assert {:ok, %{challenge: %{scope: "mcp:write"}}} =
               Discovery.discover(@server, Keyword.put(opts, :challenge, challenge))

      assert {"GET", "mcp.example.com", "/custom-prm"} in FakeOAuthServer.request_paths(as)

      refute {"GET", "mcp.example.com", "/.well-known/oauth-protected-resource/mcp"} in FakeOAuthServer.request_paths(
               as
             )
    end

    test "refuses a challenge's resource_metadata URL unless it is plain HTTPS", %{
      as: as,
      opts: opts
    } do
      for url <- [
            "http://169.254.169.254/latest/meta-data",
            "http://localhost:9200/",
            "https://user@mcp.example.com/prm",
            "https://mcp.example.com/prm#fragment"
          ] do
        challenge = ~s(Bearer resource_metadata="#{url}")

        assert {:error, {:insecure_url, ^url}} =
                 Discovery.discover(@server, Keyword.put(opts, :challenge, challenge))
      end

      assert FakeOAuthServer.request_paths(as) == []
    end

    test "probes the server for a challenge when no well-known metadata exists", %{
      as: as,
      opts: opts
    } do
      move_prm(as, "/custom-prm")

      FakeOAuthServer.update(as, fn state ->
        %{
          state
          | www_authenticate: ~s(Bearer resource_metadata="https://mcp.example.com/custom-prm")
        }
      end)

      assert {:ok, %{issuer: "https://auth.example.com"}} = Discovery.discover(@server, opts)
      assert {"POST", "mcp.example.com", "/mcp"} in FakeOAuthServer.request_paths(as)
    end

    test "tries OpenID Connect discovery for issuers with paths", %{as: as, opts: opts} do
      issuer = "https://auth.example.com/tenant1"

      FakeOAuthServer.update(as, fn state ->
        docs =
          state.docs
          |> Map.delete({"auth.example.com", "/.well-known/oauth-authorization-server"})
          |> Map.put(
            {"auth.example.com", "/tenant1/.well-known/openid-configuration"},
            FakeOAuthServer.as_metadata(%{"issuer" => issuer})
          )
          |> put_in(
            [
              {"mcp.example.com", "/.well-known/oauth-protected-resource/mcp"},
              "authorization_servers"
            ],
            [issuer]
          )

        %{state | docs: docs}
      end)

      assert {:ok, %{issuer: ^issuer}} = Discovery.discover(@server, opts)

      assert Enum.drop(FakeOAuthServer.request_paths(as), 1) == [
               {"GET", "auth.example.com", "/.well-known/oauth-authorization-server/tenant1"},
               {"GET", "auth.example.com", "/.well-known/openid-configuration/tenant1"},
               {"GET", "auth.example.com", "/tenant1/.well-known/openid-configuration"}
             ]
    end

    test "rejects metadata whose issuer differs", %{as: as, opts: opts} do
      put_as_metadata(as, %{"issuer" => "https://honest.example"})

      assert {:error, {:issuer_mismatch, "https://auth.example.com", "https://honest.example"}} =
               Discovery.discover(@server, opts)
    end

    test "refuses authorization servers without PKCE S256", %{as: as, opts: opts} do
      put_as_metadata(as, %{"code_challenge_methods_supported" => ["plain"]})
      assert {:error, {:pkce_not_supported, _}} = Discovery.discover(@server, opts)

      put_as_metadata(as, %{"code_challenge_methods_supported" => nil})
      assert {:error, {:pkce_not_supported, _}} = Discovery.discover(@server, opts)
    end

    test "refuses plain-HTTP endpoints off loopback", %{as: as, opts: opts} do
      put_as_metadata(as, %{"token_endpoint" => "http://auth.example.com/token"})

      assert {:error, {:insecure_url, "http://auth.example.com/token"}} =
               Discovery.discover(@server, opts)
    end

    test "refuses plain-HTTP loopback endpoints unless the host is allowed", %{
      as: as,
      opts: opts
    } do
      put_as_metadata(as, %{"registration_endpoint" => "http://localhost:4000/register"})

      assert {:error, {:insecure_url, "http://localhost:4000/register"}} =
               Discovery.discover(@server, opts)

      assert {:ok, _} =
               Discovery.discover(
                 @server,
                 Keyword.put(opts, :allowed_private_hosts, ["localhost"])
               )
    end
  end

  defp move_prm(as, path, overrides \\ %{}) do
    FakeOAuthServer.update(as, fn state ->
      {prm, docs} =
        Map.pop(state.docs, {"mcp.example.com", "/.well-known/oauth-protected-resource/mcp"})

      %{state | docs: Map.put(docs, {"mcp.example.com", path}, Map.merge(prm, overrides))}
    end)
  end

  defp put_as_metadata(as, overrides) do
    FakeOAuthServer.update(as, fn state ->
      put_in(
        state,
        [:docs, {"auth.example.com", "/.well-known/oauth-authorization-server"}],
        FakeOAuthServer.as_metadata(overrides)
      )
    end)
  end
end
