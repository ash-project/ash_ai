# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Oauth.FullFlowTest do
  @moduledoc """
  End-to-end OAuth 2.1 round trip:
  unauth MCP -> 401 PRM -> ASM -> DCR -> /authorize (consent) -> /token -> authenticated MCP -> refresh
  """

  use ExUnit.Case, async: false
  import Plug.{Conn, Test}

  alias AshAi.Mcp.BearerPlug
  alias AshAi.Mcp.Metadata.ProtectedResource
  alias AshAi.Oauth.{Authorize, Metadata.AuthServer, Pkce, Register, Token}

  setup do
    prior = Application.get_env(:ash_ai, AshAi.Oauth)

    Application.put_env(:ash_ai, AshAi.Oauth,
      user_resource: AshAi.Test.OauthUser,
      client_resource: AshAi.Test.OAuthClient,
      authorization_code_resource: AshAi.Test.OAuthAuthorizationCode,
      refresh_token_resource: AshAi.Test.OAuthRefreshToken,
      consent_resource: AshAi.Test.OAuthConsent,
      issuer_url: "https://app.example.com",
      canonical_mcp_url: "https://app.example.com/mcp",
      signing_secret: String.duplicate("x", 64),
      access_token_ttl: 3_600,
      refresh_token_ttl: {30, :days},
      authorization_code_ttl: {10, :minutes},
      scopes: ["mcp"]
    )

    on_exit(fn ->
      if prior, do: Application.put_env(:ash_ai, AshAi.Oauth, prior), else: Application.delete_env(:ash_ai, AshAi.Oauth)
    end)

    {:ok, user} =
      AshAi.Test.OauthUser
      |> Ash.Changeset.for_create(:create, %{email: "u@example.com"})
      |> Ash.create(authorize?: false)

    {:ok, user: user}
  end

  test "complete round trip", %{user: user} do
    # 1. Unauth MCP request -> 401 with WWW-Authenticate
    conn = conn(:post, "/mcp", "{}")
    conn = BearerPlug.call(conn, BearerPlug.init(otp_app: :ash_ai, required?: true))

    assert conn.status == 401
    [auth_header] = get_resp_header(conn, "www-authenticate")
    [_, prm_url] = Regex.run(~r/resource_metadata="([^"]+)"/, auth_header)

    # 2. GET PRM
    conn = conn(:get, prm_url)
    conn = ProtectedResource.call(conn, ProtectedResource.init(otp_app: :ash_ai))
    prm = Jason.decode!(conn.resp_body)
    [as_issuer] = prm["authorization_servers"]

    # 3. GET ASM
    conn = conn(:get, "#{as_issuer}/.well-known/oauth-authorization-server")
    conn = AuthServer.call(conn, AuthServer.init(otp_app: :ash_ai))
    asm = Jason.decode!(conn.resp_body)

    # 4. DCR
    conn =
      conn(:post, asm["registration_endpoint"], Jason.encode!(%{
        "client_name" => "ChatGPT",
        "redirect_uris" => ["https://chatgpt.com/connector/oauth/abc"],
        "token_endpoint_auth_method" => "none"
      }))
      |> put_req_header("content-type", "application/json")
      |> Plug.Parsers.call(Plug.Parsers.init(parsers: [:json], json_decoder: Jason))

    conn = Register.call(conn, Register.init(otp_app: :ash_ai))
    %{"client_id" => client_id} = Jason.decode!(conn.resp_body)

    # 5. /authorize (with prior consent so we get a code immediately)
    AshAi.Test.OAuthConsent
    |> Ash.Changeset.for_create(:grant, %{user_id: user.id, client_id: client_id, scope: "mcp"})
    |> Ash.create!(authorize?: false)

    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = Pkce.challenge(verifier)

    auth_query = URI.encode_query(%{
      "response_type" => "code",
      "client_id" => client_id,
      "redirect_uri" => "https://chatgpt.com/connector/oauth/abc",
      "code_challenge" => challenge,
      "code_challenge_method" => "S256",
      "scope" => "mcp",
      "state" => "xyz",
      "resource" => "https://app.example.com/mcp"
    })

    conn =
      conn(:get, "#{asm["authorization_endpoint"]}?#{auth_query}")
      |> Plug.Conn.fetch_query_params()
      |> Ash.PlugHelpers.set_actor(user)

    conn = Authorize.call(conn, Authorize.init(otp_app: :ash_ai))
    [location] = get_resp_header(conn, "location")
    %{"code" => code} = URI.decode_query(URI.parse(location).query)

    # 6. /token (code exchange)
    conn =
      conn(:post, asm["token_endpoint"], URI.encode_query(%{
        "grant_type" => "authorization_code",
        "code" => code,
        "redirect_uri" => "https://chatgpt.com/connector/oauth/abc",
        "client_id" => client_id,
        "code_verifier" => verifier,
        "resource" => "https://app.example.com/mcp"
      }))
      |> put_req_header("content-type", "application/x-www-form-urlencoded")
      |> Plug.Parsers.call(Plug.Parsers.init(parsers: [:urlencoded]))

    conn = Token.call(conn, Token.init(otp_app: :ash_ai))
    %{"access_token" => access, "refresh_token" => refresh} = Jason.decode!(conn.resp_body)

    # 7. Authenticated MCP request
    conn =
      conn(:post, "/mcp", "{}")
      |> put_req_header("authorization", "Bearer #{access}")

    conn = BearerPlug.call(conn, BearerPlug.init(otp_app: :ash_ai, required?: true))
    refute conn.halted
    assert Ash.PlugHelpers.get_actor(conn).id == user.id

    # 8. Refresh
    conn =
      conn(:post, asm["token_endpoint"], URI.encode_query(%{
        "grant_type" => "refresh_token",
        "refresh_token" => refresh,
        "client_id" => client_id,
        "resource" => "https://app.example.com/mcp"
      }))
      |> put_req_header("content-type", "application/x-www-form-urlencoded")
      |> Plug.Parsers.call(Plug.Parsers.init(parsers: [:urlencoded]))

    conn = Token.call(conn, Token.init(otp_app: :ash_ai))
    body = Jason.decode!(conn.resp_body)
    assert is_binary(body["access_token"])
    refute body["refresh_token"] == refresh
  end
end
