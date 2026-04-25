# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Oauth.Metadata.AuthServerTest do
  use ExUnit.Case, async: false
  import Plug.{Conn, Test}

  alias AshAi.Oauth.Metadata.AuthServer

  setup do
    prior = Application.get_env(:ash_ai, AshAi.Oauth)

    Application.put_env(:ash_ai, AshAi.Oauth,
      user_resource: nil,
      issuer_url: "https://app.example.com",
      canonical_mcp_url: "https://app.example.com/mcp",
      signing_secret: "x",
      scopes: ["mcp"]
    )

    on_exit(fn ->
      if prior, do: Application.put_env(:ash_ai, AshAi.Oauth, prior), else: Application.delete_env(:ash_ai, AshAi.Oauth)
    end)

    :ok
  end

  test "returns required RFC 8414 fields for OAuth 2.1 + PKCE + DCR" do
    conn = conn(:get, "/.well-known/oauth-authorization-server")
    conn = AuthServer.call(conn, AuthServer.init(otp_app: :ash_ai))

    assert conn.status == 200
    body = Jason.decode!(conn.resp_body)

    assert body["issuer"] == "https://app.example.com"
    assert body["authorization_endpoint"] == "https://app.example.com/oauth/authorize"
    assert body["token_endpoint"] == "https://app.example.com/oauth/token"
    assert body["registration_endpoint"] == "https://app.example.com/oauth/register"
    assert body["revocation_endpoint"] == "https://app.example.com/oauth/revoke"
    assert body["response_types_supported"] == ["code"]
    assert body["grant_types_supported"] == ["authorization_code", "refresh_token"]
    assert body["code_challenge_methods_supported"] == ["S256"]
    assert body["token_endpoint_auth_methods_supported"] == ["none"]
    assert body["scopes_supported"] == ["mcp"]
  end
end
