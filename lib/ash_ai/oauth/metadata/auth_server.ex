# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

if Code.ensure_loaded?(Plug) do
  defmodule AshAi.Oauth.Metadata.AuthServer do
    @moduledoc """
    Plug serving the RFC 8414 OAuth 2.0 Authorization Server Metadata document.

    Mount at `/.well-known/oauth-authorization-server`.
    """

    @behaviour Plug
    import Plug.Conn

    alias AshAi.Oauth.Config

    @impl Plug
    def init(opts), do: Keyword.fetch!(opts, :otp_app)

    @impl Plug
    def call(conn, otp_app) do
      issuer = Config.issuer_url(otp_app)

      body =
        Jason.encode!(%{
          "issuer" => issuer,
          "authorization_endpoint" => issuer <> "/oauth/authorize",
          "token_endpoint" => issuer <> "/oauth/token",
          "registration_endpoint" => issuer <> "/oauth/register",
          "revocation_endpoint" => issuer <> "/oauth/revoke",
          "response_types_supported" => ["code"],
          "grant_types_supported" => ["authorization_code", "refresh_token"],
          "code_challenge_methods_supported" => ["S256"],
          # v1: public clients only (PKCE). client_secret_basic deferred to v2.
          "token_endpoint_auth_methods_supported" => ["none"],
          "scopes_supported" => Config.scopes(otp_app),
          "service_documentation" => "https://hexdocs.pm/ash_ai/mcp-oauth.html"
        })

      conn
      |> put_resp_header("content-type", "application/json")
      |> put_resp_header("cache-control", "public, max-age=300")
      |> send_resp(200, body)
      |> halt()
    end
  end
end
