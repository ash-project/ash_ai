# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

if Code.ensure_loaded?(Plug) do
  defmodule AshAi.Mcp.Metadata.ProtectedResource do
    @moduledoc """
    Plug serving the RFC 9728 OAuth 2.0 Protected Resource Metadata document.

    Mount at `/.well-known/oauth-protected-resource`.
    """

    @behaviour Plug
    import Plug.Conn

    alias AshAi.Oauth.Config

    @impl Plug
    def init(opts), do: Keyword.fetch!(opts, :otp_app)

    @impl Plug
    def call(conn, otp_app) do
      body =
        Jason.encode!(%{
          "resource" => Config.canonical_mcp_url(otp_app),
          "authorization_servers" => [Config.issuer_url(otp_app)],
          "scopes_supported" => Config.scopes(otp_app),
          "bearer_methods_supported" => ["header"]
        })

      conn
      |> put_resp_header("content-type", "application/json")
      |> put_resp_header("cache-control", "public, max-age=300")
      |> send_resp(200, body)
      |> halt()
    end
  end
end
