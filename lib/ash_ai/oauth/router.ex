# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

if Code.ensure_loaded?(Plug) do
  defmodule AshAi.Oauth.Router do
    @moduledoc """
    Single-mount router for the OAuth 2.1 endpoints + well-known metadata.

    Forward at the user's app root:

        forward "/", AshAi.Oauth.Router, otp_app: :my_app

    Routes owned:

      - `GET  /.well-known/oauth-protected-resource`
      - `GET  /.well-known/oauth-authorization-server`
      - `POST /oauth/register`
      - `GET  /oauth/authorize`
      - `POST /oauth/authorize`
      - `POST /oauth/token`
      - `POST /oauth/revoke`

    Anything else passes through unchanged.
    """

    use Plug.Router, copy_opts_to_assign: :ash_ai_oauth_opts

    plug Plug.Parsers,
      parsers: [:urlencoded, :json],
      pass: ["*/*"],
      json_decoder: Jason

    plug :match
    plug :dispatch

    get "/.well-known/oauth-protected-resource" do
      AshAi.Mcp.Metadata.ProtectedResource.call(conn, otp_app(conn))
    end

    get "/.well-known/oauth-authorization-server" do
      AshAi.Oauth.Metadata.AuthServer.call(conn, otp_app(conn))
    end

    post "/oauth/register" do
      AshAi.Oauth.Register.call(conn, otp_app(conn))
    end

    get "/oauth/authorize" do
      AshAi.Oauth.Authorize.call(conn, %{otp_app: otp_app(conn), skip_csrf?: false})
    end

    post "/oauth/authorize" do
      AshAi.Oauth.Authorize.call(conn, %{otp_app: otp_app(conn), skip_csrf?: false})
    end

    post "/oauth/token" do
      AshAi.Oauth.Token.call(conn, otp_app(conn))
    end

    post "/oauth/revoke" do
      AshAi.Oauth.Revoke.call(conn, otp_app(conn))
    end

    match _ do
      conn
    end

    defp otp_app(conn), do: conn.assigns.ash_ai_oauth_opts |> Keyword.fetch!(:otp_app)
  end
end
