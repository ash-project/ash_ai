# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

if Code.ensure_loaded?(Plug) do
  defmodule AshAi.Mcp.BearerPlug do
    @moduledoc """
    Validates an OAuth 2.1 bearer token on inbound MCP requests.

    On success, sets the actor on the conn via `Ash.PlugHelpers.set_actor/2`
    and assigns `:oauth_claims` for downstream use.

    On failure (or no token, when `required?: true`), responds with
    `401 Unauthorized` and a `WWW-Authenticate` header pointing at the
    Protected Resource Metadata document (RFC 9728 §5.1).

    ## Options

    - `:otp_app` (required) — the consuming app's atom.
    - `:required?` (default `true`) — if `false`, missing tokens pass through
      without error; invalid tokens still 401.
    """

    @behaviour Plug
    import Plug.Conn

    alias AshAi.Oauth.{Config, Jwt}

    @impl Plug
    def init(opts) do
      %{
        otp_app: Keyword.fetch!(opts, :otp_app),
        required?: Keyword.get(opts, :required?, true)
      }
    end

    @impl Plug
    def call(conn, %{otp_app: otp_app, required?: required?}) do
      case extract_token(conn) do
        nil when required? -> challenge(conn, otp_app)
        nil -> conn
        token -> verify_and_assign(conn, otp_app, token)
      end
    end

    defp extract_token(conn) do
      case get_req_header(conn, "authorization") do
        ["Bearer " <> token | _] -> String.trim(token)
        _ -> nil
      end
    end

    defp verify_and_assign(conn, otp_app, token) do
      with {:ok, claims} <- Jwt.verify(otp_app, token),
           {:ok, user} <- load_user(otp_app, claims) do
        conn
        |> Ash.PlugHelpers.set_actor(user)
        |> assign(:oauth_claims, claims)
      else
        _ -> challenge(conn, otp_app)
      end
    end

    defp load_user(otp_app, %{"sub" => sub}) do
      resource = Config.user_resource(otp_app)

      case Ash.get(resource, sub, authorize?: false) do
        {:ok, user} -> {:ok, user}
        _ -> :error
      end
    end

    defp load_user(_, _), do: :error

    defp challenge(conn, otp_app) do
      prm_url = Config.issuer_url(otp_app) <> "/.well-known/oauth-protected-resource"

      conn
      |> put_resp_header("www-authenticate", ~s(Bearer resource_metadata="#{prm_url}"))
      |> send_resp(401, "")
      |> halt()
    end
  end
end
