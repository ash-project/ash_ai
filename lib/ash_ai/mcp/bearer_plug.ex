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
        nil when required? -> challenge(conn, otp_app, :missing)
        nil -> conn
        token -> verify_and_assign(conn, otp_app, token)
      end
    end

    # RFC 6750 §2.1 / RFC 7235 §2.1: scheme matching is case-insensitive.
    defp extract_token(conn) do
      with [header | _] <- get_req_header(conn, "authorization"),
           [_, token] <- Regex.run(~r/^Bearer\s+(.+)$/i, header) do
        String.trim(token)
      else
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
        _ -> challenge(conn, otp_app, :invalid_token)
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

    # RFC 6750 §3 — include `error="invalid_token"` when a token was presented
    # but failed verification, so clients can distinguish missing-vs-bad and
    # restart auth from scratch instead of silently retrying.
    defp challenge(conn, otp_app, reason) do
      prm_url = Config.issuer_url(otp_app) <> "/.well-known/oauth-protected-resource"

      header =
        case reason do
          :invalid_token -> ~s(Bearer resource_metadata="#{prm_url}", error="invalid_token")
          _ -> ~s(Bearer resource_metadata="#{prm_url}")
        end

      conn
      |> put_resp_header("www-authenticate", header)
      |> send_resp(401, "")
      |> halt()
    end
  end
end
