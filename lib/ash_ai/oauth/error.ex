# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

if Code.ensure_loaded?(Plug) do
  defmodule AshAi.Oauth.Error do
    @moduledoc """
    OAuth 2.1 / RFC 7591 error response helpers.
    """

    import Plug.Conn

    @doc """
    Send a JSON error per OAuth 2.0 / RFC 6749 §5.2.

    Examples of `code`: `"invalid_request"`, `"invalid_client"`,
    `"invalid_grant"`, `"unsupported_grant_type"`, `"invalid_scope"`.
    """
    def send_oauth_error(conn, status, code, description \\ nil) do
      body = %{"error" => code} |> maybe_put("error_description", description)

      conn
      |> put_resp_header("content-type", "application/json")
      |> put_resp_header("cache-control", "no-store")
      |> send_resp(status, Jason.encode!(body))
      |> halt()
    end

    @doc """
    Send a 400 with an RFC 7591 DCR-shaped error.

    Codes: `"invalid_redirect_uri"`, `"invalid_client_metadata"`.
    """
    def send_dcr_error(conn, code, description \\ nil) do
      send_oauth_error(conn, 400, code, description)
    end

    defp maybe_put(map, _key, nil), do: map
    defp maybe_put(map, key, value), do: Map.put(map, key, value)
  end
end
