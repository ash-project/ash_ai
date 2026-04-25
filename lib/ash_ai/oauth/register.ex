# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

if Code.ensure_loaded?(Plug) do
  defmodule AshAi.Oauth.Register do
    @moduledoc """
    Plug implementing RFC 7591 Dynamic Client Registration.

    Mount at `POST /oauth/register`.
    """

    @behaviour Plug
    import Plug.Conn

    alias AshAi.Oauth.{Config, Error}

    @valid_grant_types ~w(authorization_code refresh_token)
    @valid_response_types ~w(code)
    # v1: public clients only (PKCE). client_secret_basic deferred to v2.
    @valid_auth_methods ~w(none)

    @impl Plug
    def init(opts), do: Keyword.fetch!(opts, :otp_app)

    @impl Plug
    def call(%{method: "POST"} = conn, otp_app) do
      params = conn.params || %{}

      with :ok <- validate_redirect_uris(params),
           :ok <- validate_grant_types(params),
           :ok <- validate_response_types(params),
           :ok <- validate_auth_method(params),
           {:ok, client} <- create_client(otp_app, params) do
        respond(conn, otp_app, client)
      else
        {:error, code, desc} -> Error.send_dcr_error(conn, code, desc)
      end
    end

    def call(conn, _),
      do: Error.send_oauth_error(conn, 405, "invalid_request", "POST required")

    defp validate_redirect_uris(%{"redirect_uris" => uris}) when is_list(uris) and uris != [] do
      Enum.reduce_while(uris, :ok, fn uri, _ ->
        case URI.new(uri) do
          {:ok, %URI{scheme: "https"}} -> {:cont, :ok}
          {:ok, %URI{scheme: "http", host: host}} when host in ["localhost", "127.0.0.1", "::1"] -> {:cont, :ok}
          _ -> {:halt, {:error, "invalid_redirect_uri", "redirect URIs must use https or be localhost"}}
        end
      end)
    end

    defp validate_redirect_uris(_),
      do: {:error, "invalid_client_metadata", "redirect_uris is required"}

    defp validate_grant_types(%{"grant_types" => grants}) when is_list(grants) do
      if Enum.all?(grants, &(&1 in @valid_grant_types)),
        do: :ok,
        else: {:error, "invalid_client_metadata", "unsupported grant_type"}
    end

    defp validate_grant_types(_), do: :ok

    defp validate_response_types(%{"response_types" => types}) when is_list(types) do
      if Enum.all?(types, &(&1 in @valid_response_types)),
        do: :ok,
        else: {:error, "invalid_client_metadata", "unsupported response_type"}
    end

    defp validate_response_types(_), do: :ok

    defp validate_auth_method(%{"token_endpoint_auth_method" => m}) when m in @valid_auth_methods, do: :ok
    defp validate_auth_method(%{"token_endpoint_auth_method" => _}),
      do: {:error, "invalid_client_metadata", "unsupported token_endpoint_auth_method"}

    defp validate_auth_method(_), do: :ok

    defp create_client(otp_app, params) do
      attrs = %{
        client_name: Map.get(params, "client_name", "Unnamed Client"),
        redirect_uris: Map.fetch!(params, "redirect_uris"),
        grant_types: Map.get(params, "grant_types", ["authorization_code"]),
        response_types: Map.get(params, "response_types", ["code"]),
        token_endpoint_auth_method: Map.get(params, "token_endpoint_auth_method", "none"),
        scope: Enum.join(Config.scopes(otp_app), " ")
      }

      Config.client_resource(otp_app)
      |> Ash.Changeset.for_create(:register, attrs)
      |> Ash.create(authorize?: false)
    end

    defp respond(conn, otp_app, client) do
      base = %{
        "client_id" => client.id,
        "client_id_issued_at" => DateTime.to_unix(client.created_at),
        "client_name" => client.client_name,
        "redirect_uris" => client.redirect_uris,
        "grant_types" => client.grant_types,
        "response_types" => client.response_types,
        "token_endpoint_auth_method" => client.token_endpoint_auth_method,
        "scope" => client.scope
      }

      body =
        if Config.dcr_always_return_client_secret?(otp_app) and client.token_endpoint_auth_method == "none" do
          Map.put(base, "client_secret", "")
        else
          base
        end

      conn
      |> put_resp_header("content-type", "application/json")
      |> put_resp_header("cache-control", "no-store")
      |> send_resp(201, Jason.encode!(body))
      |> halt()
    end
  end
end
