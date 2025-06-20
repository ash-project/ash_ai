defmodule AshAi.Mcp.Auth.Strategy do
  @moduledoc """
  MCP-specific extensions for AshAuthentication OAuth2 strategies.

  This module provides helper functions to integrate AshAuthentication
  OAuth2 strategies with MCP authentication flows.
  """

  require Logger

  @doc """
  Builds an OAuth2 authorization URL for MCP authentication.

  Uses the configured AshAuthentication OAuth2 strategy to generate
  a proper authorization URL with MCP-specific parameters.
  """
  def build_authorization_url(strategy, redirect_uri, opts \\ []) do
    state = opts[:state] || generate_state()
    scopes = opts[:scopes] || strategy[:scopes] || ["user:email"]

    params = %{
      client_id: get_client_id(strategy),
      redirect_uri: redirect_uri,
      scope: Enum.join(scopes, " "),
      state: state,
      response_type: "code"
    }

    # Add provider-specific parameters
    params = add_provider_params(params, strategy)

    base_url = get_authorization_url(strategy)
    query_string = URI.encode_query(params)

    "#{base_url}?#{query_string}"
  end

  @doc """
  Exchanges OAuth2 authorization code for access token.

  Handles the OAuth2 callback by exchanging the authorization code
  for an access token and fetching user information.
  """
  def exchange_code_for_token(code, strategy, redirect_uri) do
    token_params = %{
      client_id: get_client_id(strategy),
      client_secret: get_client_secret(strategy),
      code: code,
      redirect_uri: redirect_uri,
      grant_type: "authorization_code"
    }

    token_url = get_token_url(strategy)

    case make_token_request(token_url, token_params) do
      {:ok, token_response} ->
        access_token = token_response["access_token"]

        case fetch_user_info(access_token, strategy) do
          {:ok, user_info} ->
            {:ok,
             %{
               access_token: access_token,
               refresh_token: token_response["refresh_token"],
               expires_in: token_response["expires_in"],
               user_info: user_info
             }}

          {:error, reason} ->
            {:error, {:user_info_failed, reason}}
        end

      {:error, reason} ->
        {:error, {:token_exchange_failed, reason}}
    end
  end

  @doc """
  Fetches user information from OAuth2 provider.
  """
  def fetch_user_info(access_token, strategy) do
    user_url = get_user_url(strategy)
    headers = [{"Authorization", "Bearer #{access_token}"}]

    case make_api_request(user_url, headers) do
      {:ok, user_data} ->
        normalized_user = normalize_user_info(user_data, strategy)
        {:ok, normalized_user}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Gets OAuth2 strategy configuration from AshAuthentication.
  """
  def get_strategy_config(otp_app, provider) do
    case get_ash_authentication_config(otp_app) do
      {:ok, config} ->
        find_oauth_strategy(config, provider)

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Private functions

  defp generate_state do
    :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
  end

  defp get_client_id(strategy) do
    case strategy[:client_id] do
      {module, function, args} -> apply(module, function, args)
      value when is_binary(value) -> value
      _ -> raise "Invalid client_id configuration"
    end
  end

  defp get_client_secret(strategy) do
    case strategy[:client_secret] do
      {module, function, args} -> apply(module, function, args)
      value when is_binary(value) -> value
      _ -> raise "Invalid client_secret configuration"
    end
  end

  defp get_authorization_url(strategy) do
    provider = strategy[:provider] || strategy[:name]

    case provider do
      :github -> "https://github.com/login/oauth/authorize"
      :google -> "https://accounts.google.com/o/oauth2/v2/auth"
      :discord -> "https://discord.com/api/oauth2/authorize"
      :microsoft -> "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
      _ -> strategy[:authorization_url] || raise "Unknown provider: #{provider}"
    end
  end

  defp get_token_url(strategy) do
    provider = strategy[:provider] || strategy[:name]

    case provider do
      :github -> "https://github.com/login/oauth/access_token"
      :google -> "https://oauth2.googleapis.com/token"
      :discord -> "https://discord.com/api/oauth2/token"
      :microsoft -> "https://login.microsoftonline.com/common/oauth2/v2.0/token"
      _ -> strategy[:token_url] || raise "Unknown provider: #{provider}"
    end
  end

  defp get_user_url(strategy) do
    provider = strategy[:provider] || strategy[:name]

    case provider do
      :github -> "https://api.github.com/user"
      :google -> "https://www.googleapis.com/oauth2/v2/userinfo"
      :discord -> "https://discord.com/api/users/@me"
      :microsoft -> "https://graph.microsoft.com/v1.0/me"
      _ -> strategy[:user_url] || raise "Unknown provider: #{provider}"
    end
  end

  defp add_provider_params(params, strategy) do
    provider = strategy[:provider] || strategy[:name]

    case provider do
      :microsoft ->
        Map.merge(params, %{
          response_mode: "query",
          prompt: "select_account"
        })

      _ ->
        params
    end
  end

  defp make_token_request(url, params) do
    headers = [
      {~c"Accept", ~c"application/json"},
      {~c"Content-Type", ~c"application/x-www-form-urlencoded"}
    ]

    body = URI.encode_query(params) |> to_charlist()

    case :httpc.request(
           :post,
           {to_charlist(url), headers, ~c"application/x-www-form-urlencoded", body},
           [],
           []
         ) do
      {:ok, {{_, 200, _}, _headers, response_body}} ->
        case Jason.decode(to_string(response_body)) do
          {:ok, data} -> {:ok, data}
          {:error, reason} -> {:error, {:json_decode_failed, reason}}
        end

      {:ok, {{_, status, _}, _headers, response_body}} ->
        {:error, {:http_error, status, to_string(response_body)}}

      {:error, reason} ->
        {:error, {:http_request_failed, reason}}
    end
  end

  defp make_api_request(url, headers) do
    http_headers = Enum.map(headers, fn {k, v} -> {to_charlist(k), to_charlist(v)} end)

    case :httpc.request(:get, {to_charlist(url), http_headers}, [], []) do
      {:ok, {{_, 200, _}, _headers, response_body}} ->
        case Jason.decode(to_string(response_body)) do
          {:ok, data} -> {:ok, data}
          {:error, reason} -> {:error, {:json_decode_failed, reason}}
        end

      {:ok, {{_, status, _}, _headers, response_body}} ->
        {:error, {:http_error, status, to_string(response_body)}}

      {:error, reason} ->
        {:error, {:http_request_failed, reason}}
    end
  end

  defp normalize_user_info(user_data, strategy) do
    provider = strategy[:provider] || strategy[:name]

    case provider do
      :github ->
        %{
          id: to_string(user_data["id"]),
          email: user_data["email"],
          name: user_data["name"] || user_data["login"],
          username: user_data["login"],
          avatar_url: user_data["avatar_url"],
          provider: "github"
        }

      :google ->
        %{
          id: user_data["id"],
          email: user_data["email"],
          name: user_data["name"],
          username: user_data["email"],
          avatar_url: user_data["picture"],
          provider: "google"
        }

      :discord ->
        %{
          id: user_data["id"],
          email: user_data["email"],
          name: user_data["username"],
          username: user_data["username"],
          avatar_url: build_discord_avatar_url(user_data),
          provider: "discord"
        }

      _ ->
        # Generic normalization
        %{
          id: to_string(user_data["id"] || user_data["sub"]),
          email: user_data["email"],
          name: user_data["name"] || user_data["display_name"],
          username: user_data["username"] || user_data["login"] || user_data["email"],
          avatar_url: user_data["avatar_url"] || user_data["picture"],
          provider: to_string(provider)
        }
    end
  end

  defp build_discord_avatar_url(user_data) do
    if avatar = user_data["avatar"] do
      "https://cdn.discordapp.com/avatars/#{user_data["id"]}/#{avatar}.png"
    else
      nil
    end
  end

  defp get_ash_authentication_config(otp_app) do
    # This would integrate with AshAuthentication to get the actual configuration
    # For now, return a placeholder structure that could fail
    if otp_app do
      {:ok,
       %{
         strategies: [
           %{
             name: :github,
             provider: :github,
             client_id: System.get_env("GITHUB_CLIENT_ID"),
             client_secret: System.get_env("GITHUB_CLIENT_SECRET")
           }
         ]
       }}
    else
      {:error, :invalid_otp_app}
    end
  end

  defp find_oauth_strategy(config, provider) do
    case Enum.find(config.strategies, &(&1.name == provider || &1.provider == provider)) do
      nil -> {:error, :strategy_not_found}
      strategy -> {:ok, strategy}
    end
  end
end
