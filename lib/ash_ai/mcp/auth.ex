defmodule AshAi.Mcp.Auth do
  @moduledoc """
  Authentication module for MCP server.

  Provides OAuth2 integration with AshAuthentication for MCP servers,
  supporting both session-based and bearer token authentication.
  """

  import Plug.Conn
  require Logger

  @doc """
  Creates an authentication plug for MCP servers.

  ## Options

    * `:otp_app` - The OTP application name (required)
    * `:auth_strategies` - List of authentication strategies to enable
    * `:require_auth?` - Whether authentication is required (default: false)
    * `:bearer_token_resource` - Resource module for bearer token validation
    * `:oauth_success_redirect` - URL to redirect after successful OAuth
    * `:oauth_failure_redirect` - URL to redirect after failed OAuth

  ## Example

      # In Phoenix router
      scope "/mcp" do
        pipe_through AshAi.Mcp.Auth.plug(
          otp_app: :my_app,
          auth_strategies: [:github, :google],
          require_auth?: true
        )
        
        forward "/", AshAi.Mcp.Router
      end
  """
  def plug(opts) do
    otp_app = Keyword.fetch!(opts, :otp_app)
    require_auth? = Keyword.get(opts, :require_auth?, false)
    auth_strategies = Keyword.get(opts, :auth_strategies, [])

    %{
      otp_app: otp_app,
      require_auth?: require_auth?,
      auth_strategies: auth_strategies,
      bearer_token_resource: opts[:bearer_token_resource],
      oauth_success_redirect: opts[:oauth_success_redirect],
      oauth_failure_redirect: opts[:oauth_failure_redirect]
    }
  end

  @doc """
  Plug call function for request authentication.
  """
  def call(conn, opts) do
    # Skip authentication for preflight OPTIONS requests
    if conn.method == "OPTIONS" do
      conn
    else
      authenticate_request(conn, opts)
    end
  end

  @doc """
  Extracts authenticated user from the connection.
  """
  def current_user(conn) do
    conn.assigns[:current_user]
  end

  @doc """
  Checks if the current request is authenticated.
  """
  def authenticated?(conn) do
    not is_nil(current_user(conn))
  end

  @doc """
  Generates OAuth authorization URL for MCP authentication.
  """
  def oauth_authorize_url(provider, opts \\ []) do
    otp_app = Keyword.fetch!(opts, :otp_app)
    redirect_uri = Keyword.get(opts, :redirect_uri)
    state = Keyword.get(opts, :state, generate_state())

    case get_oauth_strategy(otp_app, provider) do
      {:ok, strategy} ->
        auth_url = build_authorization_url(strategy, redirect_uri, state)
        {:ok, auth_url, state}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Handles OAuth callback for MCP authentication.
  """
  def handle_oauth_callback(conn, provider, opts \\ []) do
    otp_app = Keyword.fetch!(opts, :otp_app)

    with {:ok, strategy} <- get_oauth_strategy(otp_app, provider),
         {:ok, user_info} <- exchange_code_for_token(conn, strategy),
         {:ok, user} <- create_or_update_user(user_info, strategy, opts) do
      # Create MCP session with authenticated user
      session_opts = [
        auth_context: %{
          user: user,
          provider: provider,
          authenticated_at: DateTime.utc_now()
        }
      ]

      case AshAi.Mcp.Session.create_session(nil, session_opts) do
        {:ok, session} ->
          conn
          |> put_session(:mcp_session_id, session.id)
          |> put_session(:current_user_id, user.id)
          |> assign(:current_user, user)
          |> assign(:mcp_session, session)

        {:error, reason} ->
          Logger.error("Failed to create MCP session: #{inspect(reason)}")
          {:error, :session_creation_failed}
      end
    else
      {:error, reason} ->
        Logger.warning("OAuth callback failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  # Private functions

  defp authenticate_request(conn, opts) do
    cond do
      # Try bearer token authentication first
      bearer_token = extract_bearer_token(conn) ->
        authenticate_with_bearer_token(conn, bearer_token, opts)

      # Try session authentication
      session_user_id = get_session(conn, :current_user_id) ->
        authenticate_with_session(conn, session_user_id, opts)

      # No authentication found
      true ->
        handle_unauthenticated_request(conn, opts)
    end
  end

  defp extract_bearer_token(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] -> token
      _ -> nil
    end
  end

  defp authenticate_with_bearer_token(conn, token, opts) do
    case validate_bearer_token(token, opts) do
      {:ok, user} ->
        conn
        |> assign(:current_user, user)
        |> assign(:auth_method, :bearer_token)

      {:error, reason} ->
        Logger.debug("Bearer token validation failed: #{inspect(reason)}")
        handle_unauthenticated_request(conn, opts)
    end
  end

  defp authenticate_with_session(conn, user_id, opts) do
    case load_user_from_session(user_id, opts) do
      {:ok, user} ->
        # Link to existing MCP session if available
        mcp_session_id = get_session(conn, :mcp_session_id)
        mcp_session = if mcp_session_id, do: get_mcp_session(mcp_session_id), else: nil

        conn
        |> assign(:current_user, user)
        |> assign(:auth_method, :session)
        |> assign(:mcp_session, mcp_session)

      {:error, reason} ->
        Logger.debug("Session authentication failed: #{inspect(reason)}")
        handle_unauthenticated_request(conn, opts)
    end
  end

  defp handle_unauthenticated_request(conn, opts) do
    if opts[:require_auth?] do
      conn
      |> put_status(:unauthorized)
      |> json(%{error: "Authentication required"})
      |> halt()
    else
      # Continue without authentication
      conn
      |> assign(:current_user, nil)
      |> assign(:auth_method, :none)
    end
  end

  defp validate_bearer_token(token, opts) do
    if resource = opts[:bearer_token_resource] do
      try do
        case resource.get_by_token(token) do
          {:ok, token_record} when not is_nil(token_record) ->
            if token_expired?(token_record) do
              {:error, :token_expired}
            else
              case load_user_from_token(token_record, opts) do
                {:ok, user} -> {:ok, user}
                error -> error
              end
            end

          _ ->
            {:error, :invalid_token}
        end
      rescue
        error ->
          Logger.error("Bearer token validation error: #{inspect(error)}")
          {:error, :validation_failed}
      end
    else
      {:error, :no_token_resource_configured}
    end
  end

  defp token_expired?(token_record) do
    case Map.get(token_record, :expires_at) do
      nil -> false
      expires_at -> DateTime.compare(DateTime.utc_now(), expires_at) == :gt
    end
  end

  defp load_user_from_token(token_record, _opts) do
    case Map.get(token_record, :user) do
      nil -> {:error, :no_user_associated}
      user -> {:ok, user}
    end
  end

  defp load_user_from_session(user_id, opts) do
    # This would need to be implemented based on the user resource
    # For now, return a placeholder
    {:ok, %{id: user_id, email: "user@example.com"}}
  end

  defp get_mcp_session(session_id) do
    case AshAi.Mcp.Session.get_session(session_id) do
      {:ok, session} -> session
      _ -> nil
    end
  end

  defp get_oauth_strategy(otp_app, provider) do
    AshAi.Mcp.Auth.Strategy.get_strategy_config(otp_app, provider)
  end

  defp build_authorization_url(strategy, redirect_uri, state) do
    AshAi.Mcp.Auth.Strategy.build_authorization_url(strategy, redirect_uri, state: state)
  end

  defp exchange_code_for_token(conn, strategy) do
    code = conn.params["code"]
    redirect_uri = build_callback_url(conn, strategy[:provider] || strategy[:name])

    case AshAi.Mcp.Auth.Strategy.exchange_code_for_token(code, strategy, redirect_uri) do
      {:ok, token_data} -> {:ok, token_data.user_info}
      {:error, reason} -> {:error, reason}
    end
  end

  defp build_callback_url(conn, provider) do
    scheme = if conn.scheme == :https, do: "https", else: "http"
    host = conn.host
    port = if conn.port in [80, 443], do: "", else: ":#{conn.port}"

    "#{scheme}://#{host}#{port}/mcp/auth/#{provider}/callback"
  end

  defp create_or_update_user(user_info, strategy, opts) do
    # This would create or update the user based on OAuth user info
    # For now, return a placeholder
    {:ok, %{id: 1, email: user_info.email, name: user_info.name}}
  end

  defp generate_state do
    :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
  end

  defp json(conn, data) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(conn.status || 200, Jason.encode!(data))
  end
end
