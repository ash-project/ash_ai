defmodule AshAi.Mcp.Auth.OAuthRouter do
  @moduledoc """
  OAuth router for MCP authentication.

  Handles OAuth authorization and callback flows specifically for MCP servers.
  Integrates with AshAuthentication strategies while providing MCP-specific
  session management and redirects.
  """

  use Plug.Router
  require Logger

  plug(Plug.Parsers,
    parsers: [:urlencoded, :multipart, :json],
    pass: ["*/*"],
    json_decoder: Jason
  )

  plug(:match)
  plug(:dispatch)

  @doc """
  Initializes the OAuth router with options.
  """
  def init(opts) do
    opts
    |> Keyword.put_new(:auth_strategies, [])
    |> Keyword.put_new(:success_redirect, "/mcp/auth/success")
    |> Keyword.put_new(:failure_redirect, "/mcp/auth/failure")
  end

  # OAuth authorization endpoint - initiates OAuth flow for the specified provider
  get "/auth/:provider" do
    provider = String.to_existing_atom(provider)
    opts = conn.assigns[:oauth_opts] || []

    if provider in opts[:auth_strategies] do
      handle_oauth_request(conn, provider, opts)
    else
      send_error(conn, :not_found, "OAuth provider not configured")
    end
  end

  # OAuth callback endpoint - handles OAuth provider callbacks and completes authentication
  get "/auth/:provider/callback" do
    provider = String.to_existing_atom(provider)
    opts = conn.assigns[:oauth_opts] || []

    handle_oauth_callback(conn, provider, opts)
  end

  # OAuth success page - displays authentication success and provides session information
  get "/auth/success" do
    mcp_session = conn.assigns[:mcp_session]
    user = conn.assigns[:current_user]

    success_html = """
    <!DOCTYPE html>
    <html>
    <head>
      <title>MCP Authentication Success</title>
      <meta charset="utf-8">
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
        .success { color: #28a745; }
        .info { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0; }
        code { background: #f1f3f4; padding: 2px 4px; border-radius: 3px; }
      </style>
    </head>
    <body>
      <h1 class="success">✅ MCP Authentication Successful</h1>
      
      <div class="info">
        <h3>Session Information</h3>
        <p><strong>Session ID:</strong> <code>#{mcp_session && mcp_session.id}</code></p>
        <p><strong>User:</strong> #{user && user.email}</p>
        <p><strong>Authenticated At:</strong> #{DateTime.utc_now() |> DateTime.to_iso8601()}</p>
      </div>
      
      <div class="info">
        <h3>Next Steps</h3>
        <p>Your MCP session has been created. You can now:</p>
        <ul>
          <li>Use the session ID in MCP client connections</li>
          <li>Access authenticated MCP endpoints</li>
          <li>Close this window and return to your application</li>
        </ul>
      </div>
      
      <script>
        // Auto-close after 5 seconds if opened in popup
        if (window.opener) {
          setTimeout(() => {
            window.close();
          }, 5000);
        }
      </script>
    </body>
    </html>
    """

    conn
    |> put_resp_content_type("text/html")
    |> send_resp(200, success_html)
  end

  # OAuth failure page - displays authentication failure information
  get "/auth/failure" do
    error = conn.params["error"] || "unknown_error"
    error_description = conn.params["error_description"] || "Authentication failed"

    failure_html = """
    <!DOCTYPE html>
    <html>
    <head>
      <title>MCP Authentication Failed</title>
      <meta charset="utf-8">
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
        .error { color: #dc3545; }
        .info { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0; }
        code { background: #f1f3f4; padding: 2px 4px; border-radius: 3px; }
      </style>
    </head>
    <body>
      <h1 class="error">❌ MCP Authentication Failed</h1>
      
      <div class="info">
        <h3>Error Details</h3>
        <p><strong>Error:</strong> <code>#{error}</code></p>
        <p><strong>Description:</strong> #{error_description}</p>
      </div>
      
      <div class="info">
        <h3>What to do next</h3>
        <ul>
          <li>Try authenticating again</li>
          <li>Check your OAuth provider settings</li>
          <li>Contact your administrator if the problem persists</li>
        </ul>
      </div>
      
      <script>
        // Auto-close after 10 seconds if opened in popup
        if (window.opener) {
          setTimeout(() => {
            window.close();
          }, 10000);
        }
      </script>
    </body>
    </html>
    """

    conn
    |> put_resp_content_type("text/html")
    |> send_resp(200, failure_html)
  end

  # MCP session status endpoint - returns current authentication status for MCP clients
  get "/status" do
    user = conn.assigns[:current_user]
    mcp_session = conn.assigns[:mcp_session]

    status = %{
      authenticated: not is_nil(user),
      user: if(user, do: %{id: user.id, email: user.email}, else: nil),
      session_id: mcp_session && mcp_session.id,
      auth_method: conn.assigns[:auth_method]
    }

    send_json(conn, status)
  end

  # Catch-all for unmatched routes
  match _ do
    send_error(conn, :not_found, "Endpoint not found")
  end

  # Private functions

  defp handle_oauth_request(conn, provider, opts) do
    redirect_uri = build_callback_url(conn, provider)

    case AshAi.Mcp.Auth.oauth_authorize_url(provider,
           otp_app: opts[:otp_app],
           redirect_uri: redirect_uri
         ) do
      {:ok, auth_url, state} ->
        conn
        |> put_session(:oauth_state, state)
        |> put_session(:oauth_provider, provider)
        |> put_resp_header("location", auth_url)
        |> send_resp(302, "")

      {:error, reason} ->
        Logger.error("Failed to generate OAuth URL: #{inspect(reason)}")

        redirect_to_failure(
          conn,
          "oauth_url_generation_failed",
          "Failed to generate authorization URL"
        )
    end
  end

  defp handle_oauth_callback(conn, provider, opts) do
    stored_state = get_session(conn, :oauth_state)
    stored_provider = get_session(conn, :oauth_provider)
    received_state = conn.params["state"]

    cond do
      # Check for OAuth errors
      conn.params["error"] ->
        error = conn.params["error"]
        description = conn.params["error_description"] || "OAuth provider returned an error"
        Logger.warning("OAuth error: #{error} - #{description}")
        redirect_to_failure(conn, error, description)

      # Validate state parameter
      is_nil(stored_state) or stored_state != received_state ->
        Logger.warning("OAuth state mismatch or missing")
        redirect_to_failure(conn, "invalid_state", "State parameter mismatch")

      # Validate provider matches
      stored_provider != provider ->
        Logger.warning("OAuth provider mismatch")
        redirect_to_failure(conn, "provider_mismatch", "Provider mismatch")

      # Process successful callback
      true ->
        case AshAi.Mcp.Auth.handle_oauth_callback(conn, provider, opts) do
          %Plug.Conn{} = updated_conn ->
            # Clear OAuth session data
            updated_conn =
              updated_conn
              |> delete_session(:oauth_state)
              |> delete_session(:oauth_provider)

            redirect_to_success(updated_conn)

          {:error, reason} ->
            Logger.error("OAuth callback processing failed: #{inspect(reason)}")

            redirect_to_failure(
              conn,
              "callback_processing_failed",
              "Failed to process OAuth callback"
            )
        end
    end
  end

  defp build_callback_url(conn, provider) do
    scheme = if conn.scheme == :https, do: "https", else: "http"
    host = conn.host
    port = if conn.port in [80, 443], do: "", else: ":#{conn.port}"

    "#{scheme}://#{host}#{port}/mcp/auth/#{provider}/callback"
  end

  defp redirect_to_success(conn) do
    success_url = conn.assigns[:oauth_opts][:success_redirect] || "/mcp/auth/success"

    conn
    |> put_resp_header("location", success_url)
    |> send_resp(302, "")
  end

  defp redirect_to_failure(conn, error, description) do
    failure_url = conn.assigns[:oauth_opts][:failure_redirect] || "/mcp/auth/failure"

    query_params =
      URI.encode_query(%{
        error: error,
        error_description: description
      })

    redirect_url = "#{failure_url}?#{query_params}"

    conn
    |> put_resp_header("location", redirect_url)
    |> send_resp(302, "")
  end

  defp send_json(conn, data) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(200, Jason.encode!(data))
  end

  defp send_error(conn, :not_found, message) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(404, Jason.encode!(%{error: message}))
  end
end
