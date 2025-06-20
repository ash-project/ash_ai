if Code.ensure_loaded?(Plug) do
  defmodule AshAi.Mcp.Router do
    @moduledoc """
    MCP Router implementing the RPC functionality over HTTP.

    This router handles HTTP requests according to the Model Context Protocol specification.
    Supports optional OAuth authentication through AshAuthentication integration.

    ## Usage

    ```elixir
    # Basic usage without authentication
    forward "/mcp", AshAi.Mcp.Router, tools: [:tool1, :tool2], otp_app: :my_app

    # With OAuth authentication
    forward "/mcp", AshAi.Mcp.Router, 
      tools: [:tool1, :tool2], 
      otp_app: :my_app,
      auth_enabled?: true,
      auth_strategies: [:github, :google],
      require_auth?: false
    ```
    """

    use Plug.Router, copy_opts_to_assign: :router_opts

    alias AshAi.Mcp.Auth
    alias AshAi.Mcp.Server

    # Parse the request body for JSON
    plug(Plug.Parsers,
      parsers: [:json],
      pass: ["application/json"],
      json_decoder: Jason
    )

    # Add authentication middleware if enabled
    plug(:maybe_authenticate)

    plug(:match)
    plug(:dispatch)

    # OAuth authentication routes (conditional)
    get "/auth/status" do
      handle_auth_route(conn, fn conn ->
        user = conn.assigns[:current_user]
        mcp_session = conn.assigns[:mcp_session]

        status = %{
          authenticated: not is_nil(user),
          user: if(user, do: %{id: user.id, email: user.email}, else: nil),
          session_id: mcp_session && mcp_session.id,
          auth_method: conn.assigns[:auth_method]
        }

        conn
        |> put_resp_content_type("application/json")
        |> send_resp(200, Jason.encode!(status))
      end)
    end

    post "/" do
      session_id = get_session_id(conn)
      opts = merge_auth_context(conn.assigns.router_opts, conn)

      Server.handle_post(conn, conn.params, session_id, opts)
    end

    get "/" do
      session_id = get_session_id(conn)

      Server.handle_get(conn, session_id)
    end

    delete "/" do
      session_id = get_session_id(conn)

      Server.handle_delete(conn, session_id)
    end

    # Default route
    match _ do
      send_resp(conn, 404, "Not found")
    end

    # Authentication middleware
    defp maybe_authenticate(conn, _opts) do
      if conn.assigns.router_opts[:auth_enabled?] do
        auth_opts = Auth.plug(conn.assigns.router_opts)
        Auth.call(conn, auth_opts)
      else
        conn
      end
    end

    # Helper to extract the session ID from headers
    defp get_session_id(conn) do
      case get_req_header(conn, "mcp-session-id") do
        [session_id | _] -> session_id
        [] -> nil
      end
    end

    # Handle authentication routes conditionally
    defp handle_auth_route(conn, handler) do
      if conn.assigns.router_opts[:auth_enabled?] do
        handler.(conn)
      else
        conn
        |> put_resp_content_type("application/json")
        |> send_resp(404, Jason.encode!(%{error: "Authentication not enabled"}))
      end
    end

    # Merge authentication context into opts
    defp merge_auth_context(opts, conn) do
      auth_context = [
        actor: conn.assigns[:current_user],
        tenant: conn.assigns[:current_tenant],
        context: %{
          authenticated?: Auth.authenticated?(conn),
          auth_method: conn.assigns[:auth_method],
          mcp_session: conn.assigns[:mcp_session]
        }
      ]

      opts
      |> Keyword.merge(auth_context)
      |> Keyword.update(:context, auth_context[:context], fn existing_context ->
        Map.merge(existing_context || %{}, auth_context[:context])
      end)
    end
  end
end
