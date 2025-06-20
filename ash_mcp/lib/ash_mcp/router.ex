if Code.ensure_loaded?(Plug) do
  defmodule AshMcp.Router do
    @moduledoc """
    MCP Router implementing the RPC functionality over HTTP.

    This router handles HTTP requests according to the Model Context Protocol specification.

    ## Usage

    ```elixir
    # Basic usage
    forward "/mcp", AshMcp.Router, capabilities: [MyApp.ToolsCapability], otp_app: :my_app

    # With authentication (requires additional setup)
    forward "/mcp", AshMcp.Router,
      capabilities: [MyApp.ToolsCapability],
      otp_app: :my_app,
      auth_enabled?: true
    ```
    """

    use Plug.Router, copy_opts_to_assign: :router_opts

    alias AshMcp.Server

    # Parse the request body for JSON
    plug(Plug.Parsers,
      parsers: [:json],
      pass: ["application/json"],
      json_decoder: Jason
    )

    plug(:match)
    plug(:dispatch)

    post "/" do
      session_id = get_session_id(conn)
      opts = conn.assigns.router_opts

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

    # Helper to extract the session ID from headers
    defp get_session_id(conn) do
      case get_req_header(conn, "mcp-session-id") do
        [session_id | _] -> session_id
        [] -> nil
      end
    end
  end
end
