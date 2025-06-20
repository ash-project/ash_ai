if Code.ensure_loaded?(Plug) do
  defmodule AshAi.Mcp.Router do
    @moduledoc """
    MCP Router that provides a simple implementation for Ash applications.

    ## Usage

    ```elixir
    # In your Phoenix router
    forward "/mcp", AshAi.Mcp.Router

    # With tools enabled
    forward "/mcp", AshAi.Mcp.Router, tools: [:tool1, :tool2]
    ```

    This router implements the basic MCP protocol with tools capability.
    For more advanced features, consider using the ash_mcp library directly.
    """

    use Plug.Router, copy_opts_to_assign: :router_opts

    plug(:match)
    plug(:dispatch)

    match _ do
      opts = conn.assigns.router_opts
      
      # Extract session from headers
      session_id = 
        case Plug.Conn.get_req_header(conn, "mcp-session-id") do
          [] -> nil
          [session_id] -> session_id
        end

      case conn.method do
        "POST" ->
          # Read body
          {:ok, body, _conn} = Plug.Conn.read_body(conn)
          AshAi.Mcp.Server.handle_post(conn, body, session_id, opts)

        "GET" ->
          AshAi.Mcp.Server.handle_get(conn, session_id)

        "DELETE" ->
          AshAi.Mcp.Server.handle_delete(conn, session_id)

        _ ->
          send_resp(conn, 405, "Method not allowed")
      end
    end
  end
end
