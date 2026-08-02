# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

if Code.ensure_loaded?(Plug) do
  defmodule AshAi.Mcp.Router do
    @moduledoc """
    MCP Router implementing the RPC functionality over HTTP.

    This router handles HTTP requests according to the Model Context Protocol specification.

    ## Usage

    ```elixir
    forward "/mcp", AshAi.Mcp.Router, tools: [:tool1, :tool2], otp_app: :my_app
    ```

    Tool schemas are generated without the OpenAI strict-mode transformation by
    default — MCP clients don't constrain sampling with the schema, so the
    honest form is smaller and clearer. Pass `strict: true` to restore it.

    A `tool_argument_transformer` option may be a three-arity function receiving
    the resolved `%AshAi.Tool{}`, its argument map, and the request's Ash tool
    context. It must return `{:ok, arguments}` or `{:error, message}`. Rejections
    are rendered as ordinary MCP tool errors in the selected protocol envelope.
    """

    use Plug.Router, copy_opts_to_assign: :router_opts

    alias AshAi.Mcp.Server

    # DNS-rebinding protection: the transport requires Origin validation on
    # all incoming connections. Configure with `allowed_origins` (a list of
    # origin strings or a 1-arity predicate); by default localhost origins
    # and same-host HTTPS origins are accepted, and requests without an
    # Origin header (non-browser MCP clients) always pass.
    plug(:validate_origin)

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

      Server.handle_post(conn, conn.params, session_id, conn.assigns.router_opts)
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

    # sobelow_skip ["XSS.SendResp"]
    # The 403 body is a static JSON literal; no user input is reflected.
    defp validate_origin(conn, _opts) do
      case Server.check_origin(conn, conn.assigns[:router_opts] || []) do
        :ok ->
          conn

        :forbidden ->
          conn
          |> put_resp_header("content-type", "application/json")
          |> send_resp(
            403,
            Jason.encode!(%{
              "jsonrpc" => "2.0",
              "id" => nil,
              "error" => %{"code" => -32_600, "message" => "Origin not allowed"}
            })
          )
          |> halt()
      end
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
