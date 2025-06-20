defmodule AshMcp.Server do
  @moduledoc """
  Core MCP server implementation.

  Handles JSON-RPC protocol and delegates to registered capabilities.
  """

  require Logger
  alias AshMcp.{Registry, Session}

  @doc """
  Handle HTTP POST request for JSON-RPC.
  """
  def handle_post(conn, params, session_id, opts) do
    case process_request(params, session_id, opts) do
      {:json_response, response, new_session_id} ->
        conn
        |> maybe_set_session_header(new_session_id)
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(200, response)

      {:no_response, _, _} ->
        Plug.Conn.send_resp(conn, 204, "")

      {:error, error} ->
        error_response = json_rpc_error_response(nil, -32000, "Server error", %{"error" => inspect(error)})

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(500, error_response)
    end
  end

  @doc """
  Handle HTTP GET request for health check.
  """
  def handle_get(conn, _session_id) do
    response = %{
      "status" => "ok",
      "protocol" => "mcp",
      "version" => "2025-03-26"
    }

    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(200, Jason.encode!(response))
  end

  @doc """
  Handle HTTP DELETE request for session termination.
  """
  def handle_delete(conn, session_id) do
    if session_id do
      Session.terminate_session(session_id)
    end

    Plug.Conn.send_resp(conn, 200, "")
  end

  defp process_request(request, session_id, opts) do
    case parse_json_rpc(request) do
      {:ok, message} when is_map(message) ->
        process_message(message, session_id, opts)

      {:error, error} ->
        response = json_rpc_error_response(nil, -32700, "Parse error", %{"details" => inspect(error)})
        {:json_response, response, session_id}
    end
  end

  defp process_message(message, session_id, opts) do
    case message do
      %{"method" => "initialize", "id" => id, "params" => params} ->
        handle_initialize(id, params, session_id, opts)

      %{"method" => "ping", "id" => id} ->
        handle_ping(id, session_id)

      %{"method" => method, "id" => id, "params" => params} ->
        handle_capability_method(method, id, params, session_id, opts)

      _ ->
        response = json_rpc_error_response(nil, -32601, "Method not found", %{})
        {:json_response, response, session_id}
    end
  end

  defp handle_initialize(id, params, session_id, opts) do
    new_session_id = session_id || AshMcp.Session.generate_session_id()

    session_opts = [
      client_info: params["clientInfo"] || %{},
      auth_context: %{
        actor: opts[:actor],
        tenant: opts[:tenant],
        context: opts[:context]
      }
    ]

    case Session.create_session(new_session_id, session_opts) do
      {:ok, _session} ->
        capabilities = Registry.build_capabilities_config(new_session_id, opts)
        Session.initialize_session(new_session_id, capabilities)

        response = %{
          "jsonrpc" => "2.0",
          "id" => id,
          "result" => %{
            "serverInfo" => %{
              "name" => opts[:server_name] || "AshMcp Server",
              "version" => opts[:server_version] || "0.1.0"
            },
            "protocolVersion" => opts[:protocol_version] || "2025-03-26",
            "capabilities" => capabilities
          }
        }

        {:json_response, Jason.encode!(response), new_session_id}

      {:error, error} ->
        response = json_rpc_error_response(id, -32000, "Session creation failed", %{"error" => inspect(error)})
        {:json_response, response, session_id}
    end
  end

  defp handle_ping(id, session_id) do
    if session_id do
      Session.touch_session(session_id)
    end

    response = %{
      "jsonrpc" => "2.0",
      "id" => id,
      "result" => %{}
    }

    {:json_response, Jason.encode!(response), session_id}
  end

  defp handle_capability_method(method, id, params, session_id, opts) do
    case Registry.handle_method(method, params, session_id, opts) do
      {:ok, result} ->
        response = %{
          "jsonrpc" => "2.0",
          "id" => id,
          "result" => result
        }
        {:json_response, Jason.encode!(response), session_id}

      {:error, error} ->
        response = json_rpc_error_response(id, -32000, "Method execution failed", %{"error" => inspect(error)})
        {:json_response, response, session_id}

      :not_handled ->
        response = json_rpc_error_response(id, -32601, "Method not found", %{"method" => method})
        {:json_response, response, session_id}
    end
  end

  defp parse_json_rpc(params) when is_map(params), do: {:ok, params}
  defp parse_json_rpc(_), do: {:error, :invalid_request}

  defp json_rpc_error_response(id, code, message, data \\ %{}) do
    response = %{
      "jsonrpc" => "2.0",
      "id" => id,
      "error" => %{
        "code" => code,
        "message" => message,
        "data" => data
      }
    }

    Jason.encode!(response)
  end

  defp maybe_set_session_header(conn, nil), do: conn
  defp maybe_set_session_header(conn, session_id) do
    Plug.Conn.put_resp_header(conn, "mcp-session-id", session_id)
  end
end
