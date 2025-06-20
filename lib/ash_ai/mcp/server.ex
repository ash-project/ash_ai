defmodule AshAi.Mcp.Server do
  @moduledoc """
  Implementation of the Model Context Protocol (MCP) RPC functionality.

  This module handles HTTP requests and responses according to the MCP specification,
  supporting both synchronous and streaming communication patterns.
  It also handles the core JSON-RPC message processing for the protocol.

  The server uses a capability registry system to dynamically discover and handle
  different MCP capabilities like tools, resources, and prompts.
  """

  alias AshAi.Mcp.Registry
  alias AshAi.Mcp.Session

  @doc """
  Process an HTTP POST request containing JSON-RPC messages
  """
  # sobelow_skip ["XSS.SendResp"]
  def handle_post(conn, body, session_id, opts \\ []) do
    accept_header = Plug.Conn.get_req_header(conn, "accept")
    _accept_sse = Enum.any?(accept_header, &String.contains?(&1, "text/event-stream"))
    _accept_json = Enum.any?(accept_header, &String.contains?(&1, "application/json"))

    opts =
      [
        actor: Ash.PlugHelpers.get_actor(conn),
        tenant: Ash.PlugHelpers.get_tenant(conn),
        context: Ash.PlugHelpers.get_context(conn) || %{}
      ]
      |> Keyword.merge(opts)

    case process_request(body, session_id, opts) do
      {:initialize_response, response, new_session_id} ->
        # Return the initialize response with a session ID header
        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.put_resp_header("mcp-session-id", new_session_id)
        |> Plug.Conn.send_resp(200, response)

      {:json_response, response, _session_id} ->
        # Regular JSON response
        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.send_resp(200, response)

      {:batch_response, response, _session_id} ->
        # Batch response
        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.send_resp(200, response)

      {:no_response, _, _} ->
        # For notifications or other messages that don't require a response
        conn
        |> Plug.Conn.send_resp(202, "")
    end
  end

  @doc """
  Process an HTTP GET request to open an SSE stream
  """
  def handle_get(conn, _session_id) do
    accept_header = Plug.Conn.get_req_header(conn, "accept")

    if Enum.any?(accept_header, &String.contains?(&1, "text/event-stream")) do
      # Get the current host and path to create the post URL
      host = Plug.Conn.get_req_header(conn, "host") |> List.first()
      scheme = if conn.scheme == :https, do: "https", else: "http"
      path = conn.request_path
      post_url = "#{scheme}://#{host}#{path}"

      # Set up SSE stream
      conn
      |> Plug.Conn.put_resp_header("content-type", "text/event-stream")
      |> Plug.Conn.put_resp_header("cache-control", "no-cache")
      # Send the post_url in an endpoint event according to MCP specification
      |> Plug.Conn.send_chunked(200)
      |> send_sse_event("endpoint", Jason.encode!(%{"url" => post_url}))
      |> Plug.Conn.halt()
    else
      # Client doesn't support SSE
      conn
      |> Plug.Conn.send_resp(400, "Client must accept text/event-stream")
    end
  end

  @doc """
  Handle HTTP DELETE request for session termination
  """
  def handle_delete(conn, session_id) do
    if session_id do
      Session.terminate_session(session_id)

      conn
      |> Plug.Conn.send_resp(200, "")
    else
      conn
      |> Plug.Conn.send_resp(400, "")
    end
  end

  @doc """
  Send an SSE event over the chunked connection
  """
  def send_sse_event(conn, event, data, id \\ nil) do
    chunks = [
      if(id, do: "id: #{id}\n", else: ""),
      "event: #{event}\n",
      "data: #{data}\n\n"
    ]

    Enum.reduce(chunks, conn, fn chunk, conn ->
      {:ok, conn} = Plug.Conn.chunk(conn, chunk)
      conn
    end)
  end

  @doc """
  Get the MCP server version
  """
  def get_server_version(opts) do
    if opts[:mcp_server_version] do
      opts[:mcp_server_version]
    else
      if opts[:otp_app] do
        case :application.get_key(opts[:otp_app], :vsn) do
          {:ok, version} -> List.to_string(version)
          :undefined -> "0.1.0"
        end
      else
        "0.1.0"
      end
    end
  end

  @doc """
  Get the MCP server name
  """
  def get_server_name(opts) do
    if opts[:mcp_name] do
      opts[:mcp_name]
    else
      if opts[:otp_app] do
        "MCP Server"
      else
        "#{opts[:otp_app]} MCP Server"
      end
    end
  end

  defp process_request(request, session_id, opts) do
    case parse_json_rpc(request) do
      {:ok, message} when is_map(message) ->
        # Process a single message
        process_message(message, session_id, opts)

      {:ok, batch} when is_list(batch) ->
        # Handle batch requests
        responses = Enum.map(batch, fn item -> process_message(item, session_id, opts) end)

        # Filter out no_response items and format the response
        response_items = Enum.filter(responses, fn {type, _, _} -> type != :no_response end)

        if Enum.empty?(response_items) do
          # All items were notifications, no response needed
          {:no_response, nil, session_id}
        else
          # Convert each response to its JSON representation
          json_responses = Enum.map(response_items, fn {_, json, _} -> json end)
          {:batch_response, "[#{Enum.join(json_responses, ",")}]", session_id}
        end

      {:error, error} ->
        # Handle parsing errors
        response =
          json_rpc_error_response(nil, -32_700, "Parse error", %{"details" => inspect(error)})

        {:json_response, response, session_id}
    end
  end

  @doc """
  Process a single JSON-RPC message
  """
  def process_message(message, session_id, opts) do
    case message do
      %{"method" => "initialize", "id" => id, "params" => params} ->
        # Handle initialize request
        new_session_id = session_id || Ash.UUIDv7.generate()

        # Create or update session
        auth_context = %{
          actor: opts[:actor],
          tenant: opts[:tenant],
          context: opts[:context]
        }

        session_opts = [
          client_info: params["clientInfo"] || %{},
          auth_context: auth_context
        ]

        case Session.create_session(new_session_id, session_opts) do
          {:ok, _session} ->
            protocol_version_statement = opts[:protocol_version_statement] || "2025-03-26"

            # Return capabilities from registry
            capabilities = Registry.build_capabilities_config(new_session_id, opts)

            # Mark session as initialized
            Session.initialize_session(new_session_id, capabilities)

            response = %{
              "jsonrpc" => "2.0",
              "id" => id,
              "result" => %{
                "serverInfo" => %{
                  "name" => get_server_name(opts),
                  "version" => get_server_version(opts)
                },
                "protocolVersion" => protocol_version_statement,
                "capabilities" => capabilities
              }
            }

            {:initialize_response, Jason.encode!(response), new_session_id}

          {:error, error} ->
            response = %{
              "jsonrpc" => "2.0",
              "id" => id,
              "error" => %{
                "code" => -32_000,
                "message" => "Session creation failed",
                "data" => %{"error" => inspect(error)}
              }
            }

            {:json_response, Jason.encode!(response), session_id}
        end

      %{"method" => "shutdown", "id" => id, "params" => _params} ->
        # Terminate session
        if session_id do
          Session.terminate_session(session_id)
        end

        # Return success
        response = %{
          "jsonrpc" => "2.0",
          "id" => id,
          "result" => nil
        }

        {:json_response, Jason.encode!(response), session_id}

      %{"method" => "$/cancelRequest", "params" => %{"id" => _request_id}} ->
        # TODO: Cancel request?
        {:no_response, nil, session_id}

      %{"method" => "ping", "id" => id, "params" => _params} ->
        # Handle ping request according to MCP specification
        # Update session activity if we have one
        if session_id do
          Session.touch_session(session_id)
        end

        response = %{
          "jsonrpc" => "2.0",
          "id" => id,
          "result" => %{}
        }

        {:json_response, Jason.encode!(response), session_id}

      %{"method" => "ping", "id" => id} ->
        # Handle ping request according to MCP specification
        # Update session activity if we have one
        if session_id do
          Session.touch_session(session_id)
        end

        response = %{
          "jsonrpc" => "2.0",
          "id" => id,
          "result" => %{}
        }

        {:json_response, Jason.encode!(response), session_id}

      %{"method" => method, "id" => id, "params" => params}
      when method in [
             "tools/list",
             "tools/call",
             "resources/list",
             "resources/read",
             "resources/templates/list",
             "prompts/list",
             "prompts/get"
           ] ->
        # Update session activity
        if session_id do
          Session.touch_session(session_id)
        end

        # Handle capability methods through registry
        case Registry.handle_method(method, params, session_id, opts) do
          {:ok, result} ->
            response = %{
              "jsonrpc" => "2.0",
              "id" => id,
              "result" => result
            }

            {:json_response, Jason.encode!(response), session_id}

          {:error, {:tool_not_found, tool_name}} ->
            response = %{
              "jsonrpc" => "2.0",
              "id" => id,
              "error" => %{
                "code" => -32_602,
                "message" => "Tool not found: #{tool_name}"
              }
            }

            {:json_response, Jason.encode!(response), session_id}

          {:error, {:tool_execution_failed, error}} ->
            response = %{
              "jsonrpc" => "2.0",
              "id" => id,
              "error" => %{
                "code" => -32_000,
                "message" => "Tool execution failed",
                "data" => %{"error" => inspect(error)}
              }
            }

            {:json_response, Jason.encode!(response), session_id}

          {:error, error} ->
            response = %{
              "jsonrpc" => "2.0",
              "id" => id,
              "error" => %{
                "code" => -32_000,
                "message" => "Capability error",
                "data" => %{"error" => inspect(error)}
              }
            }

            {:json_response, Jason.encode!(response), session_id}

          :not_handled ->
            # Fall back to method not implemented
            response = %{
              "jsonrpc" => "2.0",
              "id" => id,
              "error" => %{
                "code" => -32_601,
                "message" => "Method not implemented: #{method}"
              }
            }

            {:json_response, Jason.encode!(response), session_id}
        end

      %{"method" => method, "id" => id, "params" => _params} ->
        # Handle other requests with IDs (requiring responses)
        response = %{
          "jsonrpc" => "2.0",
          "id" => id,
          "error" => %{
            "code" => -32_601,
            "message" => "Method not implemented: #{method}"
          }
        }

        {:json_response, Jason.encode!(response), session_id}

      %{"method" => _method} ->
        # Handle other notifications (no id)
        {:no_response, nil, session_id}

      _other ->
        # Invalid message
        {:json_response, json_rpc_error_response(nil, -32_600, "Invalid Request"), session_id}
    end
  end

  @doc """
  Parse the JSON-RPC request
  """
  def parse_json_rpc(request) when is_binary(request) do
    case Jason.decode(request) do
      {:ok, decoded} -> {:ok, decoded}
      {:error, _} = error -> error
    end
  end

  def parse_json_rpc(request) when is_map(request) do
    {:ok, request}
  end

  @doc """
  Create a standard JSON-RPC error response
  """
  def json_rpc_error_response(id, code, message, data \\ nil) do
    error = %{"code" => code, "message" => message}
    error = if data, do: Map.put(error, "data", data), else: error

    Jason.encode!(%{
      "jsonrpc" => "2.0",
      "id" => id,
      "error" => error
    })
  end
end
