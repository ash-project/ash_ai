# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.Server do
  @moduledoc """
  Implementation of the Model Context Protocol (MCP) RPC functionality.

  This module handles HTTP requests and responses according to the MCP specification,
  supporting both synchronous and streaming communication patterns.
  It also handles the core JSON-RPC message processing for the protocol.

  ## Protocol versions

  The server supports multiple protocol revisions in tandem on the same
  endpoint:

  * `2026-07-28`, which carries the protocol version, client identity, and
    capabilities in each request's `_meta` and never performs an
    `initialize` handshake, and
  * the initialize-based revisions (`2025-06-18` and `2025-03-26`), which
    negotiate via `initialize` and may use the `Mcp-Session-Id` header.

  The revision is selected per request: an `initialize` request (or a
  request carrying an initialize-based/absent `MCP-Protocol-Version` header
  and no per-request version `_meta`) is served with initialize-based
  semantics; a request declaring its protocol version in `_meta` (or in the
  `MCP-Protocol-Version` header) is served statelessly per the `2026-07-28`
  revision.
  """

  alias AshAi.Tool

  # Protocol revisions that declare their version on every request
  @per_request_versions ["2026-07-28"]
  # Protocol revisions that negotiate their version via `initialize`
  @initialize_based_versions ["2025-06-18", "2025-03-26"]
  @supported_protocol_versions @per_request_versions ++ @initialize_based_versions

  @meta_protocol_version "io.modelcontextprotocol/protocolVersion"
  @meta_client_info "io.modelcontextprotocol/clientInfo"
  @meta_client_capabilities "io.modelcontextprotocol/clientCapabilities"
  @meta_server_info "io.modelcontextprotocol/serverInfo"
  @meta_subscription_id "io.modelcontextprotocol/subscriptionId"

  @doc """
  The protocol versions this server supports, newest first.
  """
  def supported_protocol_versions, do: @supported_protocol_versions

  @doc """
  Process an HTTP POST request containing JSON-RPC messages
  """
  def handle_post(conn, body, session_id, opts \\ []) do
    accept_header = Plug.Conn.get_req_header(conn, "accept")
    _accept_sse = Enum.any?(accept_header, &String.contains?(&1, "text/event-stream"))
    _accept_json = Enum.any?(accept_header, &String.contains?(&1, "application/json"))

    server_url = server_url(conn)

    opts =
      [
        actor: Ash.PlugHelpers.get_actor(conn),
        tenant: Ash.PlugHelpers.get_tenant(conn),
        context: Ash.PlugHelpers.get_context(conn) || %{},
        server_url: server_url
      ]
      |> Keyword.merge(opts)

    body = unwrap_json_params(body)

    if per_request_version?(body, req_header(conn, "mcp-protocol-version")) do
      handle_post_2026_07_28(conn, body, opts)
    else
      handle_initialize_based_post(conn, body, session_id, opts)
    end
  end

  # sobelow_skip ["XSS.SendResp"]
  defp handle_initialize_based_post(conn, body, session_id, opts) do
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

  # Plug.Parsers wraps JSON array bodies (2025-03-26 batch requests) in a "_json" key
  defp unwrap_json_params(%{"_json" => list}) when is_list(list), do: list
  defp unwrap_json_params(body), do: body

  # Era selection per the 2026-07-28 versioning spec: `initialize` without
  # per-request `_meta` selects initialize-based semantics; with a `_meta`
  # protocol version it is a removed method under 2026-07-28 (404 below).
  # Otherwise a `_meta` protocol version or an `MCP-Protocol-Version` header
  # naming a non-initialize-based revision selects per-request semantics.
  defp per_request_version?(%{"method" => "initialize"} = body, _header_version),
    do: is_binary(request_meta_version(body))

  defp per_request_version?(body, header_version) when is_map(body) do
    cond do
      is_binary(request_meta_version(body)) ->
        true

      is_nil(header_version) ->
        false

      # Every dated revision before 2026-07-28 negotiates via `initialize` —
      # including ones this server doesn't itself advertise (e.g. a client
      # sending `2025-11-25` before initialize downgrades it). Route them all
      # to initialize-based semantics rather than demanding per-request
      # `_meta` they cannot know about. Revision dates are ISO-8601, so
      # string comparison orders them correctly.
      header_version < hd(@per_request_versions) ->
        false

      true ->
        true
    end
  end

  # Batches are only defined for initialize-based protocol versions. A batch
  # carrying a current/future per-request version must still enter the current
  # handler so it can return one bounded Invalid Request response rather than
  # accidentally using the initialize-era batch path.
  defp per_request_version?(body, header_version) when is_list(body),
    do: is_binary(header_version) and header_version >= hd(@per_request_versions)

  defp per_request_version?(_body, _header_version), do: false

  defp request_meta_version(%{"params" => %{"_meta" => %{@meta_protocol_version => version}}}),
    do: version

  defp request_meta_version(_body), do: nil

  defp handle_post_2026_07_28(conn, %{"method" => method, "id" => id} = message, opts) do
    cond do
      # Structurally invalid `_meta` is Invalid Params, before any version or
      # header comparison (SEP-2575)
      error = validate_request_meta(message) ->
        error_response_2026_07_28(conn, 400, id, -32_602, error)

      # Header/body consistency comes before version support: a request whose
      # header disagrees with its `_meta` is a HeaderMismatch even when one
      # of the two names an unsupported version
      error = validate_headers_2026_07_28(conn, message) ->
        error_response_2026_07_28(conn, 400, id, -32_020, error)

      (requested = request_meta_version(message)) not in @per_request_versions ->
        error_response_2026_07_28(conn, 400, id, -32_022, "Unsupported protocol version", %{
          "supported" => @supported_protocol_versions,
          "requested" => requested
        })

      true ->
        dispatch_2026_07_28(conn, method, id, message["params"] || %{}, opts)
    end
  end

  # Notifications: the core 2026-07-28 protocol defines no client-to-server
  # notifications over Streamable HTTP, and defines no header requirements
  # for notification POSTs. Accept and ignore.
  defp handle_post_2026_07_28(conn, %{"method" => _method}, _opts) do
    Plug.Conn.send_resp(conn, 202, "")
  end

  defp handle_post_2026_07_28(conn, batch, _opts) when is_list(batch) do
    error_response_2026_07_28(
      conn,
      400,
      nil,
      -32_600,
      "JSON-RPC batch requests are not supported for protocol version 2026-07-28"
    )
  end

  defp handle_post_2026_07_28(conn, other, _opts) do
    error_response_2026_07_28(conn, 400, nil, -32_600, "Invalid Request Got: #{inspect(other)}")
  end

  # Every request must carry `_meta` with the protocol version and client
  # capabilities. `clientInfo` is a SHOULD and MUST NOT be required.
  defp validate_request_meta(message) do
    meta = get_in(message, ["params", "_meta"])

    cond do
      not is_map(meta) ->
        "Invalid params: missing required _meta"

      not is_binary(meta[@meta_protocol_version]) ->
        "Invalid params: _meta is missing #{@meta_protocol_version}"

      not is_map(meta[@meta_client_capabilities]) ->
        "Invalid params: _meta is missing #{@meta_client_capabilities}"

      Map.has_key?(meta, @meta_client_info) and
          not valid_implementation?(meta[@meta_client_info]) ->
        "Invalid params: #{@meta_client_info} must include string name and version fields"

      true ->
        nil
    end
  end

  defp valid_implementation?(%{"name" => name, "version" => version})
       when is_binary(name) and is_binary(version),
       do: true

  defp valid_implementation?(_client_info), do: false

  defp validate_headers_2026_07_28(conn, %{"method" => method} = message) do
    header_version = req_header(conn, "mcp-protocol-version")
    meta_version = request_meta_version(message)
    mcp_method = req_header(conn, "mcp-method")

    cond do
      duplicate_req_header?(conn, "mcp-protocol-version") ->
        "MCP-Protocol-Version header must appear exactly once"

      is_nil(header_version) ->
        "Missing required MCP-Protocol-Version header"

      header_version != meta_version ->
        "MCP-Protocol-Version header value #{inspect(header_version)} does not match body _meta value #{inspect(meta_version)}"

      is_nil(mcp_method) ->
        "Missing required Mcp-Method header"

      duplicate_req_header?(conn, "mcp-method") ->
        "Mcp-Method header must appear exactly once"

      mcp_method != method ->
        "Mcp-Method header value #{inspect(mcp_method)} does not match body value #{inspect(method)}"

      method in ["tools/call", "resources/read", "prompts/get"] ->
        validate_mcp_name_header(conn, message)

      true ->
        nil
    end
  end

  defp validate_mcp_name_header(conn, %{"method" => method} = message) do
    expected =
      case method do
        "resources/read" -> get_in(message, ["params", "uri"])
        _ -> get_in(message, ["params", "name"])
      end

    case {req_header(conn, "mcp-name"), duplicate_req_header?(conn, "mcp-name")} do
      {_value, true} ->
        "Mcp-Name header must appear exactly once"

      {nil, false} ->
        "Missing required Mcp-Name header"

      {value, false} ->
        case decode_header_value(value) do
          {:ok, ^expected} ->
            nil

          {:ok, decoded} ->
            "Mcp-Name header value #{inspect(decoded)} does not match body value #{inspect(expected)}"

          :error ->
            "Mcp-Name header value is not valid Base64 sentinel encoding"
        end
    end
  end

  # Values that cannot be represented as plain ASCII header values are carried
  # Base64-encoded as `=?base64?{encoded}?=`
  defp decode_header_value("=?base64?" <> rest) do
    with true <- String.ends_with?(rest, "?="),
         encoded = binary_part(rest, 0, byte_size(rest) - 2),
         {:ok, decoded} <- Base.decode64(encoded) do
      {:ok, decoded}
    else
      _ -> :error
    end
  end

  defp decode_header_value(value), do: {:ok, value}

  defp dispatch_2026_07_28(conn, "server/discover", id, _params, opts) do
    result =
      %{
        "supportedVersions" => @supported_protocol_versions,
        "capabilities" => opts |> mcp_resources() |> capabilities()
      }
      |> maybe_put("instructions", get_instructions(opts))
      |> cacheable_result(opts, :list)
      |> result_2026_07_28(opts)

    response_2026_07_28(conn, 200, id, result)
  end

  defp dispatch_2026_07_28(conn, "tools/list", id, _params, opts) do
    result =
      %{"tools" => tool_definitions(opts)}
      |> cacheable_result(opts, :list)
      |> result_2026_07_28(opts)

    response_2026_07_28(conn, 200, id, result)
  end

  defp dispatch_2026_07_28(conn, "tools/call", id, params, opts) do
    case execute_tool_call(params, nil, opts) do
      {:ok, result} ->
        response_2026_07_28(conn, 200, id, result_2026_07_28(result, opts))

      {:error, :tool_not_found} ->
        error_response_2026_07_28(conn, 200, id, -32_602, "Tool not found: #{params["name"]}")
    end
  end

  defp dispatch_2026_07_28(conn, "resources/list", id, _params, opts) do
    result =
      %{"resources" => resource_definitions(opts)}
      |> cacheable_result(opts, :list)
      |> result_2026_07_28(opts)

    response_2026_07_28(conn, 200, id, result)
  end

  defp dispatch_2026_07_28(conn, "resources/read", id, %{"uri" => uri} = params, opts) do
    case read_resource_content(uri, params, nil, opts) do
      {:ok, content} ->
        result =
          %{"contents" => [content]}
          |> cacheable_result(opts, :read)
          |> result_2026_07_28(opts)

        response_2026_07_28(conn, 200, id, result)

      {:error, :not_found} ->
        # 2026-07-28 aligns resource-not-found with JSON-RPC Invalid Params
        error_response_2026_07_28(conn, 200, id, -32_602, "Resource not found", %{"uri" => uri})

      {:error, error} ->
        error_response_2026_07_28(conn, 200, id, -32_603, "Resource read failed", %{
          "uri" => uri,
          "error" => error
        })
    end
  end

  defp dispatch_2026_07_28(conn, "resources/read", id, _params, _opts) do
    error_response_2026_07_28(conn, 200, id, -32_602, "Missing required parameter: uri")
  end

  # This server's tool and resource lists are derived from compile-time DSL
  # configuration and never change at runtime, so no notification types are
  # honored: acknowledge with an empty filter and close the stream gracefully.
  defp dispatch_2026_07_28(conn, "subscriptions/listen", id, _params, opts) do
    ack = %{
      "jsonrpc" => "2.0",
      "method" => "notifications/subscriptions/acknowledged",
      "params" => %{
        "_meta" => %{@meta_subscription_id => id},
        "notifications" => %{}
      }
    }

    close = %{
      "jsonrpc" => "2.0",
      "id" => id,
      "result" => result_2026_07_28(%{"_meta" => %{@meta_subscription_id => id}}, opts)
    }

    conn
    |> Plug.Conn.put_resp_header("content-type", "text/event-stream")
    |> Plug.Conn.put_resp_header("cache-control", "no-cache")
    |> Plug.Conn.put_resp_header("x-accel-buffering", "no")
    |> Plug.Conn.send_chunked(200)
    |> send_sse_event("message", Jason.encode!(ack))
    |> send_sse_event("message", Jason.encode!(close))
  end

  defp dispatch_2026_07_28(conn, "initialize", id, _params, _opts) do
    # Removed in 2026-07-28. Name the supported versions in the error —
    # initialize-based clients have no fall-forward mechanism, so this may
    # be the only diagnostic they can surface.
    error_response_2026_07_28(
      conn,
      404,
      id,
      -32_601,
      "Method not found: initialize was removed in 2026-07-28. " <>
        "Supported protocol versions: #{Enum.join(@supported_protocol_versions, ", ")}"
    )
  end

  defp dispatch_2026_07_28(conn, method, id, _params, _opts) do
    # Unknown methods return HTTP 404 so clients probing for 2026-07-28
    # support can distinguish this endpoint from a deprecated HTTP+SSE server
    error_response_2026_07_28(conn, 404, id, -32_601, "Method not found: #{method}")
  end

  defp result_2026_07_28(result, opts) do
    server_info = %{
      "name" => get_server_name(opts),
      "version" => get_server_version(opts)
    }

    result
    |> Map.put("resultType", "complete")
    |> Map.update(
      "_meta",
      %{@meta_server_info => server_info},
      &Map.put(&1, @meta_server_info, server_info)
    )
  end

  defp cacheable_result(result, opts, kind) do
    ttl_ms =
      case kind do
        :list -> Keyword.get(opts, :list_ttl_ms, 60_000)
        :read -> Keyword.get(opts, :read_ttl_ms, 0)
      end

    result
    |> Map.put("ttlMs", ttl_ms)
    |> Map.put("cacheScope", Keyword.get(opts, :cache_scope, "private"))
  end

  defp response_2026_07_28(conn, status, id, result) do
    send_json(conn, status, %{"jsonrpc" => "2.0", "id" => id, "result" => result})
  end

  defp error_response_2026_07_28(conn, status, id, code, message, data \\ nil) do
    error =
      %{"code" => code, "message" => message}
      |> maybe_put("data", data)

    send_json(conn, status, %{"jsonrpc" => "2.0", "id" => id, "error" => error})
  end

  # sobelow_skip ["XSS.SendResp"]
  defp send_json(conn, status, payload) do
    conn
    |> Plug.Conn.put_resp_header("content-type", "application/json")
    |> Plug.Conn.send_resp(status, Jason.encode!(payload))
  end

  defp req_header(conn, name) do
    case Plug.Conn.get_req_header(conn, name) do
      # Optional whitespace around an HTTP field value is not part of the
      # value (RFC 9110 §5.5); values that genuinely need surrounding
      # whitespace arrive Base64-sentinel-encoded instead
      [value | _] -> trim_ows(value)
      [] -> nil
    end
  end

  defp duplicate_req_header?(conn, name) do
    case Plug.Conn.get_req_header(conn, name) do
      [_value] -> false
      [] -> false
      [_value | _duplicates] -> true
    end
  end

  defp trim_ows(value), do: String.replace(value, ~r/^[ \t]+|[ \t]+$/, "")

  @doc """
  Validate the `Origin` header of a request per the Streamable HTTP
  transport's DNS-rebinding protection requirement.

  Returns `:ok` when the request carries no `Origin` header (non-browser
  clients), when the origin's host is a localhost value, when the origin
  matches the request host over HTTPS, or when it is explicitly allowed by
  the `:allowed_origins` option (a list of origin strings, or a 1-arity
  predicate function). Returns `:forbidden` otherwise — respond with HTTP
  403.
  """
  def check_origin(conn, opts) do
    case Plug.Conn.get_req_header(conn, "origin") do
      [] ->
        :ok

      [origin] ->
        if origin_allowed?(trim_ows(origin), conn, opts[:allowed_origins]) do
          :ok
        else
          :forbidden
        end

      [_origin | _duplicates] ->
        :forbidden
    end
  end

  defp origin_allowed?(origin, conn, nil) do
    uri = URI.parse(origin)

    localhost_host?(uri.host) or
      (uri.host == conn.host and forwarded_scheme(conn) == "https")
  end

  defp origin_allowed?(origin, _conn, allowed) when is_list(allowed), do: origin in allowed

  defp origin_allowed?(origin, _conn, allowed) when is_function(allowed, 1),
    do: allowed.(origin)

  defp localhost_host?(host), do: host in ["localhost", "127.0.0.1", "::1", "[::1]"]

  defp forwarded_scheme(conn) do
    case Plug.Conn.get_req_header(conn, "x-forwarded-proto") do
      [proto | _] -> proto
      [] -> to_string(conn.scheme)
    end
  end

  @doc """
  Process an HTTP GET request.

  Responds `405 Method Not Allowed`, which Streamable HTTP (2025-03-26
  onward) permits for servers that never send unsolicited server-to-client
  messages — this server has none to send (2026-07-28 clients use
  `subscriptions/listen` over POST instead). The previous behavior of
  opening an SSE stream and emitting an `endpoint` event was the wire
  signature of the deprecated 2024-11-05 HTTP+SSE transport, which caused
  dual-transport clients to switch to it and wait forever for responses on
  the GET stream.
  """
  def handle_get(conn, _session_id) do
    conn
    |> Plug.Conn.put_resp_header("allow", "POST, DELETE")
    |> Plug.Conn.send_resp(405, "")
  end

  @doc """
  Handle HTTP DELETE request for session termination
  """
  def handle_delete(conn, session_id) do
    case req_header(conn, "mcp-protocol-version") do
      version when version in @per_request_versions ->
        conn
        |> Plug.Conn.put_resp_header("allow", "POST")
        |> Plug.Conn.send_resp(405, "")

      _initialize_based_or_absent ->
        if session_id do
          conn
          |> Plug.Conn.send_resp(200, "")
        else
          conn
          |> Plug.Conn.send_resp(400, "")
        end
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

    Enum.reduce_while(chunks, conn, fn chunk, conn ->
      case Plug.Conn.chunk(conn, chunk) do
        {:ok, conn} -> {:cont, conn}
        {:error, _} -> {:halt, conn}
      end
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

  @doc """
  Get the MCP server instructions, if any. Returns the configured `instructions`
  option (a string) or the result of calling it as a 1-arity function with the
  request opts, or `nil` when unset. Forwarded on the `initialize` response so
  hosts can prime the model with server-level guidance (analogous to a scoped
  system prompt) alongside per-tool descriptions.
  """
  def get_instructions(opts) do
    case opts[:instructions] do
      nil -> nil
      str when is_binary(str) -> str
      fun when is_function(fun, 1) -> fun.(opts)
    end
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, _key, ""), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

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
        # Handle initialize request (initialize-based revisions only; from
        # 2026-07-28 on, clients carry their protocol version on every
        # request instead)
        new_session_id = session_id || Ash.UUIDv7.generate()

        requested_version = params["protocolVersion"]

        protocol_version_statement =
          opts[:protocol_version_statement] ||
            if(requested_version in @initialize_based_versions, do: requested_version) ||
            "2025-03-26"

        capabilities =
          opts
          |> mcp_resources()
          |> capabilities()

        result =
          %{
            "serverInfo" => %{
              "name" => get_server_name(opts),
              "version" => get_server_version(opts)
            },
            "protocolVersion" => protocol_version_statement,
            "capabilities" => capabilities
          }
          |> maybe_put("instructions", get_instructions(opts))

        response = %{"jsonrpc" => "2.0", "id" => id, "result" => result}

        {:initialize_response, Jason.encode!(response), new_session_id}

      # Removed in 2026-07-28; initialize-based revisions require a pong
      %{"method" => "ping", "id" => id} ->
        response = %{"jsonrpc" => "2.0", "id" => id, "result" => %{}}
        {:json_response, Jason.encode!(response), session_id}

      %{"method" => "shutdown", "id" => id, "params" => _params} ->
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

      # TODO: this can support paginaton via params later
      %{"method" => "resources/list", "id" => id} ->
        response = %{
          "jsonrpc" => "2.0",
          "id" => id,
          "result" => %{
            "resources" => resource_definitions(opts)
          }
        }

        {:json_response, Jason.encode!(response), session_id}

      %{"method" => "resources/read", "id" => id, "params" => %{"uri" => uri} = params} ->
        case read_resource_content(uri, params, session_id, opts) do
          {:ok, content} ->
            response = %{
              "jsonrpc" => "2.0",
              "id" => id,
              "result" => %{
                "contents" => [content]
              }
            }

            {:json_response, Jason.encode!(response), session_id}

          {:error, :not_found} ->
            response = %{
              "jsonrpc" => "2.0",
              "id" => id,
              "error" => %{
                "code" => -32_002,
                "message" => "Resource not found",
                "data" => %{"uri" => uri}
              }
            }

            {:json_response, Jason.encode!(response), session_id}

          {:error, error} ->
            response = %{
              "jsonrpc" => "2.0",
              "id" => id,
              "error" => %{
                "code" => -32_603,
                "message" => "Resource read failed",
                "data" => %{"uri" => uri, "error" => error}
              }
            }

            {:json_response, Jason.encode!(response), session_id}
        end

      %{"method" => "tools/list", "id" => id} ->
        response = %{
          "jsonrpc" => "2.0",
          "id" => id,
          "result" => %{
            "tools" => tool_definitions(opts)
          }
        }

        {:json_response, Jason.encode!(response), session_id}

      %{"method" => "tools/call", "id" => id, "params" => params} ->
        case execute_tool_call(params, session_id, opts) do
          {:ok, result} ->
            response = %{
              "jsonrpc" => "2.0",
              "id" => id,
              "result" => result
            }

            {:json_response, Jason.encode!(response), session_id}

          {:error, :tool_not_found} ->
            response = %{
              "jsonrpc" => "2.0",
              "id" => id,
              "error" => %{
                "code" => -32_602,
                "message" => "Tool not found: #{params["name"]}"
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

      other ->
        # Invalid message
        {:json_response,
         json_rpc_error_response(nil, -32_600, "Invalid Request Got: #{inspect(other)}"),
         session_id}
    end
  end

  # tools always enabled
  defp capabilities([]), do: %{"tools" => %{"listChanged" => false}}

  # at least 1 mcp_resource (mcp_action_resource or mcp_ui_resource) adds resources capability
  defp capabilities([_ | _]),
    do:
      capabilities([])
      |> Map.put("resources", %{})

  defp mcp_resources(opts) do
    mcp_action_resources(opts) ++ mcp_ui_resources(opts)
  end

  defp mcp_action_resources(opts) do
    opts
    |> Keyword.take([
      :otp_app,
      :tools,
      :actor,
      :context,
      :tenant,
      :actions,
      :mcp_resources,
      :exclude_actions
    ])
    |> Keyword.update(
      :context,
      %{otp_app: opts[:otp_app]},
      &Map.put(&1, :otp_app, opts[:otp_app])
    )
    |> AshAi.exposed_mcp_action_resources()
  end

  defp mcp_ui_resources(opts) do
    opts
    |> Keyword.take([
      :otp_app,
      :actor,
      :context,
      :tenant,
      :actions,
      :mcp_resources
    ])
    |> Keyword.update(
      :context,
      %{otp_app: opts[:otp_app]},
      &Map.put(&1, :otp_app, opts[:otp_app])
    )
    |> AshAi.exposed_mcp_ui_resources()
  end

  # Deterministic ordering per 2026-07-28 (enables client caching and
  # improves upstream LLM prompt-cache hit rates); harmless for older revisions.
  defp tool_definitions(opts) do
    opts
    |> Keyword.take([:otp_app, :tools, :actor, :context, :tenant, :actions])
    |> Keyword.update(
      :context,
      %{otp_app: opts[:otp_app]},
      &Map.put(&1, :otp_app, opts[:otp_app])
    )
    |> tools()
    |> Enum.map(fn %Tool{} = tool ->
      # MCP schemas are advisory (no grammar-constrained sampling), so the
      # OpenAI strict transformation defaults off here.
      {req_tool, _callback} =
        AshAi.Tools.build(tool, strict: Keyword.get(opts, :strict, false))

      result = %{
        "name" => req_tool.name,
        "description" => req_tool.description,
        "inputSchema" => req_tool.parameter_schema
      }

      if Tool.has_meta?(tool) do
        Map.put(result, "_meta", tool._meta)
      else
        result
      end
    end)
    |> Enum.sort_by(& &1["name"])
  end

  defp resource_definitions(opts) do
    action_resources =
      opts
      |> mcp_action_resources()
      |> Enum.map(&action_resource_to_map/1)

    ui_resources =
      opts
      |> mcp_ui_resources()
      |> Enum.map(&ui_resource_to_map(&1, opts))

    Enum.sort_by(action_resources ++ ui_resources, & &1["uri"])
  end

  defp execute_tool_call(params, session_id, opts) do
    tool_name = params["name"]
    tool_args = params["arguments"] || %{}

    case find_tool_by_name(tool_name, session_id, opts) do
      %Tool{} = tool ->
        context = tool_context(opts)

        case transform_tool_arguments(tool, tool_args, context, opts) do
          {:ok, transformed_args} ->
            execute_resolved_tool(tool, transformed_args, context)

          {:error, error_text} ->
            {:ok, tool_error_result(error_text)}
        end

      nil ->
        {:error, :tool_not_found}
    end
  end

  defp transform_tool_arguments(tool, arguments, context, opts) do
    case opts[:tool_argument_transformer] do
      nil ->
        {:ok, arguments}

      transformer when is_function(transformer, 3) ->
        case transformer.(tool, arguments, context) do
          {:ok, transformed_args} when is_map(transformed_args) ->
            {:ok, transformed_args}

          {:error, error_text} when is_binary(error_text) ->
            {:error, error_text}

          other ->
            raise ArgumentError,
                  "tool_argument_transformer must return {:ok, map} or {:error, string}, got: #{inspect(other)}"
        end

      other ->
        raise ArgumentError,
              "tool_argument_transformer must be a three-arity function, got: #{inspect(other)}"
    end
  end

  defp execute_resolved_tool(tool, arguments, context) do
    case AshAi.Tools.execute(tool, arguments, context) do
      {:ok, result, _} ->
        result = %{
          "isError" => false,
          "content" => [%{"type" => "text", "text" => result}]
        }

        if Tool.has_meta?(tool) do
          {:ok, Map.put(result, "_meta", tool._meta)}
        else
          {:ok, result}
        end

      {:error, error_text} ->
        {:ok, tool_error_result(error_text)}
    end
  end

  defp tool_error_result(error_text) do
    %{
      "isError" => true,
      "content" => [%{"type" => "text", "text" => error_text}]
    }
  end

  defp read_resource_content(uri, params, session_id, opts) do
    opts =
      opts
      |> Keyword.update(
        :context,
        %{mcp_session_id: session_id},
        &Map.put(&1, :mcp_session_id, session_id)
      )

    with {:ok, resource} <- find_mcp_resource_by_uri(uri, opts),
         {:ok, text} <- read_mcp_resource(resource, params, opts) do
      mime_type =
        case resource do
          %AshAi.McpUiResource{} -> AshAi.McpUiResource.mime_type()
          %AshAi.McpResource{mime_type: mt} -> mt
        end

      content =
        %{"uri" => uri, "mimeType" => mime_type, "text" => text}
        |> then(fn content ->
          case resource do
            %AshAi.McpUiResource{} = mcp_ui_resource ->
              ui_meta = build_ui_meta(mcp_ui_resource, opts)
              put_if(content, "_meta", if(ui_meta != %{}, do: %{"ui" => ui_meta}))

            _ ->
              content
          end
        end)

      {:ok, content}
    end
  end

  defp find_mcp_resource_by_uri(uri, opts) do
    case Enum.find(mcp_resources(opts), &(&1.uri == uri)) do
      nil -> {:error, :not_found}
      resource -> {:ok, resource}
    end
  end

  # sobelow_skip ["Traversal.FileModule"]
  # `html_path` is a developer-configured DSL value, not user-supplied input.
  defp read_mcp_resource(%AshAi.McpUiResource{html_path: path}, _params, _opts) do
    case File.read(path) do
      {:ok, _contents} = ok -> ok
      {:error, reason} -> {:error, "Failed to read file: #{inspect(reason)}"}
    end
  end

  defp read_mcp_resource(
         %AshAi.McpResource{
           domain: _domain,
           resource: resource,
           action: action
         },
         params,
         opts
       ) do
    params = take_valid_params(params, action)

    ash_opts =
      Keyword.take(opts, [
        :domain,
        :context,
        :authorize?,
        :tenant,
        :scope,
        :actor,
        :skip_unknown_inputs,
        :tracer,
        :private_arguments
      ])

    resource
    |> Ash.ActionInput.for_action(action.name, params, ash_opts)
    |> Ash.run_action()
    |> case do
      {:error, error} ->
        {:error, AshAi.Tool.Errors.format(error)}

      result ->
        result
    end
  end

  defp action_resource_to_map(%AshAi.McpResource{} = resource) do
    %{
      "name" => Atom.to_string(resource.name),
      "description" => resource.description,
      "uri" => resource.uri,
      "title" => resource.title,
      "mimeType" => resource.mime_type
    }
  end

  defp ui_resource_to_map(%AshAi.McpUiResource{} = resource, opts) do
    ui_meta = build_ui_meta(resource, opts)

    %{
      "name" => Atom.to_string(resource.name),
      "uri" => resource.uri,
      "title" => resource.title || Atom.to_string(resource.name),
      "mimeType" => AshAi.McpUiResource.mime_type()
    }
    |> put_if("description", resource.description)
    |> put_if("_meta", if(ui_meta != %{}, do: %{"ui" => ui_meta}))
  end

  defp build_ui_meta(%AshAi.McpUiResource{} = resource, opts) do
    permissions =
      case resource.permissions do
        [_ | _] ->
          Map.new(resource.permissions, fn {key, _value} -> {snake_to_camel(key), %{}} end)

        _ ->
          nil
      end

    csp =
      case resource.csp do
        list when is_list(list) -> keyword_to_camel_case_map(list)
        _ -> %{}
      end

    domain = resolve_domain(resource.domain, opts)

    %{"csp" => csp}
    |> put_if("permissions", permissions)
    |> put_if("domain", domain)
    |> put_if("prefersBorder", resource.prefers_border)
  end

  @doc """
  Computes the sandbox domain for an `mcp_ui_resource` from the MCP server URL.

  MCP hosts render UI resources in sandboxed iframes, and each host determines the
  iframe's origin differently:

  | Host    | Domain format                                    | Behavior                                              |
  |---------|--------------------------------------------------|-------------------------------------------------------|
  | Claude  | `{sha256_hash}.claudemcpcontent.com`             | Hash derived from the MCP server endpoint URL.        |
  | ChatGPT | `{connector_id}.web-sandbox.oaiusercontent.com`  | Auto-assigned by ChatGPT; ignores the `domain` field. |

  Since ChatGPT ignores `domain` entirely, this function generates a Claude-compatible
  value so that a single configuration works across both hosts.

  When `domain` is set to `:auto` (the default), this is called automatically at
  request time using the server URL derived from the incoming connection.

  ## Examples

      iex> AshAi.Mcp.Server.sandbox_domain("http://localhost:4000/mcp")
      "0307c5dc3988887979d60ecbb5101189.claudemcpcontent.com"

  """
  def sandbox_domain(server_url) when is_binary(server_url) do
    claude_domain(server_url)
  end

  defp resolve_domain(:auto, opts) do
    case opts[:server_url] do
      nil -> nil
      server_url -> sandbox_domain(server_url)
    end
  end

  defp resolve_domain(domain, _opts), do: domain

  @doc false
  def claude_domain(server_url) when is_binary(server_url) do
    :crypto.hash(:sha256, server_url)
    |> Base.encode16(case: :lower)
    |> binary_part(0, 32)
    |> Kernel.<>(".claudemcpcontent.com")
  end

  defp server_url(conn) do
    host = Plug.Conn.get_req_header(conn, "host") |> List.first()

    scheme =
      case Plug.Conn.get_req_header(conn, "x-forwarded-proto") do
        [proto | _] -> proto
        [] -> to_string(conn.scheme)
      end

    "#{scheme}://#{host}#{conn.request_path}"
  end

  defp put_if(map, _key, nil), do: map
  defp put_if(map, key, value), do: Map.put(map, key, value)

  # Converts a keyword list to a map with camelCase string keys.
  # e.g. [connect_domains: ["a.com"]] -> %{"connectDomains" => ["a.com"]}
  defp keyword_to_camel_case_map(keyword) do
    Map.new(keyword, fn {key, value} -> {snake_to_camel(key), value} end)
  end

  # Converts a snake_case atom to a camelCase string.
  # e.g. :clipboard_write -> "clipboardWrite"
  defp snake_to_camel(atom) do
    [first | rest] =
      atom
      |> Atom.to_string()
      |> String.split("_")

    Enum.join([first | Enum.map(rest, &String.capitalize/1)])
  end

  defp find_tool_by_name(tool_name, session_id, opts) do
    opts
    |> Keyword.take([:otp_app, :tools, :actor, :context, :tenant, :actions])
    |> Keyword.update(
      :context,
      %{mcp_session_id: session_id},
      &Map.put(&1, :mcp_session_id, session_id)
    )
    |> Keyword.update(
      :context,
      %{otp_app: opts[:otp_app]},
      &Map.put(&1, :otp_app, opts[:otp_app])
    )
    |> tools()
    |> Enum.find(&(to_string(&1.name) == tool_name))
  end

  defp tool_context(opts) do
    opts
    |> Keyword.take([:actor, :tenant, :context])
    |> Map.new()
    |> Map.update(
      :context,
      %{otp_app: opts[:otp_app]},
      &Map.put(&1, :otp_app, opts[:otp_app])
    )
  end

  defp take_valid_params(params, action) do
    argument_names = Enum.map(action.arguments, &to_string(&1.name))
    Map.take(params, argument_names)
  end

  defp tools(opts) do
    opts =
      if opts[:tools] == :ash_dev_tools do
        opts
        |> Keyword.put(:actions, [{AshAi.DevTools.Tools, :*}])
        |> Keyword.put(:tools, [
          :list_ash_resources,
          :list_generators,
          :get_usage_rules,
          :list_packages_with_rules
        ])
      else
        opts
      end

    opts
    |> Keyword.take([:otp_app, :tools, :actor, :context, :tenant, :actions])
    |> Keyword.update(
      :context,
      %{otp_app: opts[:otp_app]},
      &Map.put(&1, :otp_app, opts[:otp_app])
    )
    |> AshAi.exposed_tools()
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
