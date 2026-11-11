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
  * the initialize-based revisions (`2025-11-25`, `2025-06-18`, and
    `2025-03-26`), which negotiate via `initialize` and may use the
    `Mcp-Session-Id` header.

  The revision is selected per request: an `initialize` request (or a
  request carrying an initialize-based/absent `MCP-Protocol-Version` header
  and no per-request version `_meta`) is served with initialize-based
  semantics; a request declaring its protocol version in `_meta` (or in the
  `MCP-Protocol-Version` header) is served statelessly per the `2026-07-28`
  revision.
  """

  alias AshAi.Tool

  # Sent for a body that is not a JSON-RPC request object. The body itself is
  # not echoed: a non-object body arrives wrapped by Plug.Parsers as
  # `%{"_json" => value}`, so inspecting it describes something the client did
  # not send, and an object is echoed with up to 50 of its own keys and values.
  @invalid_request_message "Invalid Request: expected a JSON-RPC request object with a \"method\""

  # Protocol revisions that declare their version on every request
  @per_request_versions ["2026-07-28"]
  # Protocol revisions that negotiate their version via `initialize`, newest
  # first: `initialize` falls back to the head
  @initialize_based_versions ["2025-11-25", "2025-06-18", "2025-03-26"]

  @list_methods ["tools/list", "resources/list", "resources/templates/list"]
  @supported_protocol_versions @per_request_versions ++ @initialize_based_versions

  @meta_protocol_version "io.modelcontextprotocol/protocolVersion"
  @meta_client_info "io.modelcontextprotocol/clientInfo"
  @meta_client_capabilities "io.modelcontextprotocol/clientCapabilities"
  @meta_server_info "io.modelcontextprotocol/serverInfo"
  @meta_subscription_id "io.modelcontextprotocol/subscriptionId"
  @ui_extension "io.modelcontextprotocol/ui"
  @ui_mime_type "text/html;profile=mcp-app"

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
    header_version = req_header(conn, "mcp-protocol-version")
    rules = header_rules(header_version, opts)

    cond do
      is_list(body) and not rules.batching? ->
        send_error_without_id(
          conn,
          400,
          -32_600,
          "JSON-RPC batch requests are not supported for protocol version #{header_version}"
        )

      per_request_version?(body, rules.era) ->
        handle_post_2026_07_28(conn, body, opts)

      # `initialize` precedes negotiation, so the server skips its header
      rules.era == :unsupported and not match?(%{"method" => "initialize"}, body) ->
        payload =
          error_payload(-32_022, "Unsupported protocol version: #{header_version}", %{
            "supported" => @supported_protocol_versions,
            "requested" => header_version
          })

        send_json(conn, 400, put_error_id(payload, body, rules.omits_unknown_id?))

      true ->
        opts = Keyword.put(opts, :omits_unknown_id?, rules.omits_unknown_id?)
        handle_initialize_based_post(conn, body, session_id, opts)
    end
  end

  # The transport rules an `MCP-Protocol-Version` header value selects. A
  # request without the header counts as 2025-03-26. Revision dates are
  # ISO-8601, so string comparison orders them.
  #
  # * `era`: a value that sorts from 2026-07-28 on selects per-request
  #   semantics. An earlier value selects initialize-based semantics if the
  #   server supports it, and `:unsupported` otherwise. Both answer an
  #   unsupported version with HTTP 400 and 2026-07-28's
  #   UnsupportedProtocolVersionError, which satisfies the earlier revisions
  #   too, since they define no error body. A configured
  #   `:protocol_version_statement` counts as supported, because
  #   `initialize` states it and the client sends it back. A value that is not
  #   a revision date at all is `:unsupported`, since it would otherwise sort
  #   above every dated revision.
  # * `batching?`: 2025-06-18 removed JSON-RPC batching.
  # * `omits_unknown_id?`: from 2025-11-25 on, the schema types an error's
  #   id as an optional string or number, so the server leaves an unknown id
  #   out. Earlier revisions follow JSON-RPC 2.0 and send `null`.
  defp header_rules(header_version, opts) do
    version = header_version || "2025-03-26"

    era =
      cond do
        not String.match?(version, ~r/\A\d{4}-\d{2}-\d{2}\z/) -> :unsupported
        version >= hd(@per_request_versions) -> :per_request
        version in [opts[:protocol_version_statement] | @initialize_based_versions] -> :initialize
        true -> :unsupported
      end

    %{era: era, batching?: version < "2025-06-18", omits_unknown_id?: version >= "2025-11-25"}
  end

  # An error for a request echoes its id. The transports give the error for
  # a rejected notification no id, and an unreadable id follows the revision's
  # rule for an unknown id.
  defp put_error_id(payload, %{"id" => _} = message, omits_unknown_id?) do
    case request_id(message) do
      nil -> put_unknown_id(payload, omits_unknown_id?)
      id -> Map.put(payload, "id", id)
    end
  end

  defp put_error_id(payload, %{"method" => _}, _omits_unknown_id?), do: payload

  defp put_error_id(payload, _body, omits_unknown_id?),
    do: put_unknown_id(payload, omits_unknown_id?)

  defp put_unknown_id(payload, true), do: payload
  defp put_unknown_id(payload, false), do: Map.put(payload, "id", nil)

  defp handle_initialize_based_post(conn, body, session_id, opts) do
    case process_request(body, session_id, opts) do
      {:initialize_response, response, new_session_id} ->
        # Return the initialize response with a session ID header
        conn
        |> Plug.Conn.put_resp_header("mcp-session-id", new_session_id)
        |> send_encoded_json(200, response)

      {:json_response, response, _session_id} ->
        # The initialize-based transports answer a POST without requests with
        # 202 or an HTTP error status, so an error for input the server
        # cannot accept goes out with 400
        status = if without_requests?(body), do: 400, else: 200
        send_encoded_json(conn, status, response)

      {:batch_response, response, _session_id} ->
        send_encoded_json(conn, 200, response)

      {:no_response, _, _} ->
        # For notifications or other messages that don't require a response
        conn
        |> Plug.Conn.send_resp(202, "")
    end
  end

  # Notifications and client responses expect no answer
  defp without_requests?([]), do: false
  defp without_requests?(batch) when is_list(batch), do: Enum.all?(batch, &unanswered?/1)
  defp without_requests?(message), do: unanswered?(message)

  defp unanswered?(message), do: notification?(message) or response?(message)

  defp notification?(message),
    do: is_map(message) and is_map_key(message, "method") and not is_map_key(message, "id")

  defp response?(message) do
    is_map(message) and not is_map_key(message, "method") and
      (is_map_key(message, "result") or is_map_key(message, "error"))
  end

  # Plug.Parsers wraps JSON array bodies (2025-03-26 batch requests) in a "_json" key
  defp unwrap_json_params(%{"_json" => list}) when is_list(list), do: list
  defp unwrap_json_params(body), do: body

  # Era selection per the 2026-07-28 versioning spec: `initialize` without
  # per-request `_meta` selects initialize-based semantics; with a `_meta`
  # protocol version it is a removed method under 2026-07-28 (404 below).
  # Otherwise a `_meta` protocol version or a per-request header era selects
  # per-request semantics.
  defp per_request_version?(%{"method" => "initialize"} = body, _header_era),
    do: is_binary(request_meta_version(body))

  defp per_request_version?(body, header_era) when is_map(body),
    do: is_binary(request_meta_version(body)) or header_era == :per_request

  defp per_request_version?(_body, _header_era), do: false

  defp request_meta_version(%{"params" => %{"_meta" => %{@meta_protocol_version => version}}}),
    do: version

  defp request_meta_version(_body), do: nil

  defp handle_post_2026_07_28(conn, %{"method" => _method} = message, opts) do
    case invalid_envelope(message) do
      nil ->
        handle_message_2026_07_28(conn, message, opts)

      error ->
        error_response_2026_07_28(conn, 400, request_id(message), -32_600, error)
    end
  end

  defp handle_post_2026_07_28(conn, _other, _opts) do
    error_response_2026_07_28(conn, 400, nil, -32_600, @invalid_request_message)
  end

  defp handle_message_2026_07_28(conn, %{"method" => method, "id" => id} = message, opts) do
    cond do
      # Structurally invalid `_meta` is Invalid Params, before any version or
      # header comparison (SEP-2575)
      error = validate_request_meta(message) ->
        error_response_2026_07_28(conn, 400, id, -32_602, error)

      # Header/body consistency comes before version support and params: the
      # transport requires HeaderMismatch for any header validation failure,
      # even when one of the two names an unsupported version or the params
      # are invalid too
      error = validate_headers_2026_07_28(conn, message) ->
        error_response_2026_07_28(conn, 400, id, -32_020, error)

      (requested = request_meta_version(message)) not in @per_request_versions ->
        error_response_2026_07_28(conn, 400, id, -32_022, "Unsupported protocol version", %{
          "supported" => @supported_protocol_versions,
          "requested" => requested
        })

      # initialize is a removed method here; dispatch answers it with Method
      # not found naming the supported versions, whatever its params.
      error = method != "initialize" && invalid_params(method, message["params"]) ->
        error_response_2026_07_28(conn, 400, id, -32_602, error)

      true ->
        dispatch_2026_07_28(conn, method, id, message["params"] || %{}, opts)
    end
  end

  # Notifications: the core 2026-07-28 protocol defines no client-to-server
  # notifications over Streamable HTTP, and defines no header requirements
  # for notification POSTs. Accept and ignore.
  defp handle_message_2026_07_28(conn, _notification, _opts) do
    Plug.Conn.send_resp(conn, 202, "")
  end

  defp invalid_envelope(message) do
    cond do
      message["jsonrpc"] != "2.0" ->
        ~s(Invalid Request: "jsonrpc" must be "2.0")

      not is_binary(message["method"]) ->
        ~s(Invalid Request: "method" must be a string)

      is_map_key(message, "id") and is_nil(request_id(message)) ->
        ~s(Invalid Request: "id" must be a string or number)

      true ->
        nil
    end
  end

  # The spec prose asks for "a string or integer ID", but every revision's
  # schema.ts, which the spec names its source of truth, types `RequestId` as
  # `string | number`, and JSON-RPC 2.0 only discourages fractional ids
  # (SHOULD NOT). The server follows the schema and accepts fractional ids;
  # `null` stays rejected because the prose forbids it explicitly.
  defp request_id(%{"id" => id}) when is_binary(id) or is_number(id), do: id
  defp request_id(_message), do: nil

  # Every request must carry `_meta` with the protocol version and client
  # capabilities. `clientInfo` is a SHOULD and MUST NOT be required.
  defp validate_request_meta(message) do
    meta =
      case message["params"] do
        %{} = params -> params["_meta"]
        _not_an_object -> nil
      end

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

          {:error, reason} ->
            "Mcp-Name header value #{reason}"
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
      _ -> {:error, "is not valid Base64 sentinel encoding"}
    end
  end

  defp decode_header_value(value) do
    if plain_header_value?(value),
      do: {:ok, value},
      else: {:error, "contains characters that require Base64 sentinel encoding"}
  end

  # RFC 9110 field values: visible ASCII, space, and horizontal tab
  defp plain_header_value?(value), do: String.match?(value, ~r/\A[\x20-\x7E\t]*\z/)

  defp dispatch_2026_07_28(conn, "server/discover", id, params, opts) do
    result =
      %{
        "supportedVersions" => @supported_protocol_versions,
        "capabilities" => capabilities(opts, client_capabilities_2026_07_28(params))
      }
      |> maybe_put("instructions", get_instructions(opts))
      |> cacheable_result(opts, :list)
      |> result_2026_07_28(opts)

    response_2026_07_28(conn, 200, id, result)
  end

  defp dispatch_2026_07_28(conn, "tools/list", id, params, opts) do
    result =
      params
      |> tools_list_result(opts)
      |> cacheable_result(opts, :list)
      |> result_2026_07_28(opts)

    response_2026_07_28(conn, 200, id, result)
  end

  defp dispatch_2026_07_28(conn, "tools/call", id, params, opts) do
    case execute_tool_call(params, nil, opts,
           structured_lists?: true,
           client_capabilities: client_capabilities_2026_07_28(params)
         ) do
      {:ok, result} ->
        response_2026_07_28(conn, 200, id, result_2026_07_28(result, opts))

      {:error, :tool_not_found} ->
        error_response_2026_07_28(conn, 200, id, -32_602, "Tool not found: #{params["name"]}")
    end
  end

  defp dispatch_2026_07_28(conn, "resources/list", id, params, opts) do
    result =
      params
      |> resources_list_result(opts)
      |> cacheable_result(opts, :list)
      |> result_2026_07_28(opts)

    response_2026_07_28(conn, 200, id, result)
  end

  defp dispatch_2026_07_28(conn, "resources/templates/list", id, params, opts) do
    result =
      params
      |> resource_templates_list_result(opts)
      |> cacheable_result(opts, :list)
      |> result_2026_07_28(opts)

    response_2026_07_28(conn, 200, id, result)
  end

  defp dispatch_2026_07_28(conn, "resources/read", id, %{"uri" => uri} = params, opts) do
    case read_resource_content(uri, params, nil, opts) do
      {:ok, contents} ->
        result =
          %{"contents" => contents}
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
    server_info = get_server_info(opts)

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
    send_json(conn, status, put_if(error_payload(code, message, data), "id", id))
  end

  # A JSON-RPC error response without an id; callers add the id their
  # revision and message call for
  defp error_payload(code, message, data \\ nil) do
    error = maybe_put(%{"code" => code, "message" => message}, "data", data)
    %{"jsonrpc" => "2.0", "error" => error}
  end

  defp send_json(conn, status, payload),
    do: send_encoded_json(conn, status, Jason.encode!(payload))

  # sobelow_skip ["XSS.SendResp"]
  defp send_encoded_json(conn, status, json) do
    conn
    |> Plug.Conn.put_resp_header("content-type", "application/json")
    |> Plug.Conn.send_resp(status, json)
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

  # Send a JSON-RPC error for a request whose `id` the server cannot read, such
  # as a body that is not valid JSON or one from a forbidden origin. From
  # 2025-11-25 on, the response omits the `id`; earlier revisions follow
  # JSON-RPC 2.0 and send `null`. Public only for `AshAi.Mcp.Router`.
  @doc false
  def send_error_without_id(conn, status, code, message) do
    rules = header_rules(req_header(conn, "mcp-protocol-version"), [])
    send_json(conn, status, put_unknown_id(error_payload(code, message), rules.omits_unknown_id?))
  end

  @doc """
  Validate the `Origin` header of a request per the Streamable HTTP
  transport's DNS-rebinding protection requirement.

  Returns `:ok` when the request carries no `Origin` header (non-browser
  clients), when the origin's host is a localhost value, or when it is
  explicitly allowed by the `:allowed_origins` option (a list of origin
  strings, or a 1-arity predicate function). Deployments serving a browser
  client from a non-localhost origin must set `:allowed_origins`; the request
  `Host` and `X-Forwarded-Proto` headers are attacker-controlled and are not
  used to authorize an origin. Returns `:forbidden` otherwise — respond with
  HTTP 403.
  """
  def check_origin(conn, opts) do
    case Plug.Conn.get_req_header(conn, "origin") do
      [] ->
        :ok

      [origin] ->
        if origin_allowed?(trim_ows(origin), opts[:allowed_origins]) do
          :ok
        else
          :forbidden
        end

      [_origin | _duplicates] ->
        :forbidden
    end
  end

  defp origin_allowed?(origin, nil) do
    # Without an explicit :allowed_origins allowlist, only same-machine
    # (localhost) origins are trusted. The request Host and X-Forwarded-Proto
    # headers are both attacker-controlled - and equal to the origin under DNS
    # rebinding - so they cannot be used to authorize a non-localhost origin.
    # Deployments that serve a browser client from another origin must configure
    # :allowed_origins.
    localhost_host?(URI.parse(origin).host)
  end

  defp origin_allowed?(origin, allowed) when is_list(allowed), do: origin in allowed

  defp origin_allowed?(origin, allowed) when is_function(allowed, 1),
    do: allowed.(origin)

  defp localhost_host?(host), do: host in ["localhost", "127.0.0.1", "::1", "[::1]"]

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
    |> Plug.Conn.put_resp_header("allow", "POST")
    |> Plug.Conn.send_resp(405, "")
  end

  @doc """
  Process an HTTP DELETE request.

  Responds `405 Method Not Allowed` for every protocol version. 2026-07-28
  removed sessions, and the initialize-based revisions let a server refuse
  client-initiated session termination this way. The server keeps no session
  state, so a terminated session would keep answering requests, while those
  revisions require `404` for every request after termination.
  """
  def handle_delete(conn, _session_id) do
    conn
    |> Plug.Conn.put_resp_header("allow", "POST")
    |> Plug.Conn.send_resp(405, "")
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
  The `serverInfo` sent on `initialize` and in the `_meta` of 2026-07-28
  results: `name` and `version`, plus `icons` when the `mcp_icons` option is
  set. `mcp_icons` is a list of icon maps (`src`, and optionally `mimeType`,
  `sizes` such as `["48x48"]` or `["any"]`, and `theme`, `"light"` or
  `"dark"`), or a 1-arity function of the request opts that returns one.
  Hosts that read them show the icon beside the server's name.
  """
  def get_server_info(opts) do
    icons =
      case opts[:mcp_icons] do
        fun when is_function(fun, 1) -> fun.(opts)
        icons -> icons
      end

    %{"name" => get_server_name(opts), "version" => get_server_version(opts)}
    |> maybe_put("icons", if(icons == [], do: nil, else: icons))
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
    cond do
      opts[:mcp_name] -> opts[:mcp_name]
      opts[:otp_app] -> "#{opts[:otp_app]} MCP Server"
      true -> "MCP Server"
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

      {:ok, []} ->
        # JSON-RPC 2.0: an empty batch array is an Invalid Request
        response =
          unknown_id_error_response(opts, -32_600, "Invalid Request: a batch must not be empty")

        {:json_response, response, session_id}

      {:ok, batch} when is_list(batch) ->
        # Handle batch requests. In a batch with requests, the errors go into
        # the batch body, where JSON-RPC 2.0 requires every error to carry an
        # id, so a rejected notification's error gets the unknown id too.
        item_opts =
          if without_requests?(batch),
            do: opts,
            else: Keyword.put(opts, :batched_with_requests?, true)

        # Pair each item with its result and drop the ones needing no response
        answered =
          batch
          |> Enum.map(fn item -> {item, process_message(item, session_id, item_opts)} end)
          |> Enum.reject(&match?({_item, {:no_response, _, _}}, &1))

        cond do
          Enum.empty?(answered) ->
            # All items were notifications, no response needed
            {:no_response, nil, session_id}

          without_requests?(batch) ->
            # A batch without requests gets 202 or an HTTP error status, never
            # a batch body; handle_initialize_based_post picks the status
            answered |> hd() |> elem(1)

          true ->
            # Convert each response to its JSON representation
            json_responses = Enum.map(answered, fn {_item, {_, json, _}} -> json end)
            {:batch_response, "[#{Enum.join(json_responses, ",")}]", session_id}
        end

      {:error, error} ->
        # Handle parsing errors
        response =
          unknown_id_error_response(opts, -32_700, "Parse error", %{"details" => inspect(error)})

        {:json_response, response, session_id}
    end
  end

  @doc """
  Process a single JSON-RPC message
  """
  def process_message(%{"method" => _method} = message, session_id, opts) do
    case invalid_message(message) do
      nil ->
        do_process_message(message, session_id, opts)

      {code, error} ->
        payload = error_payload(code, error)
        omits_unknown_id? = Keyword.get(opts, :omits_unknown_id?, false)

        response =
          if opts[:batched_with_requests?] && notification?(message),
            do: put_unknown_id(payload, omits_unknown_id?),
            else: put_error_id(payload, message, omits_unknown_id?)

        {:json_response, Jason.encode!(response), session_id}
    end
  end

  def process_message(message, session_id, opts) do
    do_process_message(message, session_id, opts)
  end

  # An error for a message whose id the server cannot read follows the
  # revision's rule for an unknown id
  defp unknown_id_error_response(opts, code, message, data \\ nil) do
    code
    |> error_payload(message, data)
    |> put_unknown_id(Keyword.get(opts, :omits_unknown_id?, false))
    |> Jason.encode!()
  end

  # `params` is optional in JSON-RPC; `invalid_params` rejects a missing
  # `params` for the methods that require it. The server checks only
  # requests, because the handlers read no notification params.
  defp invalid_message(message) do
    cond do
      error = invalid_envelope(message) ->
        {-32_600, error}

      error = is_map_key(message, "id") && invalid_params(message["method"], message["params"]) ->
        {-32_602, error}

      true ->
        nil
    end
  end

  # The shapes of the `params` members the handlers read with `Access`. Only
  # the methods that read `params` are checked, so a method that ignores them
  # keeps answering whatever a client sends there.
  defp invalid_params(method, params)
       when method in ["initialize", "tools/call", "resources/read"] and not is_map(params),
       do: "Invalid params: params must be an object"

  defp invalid_params("tools/call", params)
       when not is_map_key(params, "name") or not is_binary(:erlang.map_get("name", params)),
       do: "Invalid params: name must be a string"

  defp invalid_params("tools/call", %{"arguments" => arguments})
       when not is_map(arguments) and not is_nil(arguments),
       do: "Invalid params: arguments must be an object"

  defp invalid_params("resources/read", %{"uri" => uri}) when is_binary(uri), do: nil

  defp invalid_params("resources/read", _params), do: "Invalid params: uri must be a string"

  defp invalid_params("initialize", %{"capabilities" => capabilities})
       when not is_map(capabilities) and not is_nil(capabilities),
       do: "Invalid params: capabilities must be an object"

  # Checked whether or not paging is enabled, so a client never mistakes an
  # ignored cursor for the start of the list
  defp invalid_params(method, %{"cursor" => cursor})
       when method in @list_methods and not is_nil(cursor) do
    case decode_cursor(cursor) do
      {:ok, _after_key} -> nil
      :error -> "Invalid params: invalid cursor"
    end
  end

  defp invalid_params(_method, _params), do: nil

  defp do_process_message(message, session_id, opts) do
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
            hd(@initialize_based_versions)

        capabilities = capabilities(opts, params["capabilities"] || %{})

        result =
          %{
            "serverInfo" => get_server_info(opts),
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

      %{"method" => "shutdown", "id" => id} ->
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

      %{"method" => "resources/list", "id" => id} ->
        response = %{
          "jsonrpc" => "2.0",
          "id" => id,
          "result" => resources_list_result(message["params"], opts)
        }

        {:json_response, Jason.encode!(response), session_id}

      %{"method" => "resources/templates/list", "id" => id} ->
        response = %{
          "jsonrpc" => "2.0",
          "id" => id,
          "result" => resource_templates_list_result(message["params"], opts)
        }

        {:json_response, Jason.encode!(response), session_id}

      %{"method" => "resources/read", "id" => id, "params" => %{"uri" => uri} = params} ->
        case read_resource_content(uri, params, session_id, opts) do
          {:ok, contents} ->
            response = %{
              "jsonrpc" => "2.0",
              "id" => id,
              "result" => %{
                "contents" => contents
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
          "result" => tools_list_result(message["params"], opts)
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

      %{"method" => method, "id" => id} ->
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

      %{"jsonrpc" => "2.0", "id" => _id} = response
      when is_map_key(response, "result") or is_map_key(response, "error") ->
        # The server sends the client no requests, so a client response
        # answers nothing; the transports accept it with 202
        {:no_response, nil, session_id}

      _other ->
        # Invalid message
        {:json_response, unknown_id_error_response(opts, -32_600, @invalid_request_message),
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

  defp capabilities(opts, client_capabilities) do
    resources = mcp_resources(opts)

    resources
    |> capabilities()
    |> maybe_add_ui_capability(resources, client_capabilities)
  end

  defp maybe_add_ui_capability(capabilities, resources, client_capabilities) do
    if ui_capable?(client_capabilities) &&
         Enum.any?(resources, &match?(%AshAi.McpUiResource{}, &1)) do
      ui_capability = %{"mimeTypes" => [@ui_mime_type]}

      Map.update(
        capabilities,
        "extensions",
        %{@ui_extension => ui_capability},
        &Map.put(&1, @ui_extension, ui_capability)
      )
    else
      capabilities
    end
  end

  defp client_capabilities_2026_07_28(params) do
    get_in(params, ["_meta", @meta_client_capabilities]) || %{}
  end

  # Matched rather than read with `get_in/2`, which raises when a client sends
  # a scalar or a list anywhere along the path
  defp ui_capable?(%{"extensions" => %{@ui_extension => %{"mimeTypes" => mime_types}}})
       when is_list(mime_types),
       do: @ui_mime_type in mime_types

  defp ui_capable?(_client_capabilities), do: false

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

  # Tools are paged before their schemas are built, so a page only pays for its own entries
  defp tools_list_result(params, opts) do
    {tools, next_cursor} =
      opts
      |> listed_tools()
      |> page(&to_string(&1.name), params, opts)

    maybe_put(
      %{"tools" => Enum.map(tools, &tool_definition(&1, opts))},
      "nextCursor",
      next_cursor
    )
  end

  defp resources_list_result(params, opts) do
    {resources, next_cursor} = page(resource_definitions(opts), & &1["uri"], params, opts)
    maybe_put(%{"resources" => resources}, "nextCursor", next_cursor)
  end

  defp resource_templates_list_result(params, opts) do
    {templates, next_cursor} =
      opts
      |> mcp_action_resources()
      |> Enum.filter(& &1.uri_template)
      |> Enum.map(&resource_template_to_map/1)
      |> Enum.sort_by(& &1["uriTemplate"])
      |> page(& &1["uriTemplate"], params, opts)

    maybe_put(%{"resourceTemplates" => templates}, "nextCursor", next_cursor)
  end

  # Keyset pagination over the deterministic list order: a cursor carries the
  # key of the last entry served, so entries that appear or disappear between
  # requests don't shift later pages. Without `list_page_size` every entry
  # after the cursor is returned.
  defp page(entries, key_fun, params, opts) do
    entries =
      case params do
        %{"cursor" => cursor} when is_binary(cursor) ->
          {:ok, after_key} = decode_cursor(cursor)
          Enum.drop_while(entries, &(key_fun.(&1) <= after_key))

        _ ->
          entries
      end

    case Keyword.get(opts, :list_page_size) do
      nil ->
        {entries, nil}

      size when is_integer(size) and size > 0 ->
        case Enum.split(entries, size) do
          {page, []} -> {page, nil}
          {page, _rest} -> {page, page |> List.last() |> key_fun.() |> encode_cursor()}
        end

      other ->
        raise ArgumentError,
              "list_page_size must be a positive integer or nil, got: #{inspect(other)}"
    end
  end

  defp encode_cursor(after_key) do
    Base.url_encode64(Jason.encode!(%{"after" => after_key}), padding: false)
  end

  defp decode_cursor(cursor) when is_binary(cursor) do
    with {:ok, json} <- Base.url_decode64(cursor, padding: false),
         {:ok, %{"after" => after_key}} when is_binary(after_key) <- Jason.decode(json) do
      {:ok, after_key}
    else
      _ -> :error
    end
  end

  defp decode_cursor(_cursor), do: :error

  # Deterministic ordering per 2026-07-28 (enables client caching and
  # improves upstream LLM prompt-cache hit rates); harmless for older revisions.
  defp listed_tools(opts) do
    opts
    |> Keyword.take([:otp_app, :tools, :actor, :context, :tenant, :actions, :dev_tool_domains])
    |> Keyword.update(
      :context,
      %{otp_app: opts[:otp_app]},
      &Map.put(&1, :otp_app, opts[:otp_app])
    )
    |> tools()
    |> Enum.sort_by(&to_string(&1.name))
  end

  defp tool_definition(%Tool{} = tool, opts) do
    tool
    |> base_tool_definition(opts)
    |> transform_tool_definition(tool, opts)
  end

  defp transform_tool_definition(definition, tool, opts) do
    case opts[:tool_definition_transformer] do
      nil ->
        definition

      transformer when is_function(transformer, 3) ->
        case transformer.(tool, definition, tool_context(opts)) do
          %{} = transformed ->
            transformed

          other ->
            raise ArgumentError,
                  "tool_definition_transformer must return a map, got: #{inspect(other)}"
        end

      other ->
        raise ArgumentError,
              "tool_definition_transformer must be a three-arity function, got: #{inspect(other)}"
    end
  end

  defp base_tool_definition(%Tool{} = tool, opts) do
    # MCP schemas are advisory (no grammar-constrained sampling), so the
    # OpenAI strict transformation defaults off here.
    result =
      %{
        "name" => to_string(tool.name),
        "description" => AshAi.Tools.description(tool),
        "inputSchema" =>
          AshAi.Tools.parameter_schema(tool, strict: Keyword.get(opts, :strict, false))
      }
      |> maybe_put("title", tool.title)
      |> maybe_put("annotations", tool_annotations(tool))
      |> maybe_put("outputSchema", AshAi.Tool.OutputSchema.for_tool(tool))

    if Tool.has_meta?(tool) do
      Map.put(result, "_meta", tool._meta)
    else
      result
    end
  end

  @tool_annotations [
    :title,
    :read_only_hint,
    :destructive_hint,
    :idempotent_hint,
    :open_world_hint
  ]

  defp tool_annotations(%Tool{annotations: []}), do: nil

  defp tool_annotations(%Tool{annotations: [_ | _] = annotations}) do
    verify_annotations!(annotations)
    keyword_to_camel_case_map(annotations)
  end

  defp verify_annotations!(annotations) do
    with {:error, err} <- Keyword.validate(annotations, @tool_annotations) do
      raise ArgumentError, "unrecognized tool annotation(s): #{inspect(err)}"
    end
  end

  defp resource_definitions(opts) do
    action_resources =
      opts
      |> mcp_action_resources()
      |> Enum.reject(& &1.uri_template)
      |> Enum.map(&action_resource_to_map/1)

    ui_resources =
      opts
      |> mcp_ui_resources()
      |> Enum.map(&ui_resource_to_map(&1, opts))

    Enum.sort_by(action_resources ++ ui_resources, & &1["uri"])
  end

  # 2025-06-18 types `structuredContent` as an object; 2026-07-28 allows any
  # JSON value, so only that revision receives list results as structured content
  # Each call runs in a `[:ash_ai, :mcp, :tool_call]` telemetry span (see
  # `AshAi.Mcp.Router`), with the arguments as the client sent them, before
  # `tool_argument_transformer`.
  defp execute_tool_call(params, session_id, opts, call_opts \\ []) do
    tool_name = params["name"]
    tool_args = params["arguments"] || %{}
    tool = find_tool_by_name(tool_name, session_id, opts)
    context = tool_context(opts)

    metadata = %{
      tool_name: tool_name,
      tool: tool,
      arguments: tool_args,
      request_meta: params["_meta"],
      session_id: session_id,
      actor: context[:actor],
      tenant: context[:tenant],
      context: context[:context]
    }

    :telemetry.span([:ash_ai, :mcp, :tool_call], metadata, fn ->
      result = run_tool_call(tool, tool_args, context, opts, call_opts)
      {result, Map.merge(metadata, tool_call_outcome(result))}
    end)
  end

  defp run_tool_call(nil, _tool_args, _context, _opts, _call_opts), do: {:error, :tool_not_found}

  defp run_tool_call(%Tool{} = tool, tool_args, context, opts, call_opts) do
    case transform_tool_arguments(tool, tool_args, context, opts) do
      {:ok, transformed_args} ->
        execute_resolved_tool(tool, transformed_args, context, call_opts)

      {:error, error_text} ->
        {:ok, tool_error_result(error_text)}
    end
  end

  defp tool_call_outcome({:ok, result}),
    do: %{result: result, is_error: result["isError"] == true, error: nil}

  defp tool_call_outcome({:error, error}), do: %{result: nil, is_error: true, error: error}

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

  defp execute_resolved_tool(tool, arguments, context, call_opts) do
    case AshAi.Tools.execute(tool, arguments, context, encode?: false) do
      {:ok, result, raw_result} ->
        case encode_tool_result(tool, result) do
          {:ok, encoded_result} ->
            result_meta_context = %AshAi.Tool.ResultMeta.Context{
              tool: tool,
              arguments: arguments,
              actor: context[:actor],
              tenant: context[:tenant],
              context: context[:context],
              client_capabilities: call_opts[:client_capabilities]
            }

            result =
              %{
                "isError" => false,
                "content" => [%{"type" => "text", "text" => encoded_result}]
              }
              |> maybe_put_structured_content(
                result,
                encoded_result,
                Keyword.get(call_opts, :structured_lists?, false)
              )
              |> put_result_meta(tool, raw_result, result_meta_context)

            {:ok, result}

          {:error, error_text} ->
            {:ok, tool_error_result(error_text)}
        end

      {:error, error_text} ->
        {:ok, tool_error_result(error_text)}
    end
  end

  defp put_result_meta(result, tool, raw_result, context) do
    meta =
      deep_merge(
        if(Tool.has_meta?(tool), do: tool._meta, else: %{}),
        AshAi.Tool.ResultMeta.run(tool, raw_result, context)
      )

    if meta == %{}, do: result, else: Map.put(result, "_meta", meta)
  end

  defp deep_merge(left, right) do
    Map.merge(left, right, fn
      _key, %{} = left, %{} = right -> deep_merge(left, right)
      _key, _left, right -> right
    end)
  end

  defp encode_tool_result(%{action: %{type: :action, returns: nil}}, result), do: {:ok, result}

  # A string result is the text content itself. JSON-encoding it would hand the
  # client a quoted literal with every newline escaped.
  defp encode_tool_result(tool, result) do
    if text_result?(tool, result) do
      {:ok, to_string(result)}
    else
      {:ok, Jason.encode!(result)}
    end
  rescue
    error -> {:error, AshAi.Tool.Errors.format(error)}
  end

  defp text_result?(%{action: %{type: :action, returns: returns}}, result)
       when is_binary(result) or is_struct(result, Ash.CiString) do
    string_type?(returns) and String.valid?(to_string(result))
  end

  defp text_result?(_tool, _result), do: false

  defp string_type?(type) do
    type = Ash.Type.get_type(type)

    cond do
      type in [Ash.Type.String, Ash.Type.CiString] -> true
      Ash.Type.NewType.new_type?(type) -> string_type?(Ash.Type.NewType.subtype_of(type))
      true -> false
    end
  end

  # `is_map/1` also holds for structs such as DateTime, which Jason encodes as
  # a string, so the encoded text decides whether the result is an object or
  # an array. A CiString is sent as plain text, which may itself start with "{".
  defp maybe_put_structured_content(result, structured_content, "{" <> _, _lists?)
       when is_map(structured_content) and not is_struct(structured_content, Ash.CiString),
       do: Map.put(result, "structuredContent", structured_content)

  defp maybe_put_structured_content(result, structured_content, "[" <> _, true)
       when is_list(structured_content),
       do: Map.put(result, "structuredContent", structured_content)

  defp maybe_put_structured_content(result, _structured_content, _encoded, _lists?),
    do: result

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

    with {:ok, resource, variables} <- find_mcp_resource_by_uri(uri, opts) do
      read_mcp_resource(resource, uri, variables, params, opts)
    end
  end

  # A resource whose URI is exactly `uri` wins over a template matching it.
  # Templates are tried in declaration order.
  defp find_mcp_resource_by_uri(uri, opts) do
    resources = mcp_resources(opts)

    case Enum.find(resources, &(not templated?(&1) and &1.uri == uri)) do
      nil ->
        Enum.find_value(resources, {:error, :not_found}, fn
          %AshAi.McpResource{uri_template: %AshAi.Mcp.UriTemplate{} = template} = resource ->
            case AshAi.Mcp.UriTemplate.match(template, uri) do
              {:ok, variables} -> {:ok, resource, variables}
              :error -> nil
            end

          _resource ->
            nil
        end)

      resource ->
        {:ok, resource, %{}}
    end
  end

  defp templated?(%AshAi.McpResource{uri_template: %AshAi.Mcp.UriTemplate{}}), do: true
  defp templated?(_resource), do: false

  defp read_mcp_resource(%AshAi.McpUiResource{} = resource, uri, _variables, _params, opts) do
    with {:ok, html} <- read_mcp_ui_html(resource) do
      ui_meta = build_ui_meta(resource, opts)

      content =
        %{"uri" => uri, "mimeType" => AshAi.McpUiResource.mime_type(), "text" => html}
        |> put_if("_meta", if(ui_meta != %{}, do: %{"ui" => ui_meta}))

      {:ok, [content]}
    end
  end

  defp read_mcp_resource(
         %AshAi.McpResource{resource: resource, action: action} = mcp_resource,
         uri,
         variables,
         params,
         opts
       ) do
    # Template variables win over request params of the same name
    arguments = params |> take_valid_params(action) |> Map.merge(variables)

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
    |> Ash.ActionInput.for_action(action.name, arguments, ash_opts)
    |> Ash.run_action()
    |> case do
      {:ok, nil} ->
        {:error, :not_found}

      {:ok, result} ->
        AshAi.McpResource.Contents.run(mcp_resource, result, %AshAi.McpResource.Contents.Context{
          mcp_resource: mcp_resource,
          uri: uri,
          arguments: arguments,
          actor: opts[:actor],
          tenant: opts[:tenant],
          context: opts[:context]
        })

      {:error, error} ->
        if not_found_error?(error),
          do: {:error, :not_found},
          else: {:error, AshAi.Tool.Errors.format(error)}
    end
  end

  defp read_mcp_ui_html(%AshAi.McpUiResource{html: {module, function, args}}) do
    case apply(module, function, args) do
      html when is_binary(html) -> {:ok, html}
      {:error, message} when is_binary(message) -> {:error, message}
      _ -> {:error, "MCP UI HTML renderer must return a string or {:error, message}."}
    end
  end

  # sobelow_skip ["Traversal.FileModule"]
  # `html_path` is a developer-configured DSL value, not user-supplied input.
  defp read_mcp_ui_html(%AshAi.McpUiResource{html_path: path}) do
    case File.read(path) do
      {:ok, _contents} = ok -> ok
      {:error, reason} -> {:error, "Failed to read file: #{inspect(reason)}"}
    end
  end

  defp not_found_error?(error) do
    case Ash.Error.to_error_class(error) do
      %{errors: errors} -> Enum.any?(errors, &match?(%Ash.Error.Query.NotFound{}, &1))
      _error -> false
    end
  end

  defp action_resource_to_map(%AshAi.McpResource{} = resource) do
    %{
      "name" => Atom.to_string(resource.name),
      "uri" => resource.uri,
      "title" => resource.title
    }
    |> put_if("mimeType", resource.mime_type)
    |> put_if("description", resource.description)
  end

  defp resource_template_to_map(%AshAi.McpResource{} = resource) do
    %{
      "name" => Atom.to_string(resource.name),
      "uriTemplate" => resource.uri,
      "title" => resource.title
    }
    |> put_if("mimeType", resource.mime_type)
    |> put_if("description", resource.description)
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
    |> Keyword.take([:otp_app, :tools, :actor, :context, :tenant, :actions, :dev_tool_domains])
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
        dev_tools = AshAi.Mcp.Dev.dev_tools(opts[:dev_tool_domains] || [])

        opts
        |> Keyword.put(:actions, dev_tools |> Enum.map(&{&1.resource, :*}) |> Enum.uniq())
        |> Keyword.put(:tools, dev_tools |> Enum.map(& &1.name) |> Enum.uniq())
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

  # A batch body arrives as a list once `unwrap_json_params/1` has removed the
  # `_json` wrapper that Plug.Parsers puts around a JSON array
  def parse_json_rpc(request) when is_list(request) do
    {:ok, request}
  end

  @doc """
  Create a standard JSON-RPC error response
  """
  @deprecated "Always includes an id, which 2025-11-25 and later omit when the request id is unknown"
  def json_rpc_error_response(id, code, message, data \\ nil) do
    code
    |> error_payload(message, data)
    |> Map.put("id", id)
    |> Jason.encode!()
  end
end
