# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

if Code.ensure_loaded?(Req) do
  defmodule AshAi.Mcp.Client do
    @moduledoc """
    A client for MCP servers reached over the Streamable HTTP transport.

    The client keeps no process state. `connect/1` settles the protocol details
    for a `AshAi.Mcp.Client.Server` and returns an `AshAi.Mcp.Client.Connection`,
    a plain struct that the other functions take, so a job can build one, use it,
    and drop it.

        server =
          AshAi.Mcp.Client.server(
            name: "linear",
            url: "https://mcp.linear.app/mcp",
            auth: {AshAi.Mcp.OAuth, store: MyApp.McpTokens, owner: user.id}
          )

        {:ok, conn} = AshAi.Mcp.Client.connect(server)
        {:ok, definitions} = AshAi.Mcp.Client.list_tools(conn)
        tools = AshAi.Mcp.Client.req_llm_tools(conn, definitions)

        AshAi.ToolLoop.run(messages, extra_tools: tools, ...)

    ## Resources

    `list_resources/1`, `list_resource_templates/1`, and `read_resource/2` reach
    the server's resources, and `format_resource/1` turns a read into text or
    ReqLLM content parts, for example to attach a resource a person picked to
    their message. To let the model list and read them itself, pass
    `resources: true` to `req_llm_tools/3`.

    ## Protocol versions

    The client prefers revision `2026-07-28`, which carries the protocol version,
    client info, and capabilities on every request and needs no handshake. It
    falls back to the `initialize`-based revisions (`2025-11-25`, `2025-06-18`,
    `2025-03-26`) for servers that don't support it:

    1. `connect/1` sends `server/discover` as a `2026-07-28` request.
    2. A result means the server is modern. An `UnsupportedProtocolVersionError`
       also means it is modern; the client retries with a version from the
       error's `supported` list.
    3. Any other rejection (an HTTP 4xx, or a JSON-RPC error that only a legacy
       server would send) means the server is legacy. The client sends
       `initialize`, then `notifications/initialized`, and sends the
       negotiated `MCP-Protocol-Version` and any `Mcp-Session-Id` on every
       later request.

    Set the server's `protocol_version` to a previously negotiated
    `Connection.protocol_version` to skip the probe. For a `2026-07-28` server,
    `connect/1` then makes no request at all.

    ## Tool definitions and prompt caching

    `list_tools/1` fetches definitions, and `req_llm_tools/3` turns definitions
    into ReqLLM tools. They are separate so an app can store the definitions it
    fetched when a conversation starts and build the same tools from them on
    every turn: a server changing its tool list then can't change the tools
    array mid-conversation and invalidate the prompt cache.

    ## Not supported yet

    Server-to-client features (sampling, elicitation, roots) aren't
    implemented. A `2026-07-28` result asking for input
    (`resultType: "input_required"`) returns `{:error, {:input_required, result}}`.
    A legacy server's requests on a response stream are answered with
    JSON-RPC "method not found", except `ping`. `subscriptions/listen`,
    resource subscriptions (`resources/subscribe`), and the deprecated HTTP+SSE
    transport aren't supported.
    """

    require Logger

    alias AshAi.Mcp.Client.{Connection, Headers, Server, SSE}
    alias AshAi.Mcp.NetworkPolicy

    @modern_versions ["2026-07-28"]
    @legacy_versions ["2025-11-25", "2025-06-18", "2025-03-26"]
    @supported_versions @modern_versions ++ @legacy_versions

    @meta_protocol_version "io.modelcontextprotocol/protocolVersion"
    @meta_client_info "io.modelcontextprotocol/clientInfo"
    @meta_client_capabilities "io.modelcontextprotocol/clientCapabilities"
    @meta_server_info "io.modelcontextprotocol/serverInfo"

    # Errors that only a modern server sends (HeaderMismatch,
    # MissingRequiredClientCapability, UnsupportedProtocolVersion). One of them
    # on a rejected modern request means the server is modern, so the client
    # must not fall back to `initialize`.
    @modern_error_codes [-32_020, -32_021, -32_022]

    # Bounds list pagination against a server that never stops returning a
    # cursor
    @max_pages 100

    # Bounds the requests a legacy server can make the client answer while it
    # waits for one response
    @max_answered_requests 16

    # Notifications, answers to a legacy server's requests, and ending a
    # session get only a status back, so they get less time than a request.
    # A slow server answering inside a response stream holds that stream up.
    @message_timeout 10_000

    @type result :: %{
            content: [map()],
            structured_content: term(),
            meta: map() | nil,
            is_error: boolean()
          }

    @type resource_result :: %{contents: [map()], meta: map() | nil}

    @doc "The protocol versions this client supports, newest first."
    @spec supported_protocol_versions() :: [String.t()]
    def supported_protocol_versions, do: @supported_versions

    @doc """
    Builds a server configuration. See `AshAi.Mcp.Client.Server.new/1` for the options.
    """
    @spec server(keyword()) :: Server.t()
    def server(opts), do: Server.new(opts)

    @doc """
    Settles the protocol version to use with `server` and returns a connection.

    Accepts a `AshAi.Mcp.Client.Server` or the options for one.
    """
    @spec connect(Server.t() | keyword()) :: {:ok, Connection.t()} | {:error, term()}
    def connect(opts) when is_list(opts), do: connect(Server.new(opts))

    def connect(%Server{protocol_version: nil} = server),
      do: probe(server, hd(@modern_versions), [])

    def connect(%Server{protocol_version: version} = server) when version in @modern_versions,
      do: {:ok, modern_connection(server, version, nil)}

    def connect(%Server{protocol_version: version} = server) when version in @legacy_versions,
      do: initialize(server, version)

    def connect(%Server{protocol_version: version}),
      do: {:error, {:unsupported_protocol_version, version}}

    @doc """
    Lists the server's tools, following `nextCursor` pagination.

    Returns the tool definitions as the server sent them (string keys). Tools
    whose `inputSchema` carries an invalid `x-mcp-header` annotation are left
    out with a warning, as the transport requires.
    """
    @spec list_tools(Connection.t()) :: {:ok, [map()]} | {:error, term()}
    def list_tools(%Connection{} = conn) do
      with {:ok, tools} <- paginate(conn, "tools/list", "tools", nil, [], 0) do
        {:ok, Enum.filter(tools, &valid_tool?(conn, &1))}
      end
    end

    @doc """
    Calls a tool on the server.

    `name` is the server's own tool name, not the `mcp__...` name from
    `req_llm_tools/3`. Pass the tool's definition as `definition:` so the
    client can mirror `x-mcp-header` parameters into headers.

    Returns `{:ok, %{content: blocks, structured_content: value, meta: map, is_error: boolean}}`,
    where `meta` is the result's `_meta` (or `nil`).
    A tool that failed while running is still `{:ok, %{is_error: true}}`;
    `{:error, reason}` means the request itself failed.
    """
    @spec call_tool(Connection.t(), String.t(), map() | nil, keyword()) ::
            {:ok, result()} | {:error, term()}
    def call_tool(%Connection{} = conn, name, arguments, opts \\ []) do
      arguments = arguments || %{}

      param_headers =
        with %Connection{era: :modern} <- conn,
             %{} = definition <- opts[:definition],
             {:ok, params} <- Headers.params(definition["inputSchema"]) do
          Headers.param_headers(params, arguments)
        else
          _ -> []
        end

      params = %{"name" => name, "arguments" => arguments}

      with {:ok, result} <- request(conn, "tools/call", params, headers: param_headers) do
        {:ok,
         %{
           content: List.wrap(result["content"]),
           structured_content: result["structuredContent"],
           meta: result["_meta"],
           is_error: result["isError"] == true
         }}
      end
    end

    @doc """
    Lists the server's resources, following `nextCursor` pagination.

    Returns the resource entries as the server sent them (string keys), leaving
    out any without a string `uri`. Templated resources are listed separately,
    by `list_resource_templates/1`.
    """
    @spec list_resources(Connection.t()) :: {:ok, [map()]} | {:error, term()}
    def list_resources(%Connection{} = conn) do
      with {:ok, resources} <- paginate(conn, "resources/list", "resources", nil, [], 0) do
        {:ok, Enum.filter(resources, &is_binary(&1["uri"]))}
      end
    end

    @doc """
    Lists the server's resource templates, following `nextCursor` pagination.

    Returns the template entries as the server sent them (string keys), leaving
    out any without a string `uriTemplate`. Each `uriTemplate` is an RFC 6570
    URI template: expand it and pass the URI to `read_resource/2`.
    """
    @spec list_resource_templates(Connection.t()) :: {:ok, [map()]} | {:error, term()}
    def list_resource_templates(%Connection{} = conn) do
      with {:ok, templates} <-
             paginate(conn, "resources/templates/list", "resourceTemplates", nil, [], 0) do
        {:ok, Enum.filter(templates, &is_binary(&1["uriTemplate"]))}
      end
    end

    @doc """
    Reads a resource from the server.

    Returns `{:ok, %{contents: items, meta: map}}`, where each item is a map
    with a `"uri"`, an optional `"mimeType"`, and either `"text"` or a base64
    `"blob"`, as the server sent it, and `meta` is the result's `_meta` (or
    `nil`). A resource the server doesn't have is a JSON-RPC error: `-32602`
    from `2026-07-28` servers, `-32002` from earlier ones.

    `format_resource/1` turns the result into text or ReqLLM content parts.
    """
    @spec read_resource(Connection.t(), String.t()) ::
            {:ok, resource_result()} | {:error, term()}
    def read_resource(%Connection{} = conn, uri) when is_binary(uri) do
      with {:ok, result} <- request(conn, "resources/read", %{"uri" => uri}) do
        {:ok,
         %{
           contents: result["contents"] |> List.wrap() |> Enum.filter(&is_map/1),
           meta: result["_meta"]
         }}
      end
    end

    @doc """
    Sends a JSON-RPC request and returns its result.

    `params` uses string keys. For `2026-07-28` the client adds the required
    `_meta` fields. Pass extra HTTP headers as `headers:`.
    """
    @spec request(Connection.t(), String.t(), map(), keyword()) ::
            {:ok, map()} | {:error, term()}
    def request(%Connection{} = conn, method, params \\ %{}, opts \\ []) do
      with {:ok, result, _response} <- call(conn, method, params, opts) do
        case result do
          %{"resultType" => "input_required"} -> {:error, {:input_required, result}}
          %{"resultType" => type} when type != "complete" -> {:error, {:invalid_result, type}}
          result -> {:ok, result}
        end
      end
    end

    @doc """
    Ends a legacy session with `DELETE`, if the server assigned one.

    Servers may refuse to end sessions, so the result is ignored.
    """
    @spec close(Connection.t()) :: :ok
    def close(%Connection{era: :legacy, session_id: session_id} = conn)
        when is_binary(session_id) do
      with {:ok, headers} <- base_headers(conn) do
        Req.request(req(conn.server),
          method: :delete,
          headers: headers,
          into: capped_body(conn),
          request_timeout: @message_timeout
        )
      end

      :ok
    end

    def close(%Connection{}), do: :ok

    @doc """
    The ReqLLM tool name for an MCP server's tool: `mcp__<server>__<tool>`.

    Names are limited to the characters and length every LLM provider accepts.
    A name that has to be changed to fit gets a short hash of the original
    appended, so names stay unique and come out the same on every run, which
    prompt caching depends on.
    """
    @spec tool_name(Connection.t() | Server.t() | String.t(), String.t()) :: String.t()
    def tool_name(%Connection{server: server}, tool), do: tool_name(server, tool)
    def tool_name(%Server{name: name}, tool), do: tool_name(name, tool)

    def tool_name(server_name, tool) when is_binary(server_name) and is_binary(tool) do
      raw = "mcp__#{server_name}__#{tool}"

      sanitized =
        raw
        |> String.replace(~r/[^a-zA-Z0-9_-]/, "_")
        # Providers require every hyphen to be followed by a word character
        |> String.replace(~r/-(?=-|$)/, "_")

      if sanitized == raw and byte_size(raw) <= 64 do
        raw
      else
        hash =
          :sha256
          |> :crypto.hash(raw)
          |> Base.encode16(case: :lower)
          |> binary_part(0, 8)

        binary_part(sanitized, 0, min(byte_size(sanitized), 55)) <> "_" <> hash
      end
    end

    @doc """
    Describes each of `definitions` by its ReqLLM tool name.

    Returns `%{tool_name => %{server: name, name: mcp_name, annotations: map, definition: map}}`.
    Approval hooks can use the MCP annotations (`readOnlyHint`,
    `destructiveHint`, `idempotentHint`, `openWorldHint`) to decide which calls
    need a person's approval. Annotations come from the server, so only trust
    them from servers you trust.
    """
    @spec tool_info(Connection.t() | Server.t() | String.t(), [map()]) :: %{String.t() => map()}
    def tool_info(server, definitions) do
      server_name = server_name(server)

      definitions
      |> normalize_definitions()
      |> Map.new(fn definition ->
        {tool_name(server_name, definition["name"]),
         %{
           server: server_name,
           name: definition["name"],
           annotations: definition["annotations"] || %{},
           definition: definition
         }}
      end)
    end

    @doc """
    The MCP annotations of the tool named `tool_name` (a ReqLLM tool name), or
    `nil` when `definitions` has no such tool.
    """
    @spec annotations(Connection.t() | Server.t() | String.t(), [map()], String.t()) ::
            map() | nil
    def annotations(server, definitions, tool_name) do
      case Map.fetch(tool_info(server, definitions), tool_name) do
        {:ok, info} -> info.annotations
        :error -> nil
      end
    end

    if Code.ensure_loaded?(ReqLLM) do
      alias ReqLLM.Message.ContentPart

      # Images over this size, 5 MB once base64-encoded and the smallest
      # per-image limit among the providers that accept them, are described
      # instead. So are images in formats they don't all take, and data that
      # isn't an image at all: a request carrying one fails, on this turn and
      # every later turn that replays it.
      @max_image_bytes 3_750_000

      @doc """
      Turns a `call_tool/4` result into what a ReqLLM tool callback returns.

      Text blocks are joined with newlines, and other blocks are JSON-encoded.
      A result with images, as image blocks or embedded image resources, comes
      back as content parts with an image part for each. `AshAi.ToolLoop`
      describes them in text instead for models that can't receive images in
      tool results. PNG, JPEG, GIF, and WebP images up to 3.75 MB are kept,
      typed by their contents rather than the type the server gave; other
      images, audio, and other binary resources are described without their
      data. A result with only `structuredContent` is JSON-encoded. `isError`
      results become `{:error, text}`.
      """
      @spec format_result(result()) ::
              {:ok, String.t() | [ContentPart.t()]} | {:error, String.t()}
      def format_result(%{content: content, structured_content: structured, is_error: error?}) do
        parts = Enum.map(content, &format_content(&1, not error?))

        cond do
          error? -> {:error, text(parts, structured)}
          Enum.any?(parts, &is_struct(&1, ContentPart)) -> {:ok, merge_text(parts)}
          true -> {:ok, text(parts, structured)}
        end
      end

      # The block as text, or as an image part when `images?`
      defp format_content(%{"type" => "text", "text" => text}, _images?) when is_binary(text),
        do: text

      defp format_content(
             %{"type" => "image", "data" => data, "mimeType" => "image/" <> _} = block,
             true
           ),
           do: image_part(data, block)

      defp format_content(
             %{"type" => "resource", "resource" => %{"blob" => data, "mimeType" => "image/" <> _}} =
               block,
             true
           ),
           do: image_part(data, block)

      defp format_content(%{"type" => type} = block, _images?) when type in ["image", "audio"] do
        block
        |> Map.delete("data")
        |> Map.put("note", "binary content omitted")
        |> Jason.encode!()
      end

      defp format_content(
             %{"type" => "resource", "resource" => %{"blob" => _} = resource} = block,
             _images?
           ) do
        resource =
          resource
          |> Map.delete("blob")
          |> Map.put("note", "binary content omitted")

        Jason.encode!(%{block | "resource" => resource})
      end

      defp format_content(block, _images?), do: Jason.encode!(block)

      defp image_part(data, block) do
        case decode_image(data) do
          {:ok, part} -> part
          :error -> format_content(block, false)
        end
      end

      defp decode_image(data) do
        with true <- is_binary(data),
             {:ok, image} <- Base.decode64(data, ignore: :whitespace),
             true <- byte_size(image) <= @max_image_bytes,
             type when is_binary(type) <- image_type(image) do
          {:ok, ContentPart.image(image, type)}
        else
          _ -> :error
        end
      end

      # The format the data's signature shows, among those every provider takes
      defp image_type(<<0x89, "PNG", 0x0D, 0x0A, 0x1A, 0x0A, _::binary>>), do: "image/png"
      defp image_type(<<0xFF, 0xD8, 0xFF, _::binary>>), do: "image/jpeg"

      defp image_type(<<"GIF8", version, "a", _::binary>>) when version in [?7, ?9],
        do: "image/gif"

      defp image_type(<<"RIFF", _size::binary-size(4), "WEBP", _::binary>>), do: "image/webp"
      defp image_type(_data), do: nil

      defp text(parts, structured) do
        case Enum.join(parts, "\n") do
          "" when not is_nil(structured) -> Jason.encode!(structured)
          text -> text
        end
      end

      # Runs of text become one text part, so the text reads as it would alone
      defp merge_text(parts) do
        parts
        |> Enum.chunk_by(&is_binary/1)
        |> Enum.flat_map(fn
          [text | _] = texts when is_binary(text) -> [ContentPart.text(Enum.join(texts, "\n"))]
          images -> images
        end)
      end

      @doc """
      Turns a `read_resource/2` result into text or ReqLLM content parts, for a
      tool result or a message.

      Text items come back as their text. Blobs are handled as `format_result/1`
      handles embedded resources: PNG, JPEG, GIF, and WebP images up to 3.75 MB
      become image parts, typed by their contents, and other blobs are
      described without their data. When the read returned several items, each
      is introduced by a line naming its URI. A result with images comes back
      as content parts, and any other as one string.
      """
      @spec format_resource(resource_result()) :: {:ok, String.t() | [ContentPart.t()]}
      def format_resource(%{contents: contents}) do
        label? = match?([_, _ | _], contents)
        parts = Enum.flat_map(contents, &resource_parts(&1, label?))

        if Enum.any?(parts, &is_struct(&1, ContentPart)),
          do: {:ok, merge_text(parts)},
          else: {:ok, Enum.join(parts, "\n")}
      end

      defp resource_parts(item, label?) do
        label =
          if label? and is_binary(item["uri"]), do: ["Contents of #{item["uri"]}:"], else: []

        label ++ [resource_part(item)]
      end

      defp resource_part(%{"text" => text}) when is_binary(text), do: text

      defp resource_part(%{"blob" => data, "mimeType" => "image/" <> _} = item) do
        case decode_image(data) do
          {:ok, part} -> part
          :error -> describe_blob(item)
        end
      end

      defp resource_part(%{"blob" => _} = item), do: describe_blob(item)
      defp resource_part(item), do: Jason.encode!(item)

      defp describe_blob(item) do
        item
        |> Map.delete("blob")
        |> Map.put("note", "binary content omitted")
        |> Jason.encode!()
      end

      @doc """
      Builds ReqLLM tools for `definitions`, for `AshAi.ToolLoop`'s `extra_tools`.

      Returns `[{%ReqLLM.Tool{}, callback}]`, sorted by name so the same
      definitions always produce the same tools array. Each tool is named by
      `tool_name/2`, takes the definition's `inputSchema` as its JSON Schema,
      and calls the tool on `conn`.

      Pass a `Server` instead of a connection to connect on each call. Tools
      then build without a request, so a loop can start from a stored snapshot
      of the definitions even while the server needs authorization; a call
      that needs it pauses the loop. Set the server's `protocol_version` to
      the one it negotiated before (`Connection.protocol_version`) and a
      2026-07-28 server needs no extra request per call.

      ## Resources

      With `resources: true`, two more tools let the model read the server's
      resources:

      * `mcp__<server>__list_resources` lists one page of the server's
        resources, plus its resource templates on the first page. It takes the
        `nextCursor` of a previous page as `cursor`.
      * `mcp__<server>__read_resource` reads a resource by URI, formatted by
        `format_resource/1`: one that was listed, one built from a template,
        or a `resource_link` in one of the server's tool results.

      MCP leaves it to the app to decide which resources reach the model, so
      these are off by default. Only add them for servers whose resources the
      model may read. If the server has tools of its own with these names, its
      tools are kept and a warning is logged.

      ## Options

      * `:provider_options` - ReqLLM provider options for every tool, such as
        `[anthropic: [defer_loading: true]]`, or a function of the definition
        returning them. For the resource tools, the function gets a definition
        named `"list_resources"` or `"read_resource"`.
      * `:format_result` - replaces `format_result/1`.
      * `:resources` - adds the resource tools described above. Defaults to `false`.
      * `:format_resource` - replaces `format_resource/1`.
      """
      @spec req_llm_tools(Connection.t() | Server.t(), [map()], keyword()) ::
              [{ReqLLM.Tool.t(), (map(), map() -> {:ok, term()} | {:error, term()})}]
      def req_llm_tools(conn, definitions, opts \\ [])
          when is_struct(conn, Connection) or is_struct(conn, Server) do
        format = Keyword.get(opts, :format_result, &format_result/1)

        tools =
          definitions
          |> normalize_definitions()
          |> Enum.map(fn definition ->
            req_llm_tool(conn, definition, opts, fn arguments ->
              run(
                conn,
                &call_tool(&1, definition["name"], arguments, definition: definition),
                format
              )
            end)
          end)
          # A server could name one tool to match another's shortened name.
          # Keeping the first stops that from failing the whole tools array.
          |> Enum.uniq_by(fn {tool, _callback} -> tool.name end)

        if opts[:resources], do: add_resource_tools(tools, conn, opts), else: tools
      end

      defp req_llm_tool(conn, definition, opts, run) do
        tool =
          ReqLLM.Tool.new!(
            name: tool_name(conn, definition["name"]),
            description: description(conn, definition),
            parameter_schema: clean_schema(definition["inputSchema"] || %{"type" => "object"}),
            callback: run,
            strict: false,
            provider_options: provider_options(opts[:provider_options], definition)
          )

        {tool, fn arguments, _context -> run.(arguments) end}
      end

      defp add_resource_tools(tools, conn, opts) do
        taken = MapSet.new(tools, fn {tool, _callback} -> tool.name end)

        {shadowed, resource_tools} =
          conn
          |> resource_tools(opts)
          |> Enum.split_with(fn {tool, _callback} -> tool.name in taken end)

        for {tool, _callback} <- shadowed do
          Logger.warning(
            "The #{server_name(conn)} MCP server has its own #{tool.name} tool, " <>
              "so that tool is kept and #{tool.name} won't read resources"
          )
        end

        Enum.sort_by(tools ++ resource_tools, fn {tool, _callback} -> tool.name end)
      end

      defp resource_tools(conn, opts) do
        read_name = tool_name(conn, "read_resource")
        list_name = tool_name(conn, "list_resources")
        format = Keyword.get(opts, :format_resource, &format_resource/1)

        list = %{
          "name" => "list_resources",
          "description" =>
            "Lists the resources the #{server_name(conn)} MCP server offers, such as files " <>
              "or records, by URI, and on the first page the URI templates (RFC 6570) " <>
              "it reads others by. Read one with #{read_name}. When the result has a " <>
              "nextCursor, pass it as cursor for the next page.",
          "inputSchema" => %{
            "type" => "object",
            "properties" => %{
              "cursor" => %{
                "type" => "string",
                "description" => "The nextCursor of the previous page"
              }
            }
          }
        }

        read = %{
          "name" => "read_resource",
          "description" =>
            "Reads a resource from the #{server_name(conn)} MCP server by its URI: one " <>
              "listed by #{list_name}, one built from a URI template it lists, or one " <>
              "linked from another of the server's tool results.",
          "inputSchema" => %{
            "type" => "object",
            "properties" => %{
              "uri" => %{"type" => "string", "description" => "The resource's URI"}
            },
            "required" => ["uri"]
          }
        }

        [
          req_llm_tool(conn, list, opts, fn arguments ->
            run(
              conn,
              &resource_page(&1, argument(arguments, "cursor")),
              &{:ok, Jason.encode!(&1)}
            )
          end),
          req_llm_tool(conn, read, opts, fn arguments ->
            case argument(arguments, "uri") do
              uri when is_binary(uri) and uri != "" -> run(conn, &read_resource(&1, uri), format)
              _uri -> {:error, Jason.encode!(%{error: "uri must be a non-empty string"})}
            end
          end)
        ]
      end

      defp argument(%{} = arguments, key), do: arguments[key]
      defp argument(_arguments, _key), do: nil

      # One page per call, so a server with many resources can't flood the
      # context. Templates are few, so the first page carries all of them.
      defp resource_page(conn, cursor) do
        params = if is_binary(cursor) and cursor != "", do: %{"cursor" => cursor}, else: %{}

        with {:ok, result} <- request(conn, "resources/list", params),
             {:ok, templates} <- page_templates(conn, params) do
          page =
            %{
              "resources" =>
                for(
                  %{"uri" => uri} = entry when is_binary(uri) <- List.wrap(result["resources"]),
                  do: listed_fields(entry)
                )
            }

          page = if templates, do: Map.put(page, "resourceTemplates", templates), else: page

          case result["nextCursor"] do
            next when is_binary(next) and next != "" -> {:ok, Map.put(page, "nextCursor", next)}
            _done -> {:ok, page}
          end
        end
      end

      defp page_templates(_conn, %{"cursor" => _}), do: {:ok, nil}

      defp page_templates(conn, _params) do
        case list_resource_templates(conn) do
          {:ok, templates} -> {:ok, Enum.map(templates, &listed_fields/1)}
          # Servers without templates may not implement the method
          {:error, {:jsonrpc_error, -32_601, _message, _data}} -> {:ok, []}
          error -> error
        end
      end

      # Icons can be data URIs, and `_meta` is for the app, not the model
      @listed_fields ~w(uri uriTemplate name title description mimeType size annotations)
      defp listed_fields(entry), do: Map.take(entry, @listed_fields)

      # Connects per call when given a `Server`
      defp run(conn, request, format) do
        case with_connection(conn, request) do
          {:ok, result} ->
            format.(result)

          # Pauses the tool loop instead of telling the model, so the call can
          # run once the user authorizes. See `AshAi.ToolLoop.Result`.
          {:error, {kind, _info} = reason}
          when kind in [:authorization_required, :insufficient_scope] ->
            {:pause, reason}

          {:error, reason} ->
            {:error, Jason.encode!(%{error: error_message(conn, reason)})}
        end
      end

      defp with_connection(%Connection{} = conn, request), do: request.(conn)

      defp with_connection(%Server{} = server, request) do
        with {:ok, conn} <- connect(server) do
          try do
            request.(conn)
          after
            close(conn)
          end
        end
      end

      defp description(conn, definition) do
        definition["description"] || definition["title"] ||
          "Call the #{definition["name"]} tool on the #{server_name(conn)} MCP server"
      end

      # Some providers (Gemini, OpenAI strict mode) reject schema keywords they
      # don't know, so drop the dialect marker and vendor extensions like
      # `x-mcp-header`. Property names are kept even when they look like these.
      defp clean_schema(schema) when is_map(schema) do
        for {key, value} <- schema, not dropped_keyword?(key), into: %{} do
          {key, clean_subschemas(key, value)}
        end
      end

      defp clean_schema(schema), do: schema

      defp dropped_keyword?("$schema"), do: true
      defp dropped_keyword?("x-" <> _), do: true
      defp dropped_keyword?(_key), do: false

      @schema_maps ["properties", "patternProperties", "$defs", "definitions", "dependentSchemas"]
      @schema_lists ["allOf", "anyOf", "oneOf", "prefixItems"]
      @schemas ~w(items additionalProperties additionalItems not if then else contains
                  propertyNames unevaluatedProperties unevaluatedItems)

      defp clean_subschemas(key, value) when key in @schema_maps and is_map(value),
        do: Map.new(value, fn {name, schema} -> {name, clean_schema(schema)} end)

      defp clean_subschemas(key, value) when key in @schema_lists and is_list(value),
        do: Enum.map(value, &clean_schema/1)

      defp clean_subschemas("items", value) when is_list(value),
        do: Enum.map(value, &clean_schema/1)

      defp clean_subschemas(key, value) when key in @schemas, do: clean_schema(value)

      # Anything else is data, such as `default` or `examples`
      defp clean_subschemas(_key, value), do: value

      defp provider_options(nil, _definition), do: %{}
      defp provider_options(fun, definition) when is_function(fun, 1), do: fun.(definition)
      defp provider_options(options, _definition), do: options

      # The model sees this text, so it names the failure without echoing
      # server responses, which may carry tokens or internals
      defp error_message(conn, {:jsonrpc_error, _code, message, _data}),
        do: "The #{server_name(conn)} MCP server rejected the call: #{message}"

      defp error_message(conn, {:http_error, status, _body}),
        do: "The #{server_name(conn)} MCP server answered with HTTP #{status}"

      defp error_message(conn, _reason),
        do: "The request to the #{server_name(conn)} MCP server failed"
    end

    # Definitions may come back from storage with atom keys or in another
    # order; normalizing makes the tools array identical across turns
    defp normalize_definitions(definitions) do
      definitions
      |> Jason.encode!()
      |> Jason.decode!()
      |> Enum.filter(&(is_map(&1) and is_binary(&1["name"])))
      |> Enum.sort_by(& &1["name"])
      |> Enum.uniq_by(& &1["name"])
    end

    defp server_name(%Connection{server: server}), do: server.name
    defp server_name(%Server{name: name}), do: name
    defp server_name(name) when is_binary(name), do: name

    defp valid_tool?(conn, definition) do
      case Headers.params(definition["inputSchema"]) do
        {:ok, _params} ->
          true

        {:error, reason} ->
          Logger.warning(
            "Skipping tool #{inspect(definition["name"])} from MCP server #{conn.server.name}: #{reason}"
          )

          false
      end
    end

    defp paginate(_conn, _method, _key, _cursor, _acc, page) when page >= @max_pages,
      do: {:error, {:too_many_pages, @max_pages}}

    defp paginate(conn, method, key, cursor, acc, page) do
      params = if cursor, do: %{"cursor" => cursor}, else: %{}

      with {:ok, result} <- request(conn, method, params) do
        acc = [result[key] |> List.wrap() |> Enum.filter(&is_map/1) | acc]

        case result["nextCursor"] do
          next when is_binary(next) and next != "" and next != cursor ->
            paginate(conn, method, key, next, acc, page + 1)

          _done ->
            {:ok, acc |> Enum.reverse() |> Enum.concat()}
        end
      end
    end

    # Era detection: a modern request either succeeds or comes back with an
    # error only a modern server sends; anything else marks a legacy server
    defp probe(server, version, tried) do
      conn = modern_connection(server, version, nil)

      case call(conn, "server/discover", %{}, []) do
        {:ok, result, _response} ->
          {:ok, modern_connection(server, version, result)}

        {:error, {:jsonrpc_error, -32_022, _message, data} = error} ->
          supported = if is_map(data), do: List.wrap(data["supported"]), else: []
          tried = [version | tried]

          cond do
            modern = Enum.find(@modern_versions, &(&1 in supported and &1 not in tried)) ->
              probe(server, modern, tried)

            legacy = Enum.find(@legacy_versions, &(&1 in supported)) ->
              initialize(server, legacy)

            true ->
              {:error, error}
          end

        {:error, {:jsonrpc_error, code, _message, _data} = error}
        when code in @modern_error_codes ->
          {:error, error}

        {:error, {:jsonrpc_error, _code, _message, _data}} ->
          initialize(server, hd(@legacy_versions))

        {:error, {:http_error, status, _body}} when status in [400, 404, 405] ->
          initialize(server, hd(@legacy_versions))

        {:error, reason} ->
          {:error, reason}
      end
    end

    defp modern_connection(server, version, discover_result) do
      discover_result = discover_result || %{}

      %Connection{
        server: server,
        protocol_version: version,
        era: :modern,
        server_info: get_in(discover_result, ["_meta", @meta_server_info]),
        capabilities: discover_result["capabilities"] || %{},
        instructions: discover_result["instructions"],
        supported_versions: discover_result["supportedVersions"] || []
      }
    end

    defp initialize(server, version) do
      # No protocol version header until the server states one
      conn = %Connection{server: server, era: :legacy}

      params = %{
        "protocolVersion" => version,
        "capabilities" => server.capabilities,
        "clientInfo" => client_info(server)
      }

      with {:ok, result, response} <- call(conn, "initialize", params, []),
           {:ok, negotiated} <- negotiated_version(result) do
        conn = %Connection{
          conn
          | protocol_version: negotiated,
            session_id: response_header(response, "mcp-session-id"),
            server_info: result["serverInfo"],
            capabilities: result["capabilities"] || %{},
            instructions: result["instructions"],
            supported_versions: [negotiated]
        }

        with :ok <- notify(conn, "notifications/initialized") do
          {:ok, conn}
        end
      end
    end

    defp negotiated_version(%{"protocolVersion" => version}) when version in @legacy_versions,
      do: {:ok, version}

    defp negotiated_version(result),
      do: {:error, {:unsupported_protocol_version, result["protocolVersion"]}}

    defp notify(conn, method) do
      message = %{"jsonrpc" => "2.0", "method" => method}

      case post_message(conn, message) do
        {:ok, %Req.Response{status: status}} when status in 200..299 -> :ok
        {:ok, %Req.Response{status: status, body: body}} -> {:error, {:http_error, status, body}}
        {:error, reason} -> {:error, reason}
      end
    end

    # Sends a request and returns `{:ok, result, response}` or `{:error, reason}`
    defp call(conn, method, params, opts) do
      id = System.unique_integer([:positive, :monotonic])
      body = request_body(conn, method, id, params)
      headers = protocol_headers(conn, method, params) ++ Keyword.get(opts, :headers, [])

      with {:ok, response} <- post(conn, body, headers, id, 0) do
        interpret(conn, response, id)
      end
    end

    defp request_body(%Connection{era: :modern} = conn, method, id, params) do
      meta =
        params
        |> Map.get("_meta", %{})
        |> Map.merge(%{
          @meta_protocol_version => conn.protocol_version,
          @meta_client_info => client_info(conn.server),
          @meta_client_capabilities => conn.server.capabilities
        })

      %{
        "jsonrpc" => "2.0",
        "id" => id,
        "method" => method,
        "params" => Map.put(params, "_meta", meta)
      }
    end

    defp request_body(%Connection{era: :legacy}, method, id, params),
      do: %{"jsonrpc" => "2.0", "id" => id, "method" => method, "params" => params}

    defp protocol_headers(%Connection{era: :modern}, method, params) do
      name =
        case method do
          "resources/read" -> params["uri"]
          method when method in ["tools/call", "prompts/get"] -> params["name"]
          _ -> nil
        end

      [{"mcp-method", method}] ++
        if(is_binary(name), do: [{"mcp-name", Headers.encode_value(name)}], else: [])
    end

    defp protocol_headers(%Connection{era: :legacy}, _method, _params), do: []

    # Every request carries the protocol version and session headers; the
    # caller's headers come after the configured ones so they can't be
    # overridden by mistake
    defp base_headers(%Connection{server: server} = conn) do
      with {:ok, auth_headers} <- auth_headers(server) do
        {:ok,
         [{"accept", "application/json, text/event-stream"}] ++
           static_headers(server) ++
           auth_headers ++
           version_headers(conn) ++
           if(conn.session_id, do: [{"mcp-session-id", conn.session_id}], else: [])}
      end
    end

    # 2025-03-26 predates the MCP-Protocol-Version header
    defp version_headers(%Connection{protocol_version: version})
         when is_nil(version) or version == "2025-03-26",
         do: []

    defp version_headers(%Connection{protocol_version: version}),
      do: [{"mcp-protocol-version", version}]

    defp static_headers(%Server{headers: fun}) when is_function(fun, 0), do: fun.()
    defp static_headers(%Server{headers: headers}), do: headers

    defp auth_headers(%Server{auth: nil}), do: {:ok, []}
    defp auth_headers(%Server{auth: {module, opts}, url: url}), do: module.headers(url, opts)

    defp post(conn, body, headers, id, attempt) do
      with {:ok, base} <- base_headers(conn) do
        result =
          Req.request(req(conn.server),
            method: :post,
            headers: [{"content-type", "application/json"} | base] ++ headers,
            body: Jason.encode!(body),
            into: collect(conn, id)
          )

        case result do
          {:ok, %Req.Response{status: status} = response} when status in [401, 403] ->
            challenge(conn, response, attempt, fn ->
              post(conn, body, headers, id, attempt + 1)
            end)

          {:ok, response} ->
            {:ok, response}

          {:error, %{reason: :non_public_address}} ->
            {:error, {:non_public_address, conn.server.url}}

          {:error, exception} ->
            {:error, exception}
        end
      end
    end

    # Posts a message that gets no JSON-RPC response: a notification, or the
    # answer to a legacy server's request
    defp post_message(conn, message, attempt \\ 0) do
      with {:ok, base} <- base_headers(conn) do
        case Req.request(req(conn.server),
               method: :post,
               headers: [{"content-type", "application/json"} | base],
               body: Jason.encode!(message),
               into: capped_body(conn),
               request_timeout: @message_timeout
             ) do
          {:ok, %Req.Response{status: status} = response} when status in [401, 403] ->
            challenge(conn, response, attempt, fn -> post_message(conn, message, attempt + 1) end)

          other ->
            other
        end
      end
    end

    # The auth module gets one chance to fix credentials. If the retried
    # request is rejected too, it still classifies the rejection, but a second
    # `:retry` ends the attempt instead of looping.
    defp challenge(conn, response, attempt, retry) do
      challenge = %{
        status: response.status,
        www_authenticate: response_header(response, "www-authenticate")
      }

      case conn.server.auth do
        nil ->
          {:error, {:http_error, response.status, challenge.www_authenticate || response.body}}

        {module, opts} ->
          case module.handle_challenge(conn.server.url, challenge, opts) do
            :retry when attempt == 0 -> retry.()
            :retry -> {:error, {:http_error, response.status, challenge.www_authenticate}}
            {:error, reason} -> {:error, reason}
          end
      end
    end

    # Redirects aren't followed: they would carry the request body and any
    # credential headers wherever the server points, and get around whatever
    # checks the application made on the server's URL
    defp req(%Server{} = server) do
      [
        url: server.url,
        retry: false,
        redirect: false,
        decode_body: false,
        request_timeout: server.request_timeout
      ]
      |> Keyword.merge(server.req_options)
      |> NetworkPolicy.req_options(server.url, server.allowed_private_hosts)
      |> Req.new()
    end

    # Keeps a response body up to `max_response_size`, ending the request
    # past it, for messages whose body only matters in an error
    defp capped_body(conn) do
      fn {:data, data}, {request, response} ->
        body = response.body <> data

        if byte_size(body) > conn.server.max_response_size,
          do: {:halt, {request, %{response | body: ""}}},
          else: {:cont, {request, %{response | body: body}}}
      end
    end

    # Streams the response body. An SSE stream is parsed as it arrives so a
    # legacy server's requests can be answered while it waits, and the request
    # ends as soon as the matching response arrives. Any other body is kept.
    # Either way, a response past `max_response_size` ends the request.
    defp collect(conn, id) do
      fn {:data, data}, {request, response} ->
        received = Req.Response.get_private(response, :mcp_received, 0) + byte_size(data)
        response = Req.Response.put_private(response, :mcp_received, received)

        cond do
          received > conn.server.max_response_size ->
            response = Req.Response.put_private(%{response | body: ""}, :mcp_too_large, true)
            {:halt, {request, response}}

          event_stream?(response) ->
            buffer = Req.Response.get_private(response, :mcp_buffer, "")
            answered = Req.Response.get_private(response, :mcp_answered, 0)
            {events, rest} = SSE.parse(buffer, data)

            case handle_events(conn, events, id, answered) do
              {:response, message} ->
                {:halt, {request, Req.Response.put_private(response, :mcp_response, message)}}

              {:continue, answered} ->
                response =
                  response
                  |> Req.Response.put_private(:mcp_buffer, rest)
                  |> Req.Response.put_private(:mcp_answered, answered)

                {:cont, {request, response}}
            end

          true ->
            {:cont, {request, %{response | body: response.body <> data}}}
        end
      end
    end

    defp event_stream?(response) do
      response
      |> Req.Response.get_header("content-type")
      |> Enum.any?(&String.starts_with?(&1, "text/event-stream"))
    end

    defp handle_events(conn, events, id, answered) do
      events
      # Legacy servers may send other event types, such as `endpoint`
      |> Enum.filter(&(&1.event in [nil, "message"]))
      |> Enum.flat_map(fn event ->
        case Jason.decode(event.data) do
          {:ok, messages} when is_list(messages) -> Enum.filter(messages, &is_map/1)
          {:ok, message} when is_map(message) -> [message]
          _ -> []
        end
      end)
      |> Enum.reduce_while({:continue, answered}, fn message, {:continue, answered} ->
        cond do
          response_for?(message, id) ->
            {:halt, {:response, message}}

          is_map_key(message, "method") and is_map_key(message, "id") and
              answered < @max_answered_requests ->
            answer_server_request(conn, message)
            {:cont, {:continue, answered + 1}}

          true ->
            # Notifications (progress, logging), stray responses, and requests
            # past the limit
            {:cont, {:continue, answered}}
        end
      end)
    end

    defp response_for?(message, id) do
      not is_map_key(message, "method") and message["id"] == id and
        (is_map_key(message, "result") or is_map_key(message, "error"))
    end

    # Only legacy servers send requests; 2026-07-28 embeds them in results.
    # Answering keeps a legacy server from waiting forever for an answer.
    defp answer_server_request(%Connection{era: :legacy} = conn, %{"id" => id} = request) do
      answer =
        case request["method"] do
          "ping" ->
            %{"jsonrpc" => "2.0", "id" => id, "result" => %{}}

          method ->
            %{
              "jsonrpc" => "2.0",
              "id" => id,
              "error" => %{"code" => -32_601, "message" => "Method not found: #{method}"}
            }
        end

      post_message(conn, answer)
    end

    defp answer_server_request(_conn, _request), do: :ok

    defp interpret(conn, response, id) do
      message = Req.Response.get_private(response, :mcp_response) || decode_body(response, id)

      cond do
        Req.Response.get_private(response, :mcp_too_large) ->
          {:error, {:response_too_large, conn.server.max_response_size}}

        match?(%{"error" => %{}}, message) ->
          error = message["error"]
          {:error, {:jsonrpc_error, error["code"], error["message"], error["data"]}}

        # MCP results are objects, and everything downstream reads them as maps
        response.status in 200..299 and is_map(message) and is_map_key(message, "result") ->
          case message["result"] do
            %{} = result -> {:ok, result, response}
            _other -> {:error, {:invalid_response, "result"}}
          end

        conn.era == :legacy and is_binary(conn.session_id) and response.status == 404 ->
          {:error, :session_expired}

        true ->
          {:error, {:http_error, response.status, response.body}}
      end
    end

    defp decode_body(%Req.Response{body: body}, id) when is_binary(body) and body != "" do
      case Jason.decode(body) do
        {:ok, %{} = message} ->
          message

        # 2025-03-26 allowed batched responses
        {:ok, messages} when is_list(messages) ->
          Enum.find(messages, &(is_map(&1) and response_for?(&1, id)))

        _ ->
          nil
      end
    end

    defp decode_body(_response, _id), do: nil

    defp response_header(response, name) do
      case Req.Response.get_header(response, name) do
        [value | _] -> value
        [] -> nil
      end
    end

    defp client_info(%Server{client_info: %{} = client_info}), do: client_info

    defp client_info(%Server{}) do
      %{"name" => "ash_ai", "version" => to_string(Application.spec(:ash_ai, :vsn) || "0.0.0")}
    end
  end
end
