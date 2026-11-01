# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.ClientResourcesTest do
  @moduledoc """
  Reading an MCP server's resources with `AshAi.Mcp.Client`, directly and as ReqLLM tools.
  """
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog
  import Plug.Conn

  alias AshAi.Mcp.Client
  alias ReqLLM.Message.ContentPart
  alias __MODULE__.{Docs, Domain}

  @url "https://mcp.example.com/mcp"
  @png <<0x89, "PNG", 0x0D, 0x0A, 0x1A, 0x0A, "png bytes">>

  defmodule Docs do
    use Ash.Resource, domain: Domain, validate_domain_inclusion?: false

    @png <<0x89, "PNG", 0x0D, 0x0A, 0x1A, 0x0A, "png bytes">>

    actions do
      action :readme, :string do
        description "The project's readme"
        run fn _input, _context -> {:ok, "# Readme"} end
      end

      action :archive, :binary do
        run fn _input, _context -> {:ok, <<"PK", 3, 4>>} end
      end

      action :note, :string do
        description "A note by id"
        argument :id, :string, allow_nil?: false
        run fn %{arguments: %{id: id}}, _context -> {:ok, "note #{id}"} end
      end

      action :photo, :binary do
        description "A photo by id"
        argument :id, :string, allow_nil?: false
        run fn _input, _context -> {:ok, @png} end
      end
    end
  end

  defmodule Domain do
    use Ash.Domain, extensions: [AshAi], validate_config_inclusion?: false

    resources do
      resource Docs
    end

    mcp_resources do
      mcp_resource :readme, "docs://readme", Docs, :readme,
        title: "Readme",
        mime_type: "text/markdown"

      mcp_resource :archive, "docs://archive.zip", Docs, :archive,
        title: "Archive",
        mime_type: "application/zip"

      mcp_resource :note, "notes://{id}", Docs, :note, title: "Note"

      mcp_resource :photo, "photos://{id}", Docs, :photo,
        title: "Photo",
        mime_type: "image/png"
    end
  end

  defmodule NoAuth do
    @behaviour AshAi.Mcp.Client.Auth

    @impl true
    def headers(_server_url, _opts), do: {:error, {:authorization_required, %{}}}

    @impl true
    def handle_challenge(_server_url, _challenge, _opts),
      do: {:error, {:authorization_required, %{}}}
  end

  @router_opts [actions: [{Docs, :*}]]

  defp server(plug, opts \\ []) do
    Client.server(Keyword.merge([name: "docs", url: @url, req_options: [plug: plug]], opts))
  end

  defp connect(plug, opts \\ []) do
    {:ok, conn} = Client.connect(server(plug, opts))
    _ = requests()
    conn
  end

  # Records each request, then lets the real router answer it
  defp router(opts \\ @router_opts) do
    fn conn ->
      {conn, message} = read_message(conn)
      route(conn, message, opts)
    end
  end

  # Answers only the initialize-based revisions, as common legacy SDKs do
  defp legacy_router(opts \\ @router_opts) do
    fn conn ->
      {conn, message} = read_message(conn)

      if get_in(message || %{}, ["params", "_meta", "io.modelcontextprotocol/protocolVersion"]) do
        json(conn, 400, %{
          "jsonrpc" => "2.0",
          "id" => nil,
          "error" => %{"code" => -32_000, "message" => "Bad Request: Server not initialized"}
        })
      else
        route(conn, message, opts)
      end
    end
  end

  defp route(conn, message, opts) do
    conn = %{conn | path_info: [], body_params: if(is_map(message), do: message, else: %{})}
    AshAi.Mcp.Router.call(conn, AshAi.Mcp.Router.init(opts))
  end

  # A scripted server: `handler` gets the decoded message and answers it
  defp fake(handler) do
    fn conn ->
      {conn, message} = read_message(conn)

      case message["method"] do
        "server/discover" ->
          result(conn, message, %{
            "supportedVersions" => ["2026-07-28"],
            "capabilities" => %{"resources" => %{}}
          })

        _method ->
          handler.(conn, message)
      end
    end
  end

  defp read_message(conn) do
    {:ok, body, conn} = read_body(conn)
    message = if body == "", do: nil, else: Jason.decode!(body)
    send(self(), {:mcp_request, conn.req_headers, message})
    {conn, message}
  end

  defp json(conn, status, body) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(body))
  end

  defp result(conn, %{"id" => id}, result),
    do: json(conn, 200, %{"jsonrpc" => "2.0", "id" => id, "result" => result})

  defp error(conn, %{"id" => id}, code, message),
    do:
      json(conn, 200, %{
        "jsonrpc" => "2.0",
        "id" => id,
        "error" => %{"code" => code, "message" => message}
      })

  defp requests, do: receive_requests([])

  defp receive_requests(acc) do
    receive do
      {:mcp_request, headers, message} ->
        receive_requests([%{headers: headers, message: message} | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end

  defp header(headers, name) do
    case List.keyfind(headers, name, 0) do
      {^name, value} -> value
      nil -> nil
    end
  end

  defp tools(conn, definitions \\ [], opts \\ [resources: true]) do
    conn
    |> Client.req_llm_tools(definitions, opts)
    |> Map.new(fn {tool, callback} -> {tool.name, {tool, callback}} end)
  end

  defp call(tools, name, arguments) do
    {_tool, callback} = Map.fetch!(tools, name)
    callback.(arguments, %{})
  end

  describe "list_resources/1 and list_resource_templates/1" do
    test "list a server's resources and templates in either era" do
      for plug <- [router(), legacy_router()] do
        conn = connect(plug)

        assert {:ok, resources} = Client.list_resources(conn)

        assert [
                 %{"uri" => "docs://archive.zip", "mimeType" => "application/zip"},
                 %{"uri" => "docs://readme", "name" => "readme", "title" => "Readme"}
               ] = resources

        assert {:ok, templates} = Client.list_resource_templates(conn)

        assert [
                 %{"uriTemplate" => "notes://{id}", "description" => "A note by id"},
                 %{"uriTemplate" => "photos://{id}", "mimeType" => "image/png"}
               ] = templates
      end
    end

    test "follow nextCursor pagination" do
      conn = connect(router(Keyword.put(@router_opts, :list_page_size, 1)))

      assert {:ok, [_, _]} = Client.list_resources(conn)
      assert {:ok, [_, _]} = Client.list_resource_templates(conn)

      assert requests() |> Enum.map(& &1.message["method"]) ==
               List.duplicate("resources/list", 2) ++
                 List.duplicate("resources/templates/list", 2)
    end

    test "skip entries without a string URI" do
      conn =
        connect(
          fake(fn conn, message ->
            case message["method"] do
              "resources/list" ->
                result(conn, message, %{
                  "resources" => [%{"uri" => "a://1"}, %{"name" => "no uri"}, %{"uri" => 2}, "x"]
                })

              "resources/templates/list" ->
                result(conn, message, %{
                  "resourceTemplates" => [%{"uriTemplate" => "a://{id}"}, %{"uri" => "a://1"}]
                })
            end
          end)
        )

      assert {:ok, [%{"uri" => "a://1"}]} = Client.list_resources(conn)
      assert {:ok, [%{"uriTemplate" => "a://{id}"}]} = Client.list_resource_templates(conn)
    end
  end

  describe "read_resource/2" do
    test "reads text, binary and templated resources in either era" do
      for plug <- [router(), legacy_router()] do
        conn = connect(plug)

        assert {:ok, %{contents: [readme]}} = Client.read_resource(conn, "docs://readme")

        assert readme == %{
                 "uri" => "docs://readme",
                 "mimeType" => "text/markdown",
                 "text" => "# Readme"
               }

        assert {:ok, %{contents: [%{"blob" => blob}]}} =
                 Client.read_resource(conn, "docs://archive.zip")

        assert Base.decode64!(blob) == <<"PK", 3, 4>>

        assert {:ok, %{contents: [%{"uri" => "notes://7", "text" => "note 7"}]}} =
                 Client.read_resource(conn, "notes://7")
      end
    end

    test "names the resource in the Mcp-Name header on 2026-07-28" do
      conn = connect(router())
      assert {:ok, %{meta: meta}} = Client.read_resource(conn, "notes://7")
      assert is_map(meta["io.modelcontextprotocol/serverInfo"])

      [read] = requests()
      assert header(read.headers, "mcp-method") == "resources/read"
      assert header(read.headers, "mcp-name") == "notes://7"
    end

    test "a missing resource is a JSON-RPC error" do
      assert {:error, {:jsonrpc_error, -32_602, "Resource not found", %{"uri" => "docs://nope"}}} =
               router() |> connect() |> Client.read_resource("docs://nope")

      assert {:error, {:jsonrpc_error, -32_002, "Resource not found", %{"uri" => "docs://nope"}}} =
               legacy_router() |> connect() |> Client.read_resource("docs://nope")
    end
  end

  describe "format_resource/1" do
    defp format(contents), do: Client.format_resource(%{contents: contents, meta: nil})

    test "returns a text item as its text" do
      assert format([%{"uri" => "a://1", "text" => "hello"}]) == {:ok, "hello"}
      assert format([]) == {:ok, ""}
    end

    test "names each item's URI when there are several" do
      assert format([
               %{"uri" => "a://1", "text" => "one"},
               %{"uri" => "a://2", "text" => "two"}
             ]) == {:ok, "Contents of a://1:\none\nContents of a://2:\ntwo"}
    end

    test "returns image blobs as image parts, typed by their contents" do
      image = %{"uri" => "a://1", "mimeType" => "image/jpeg", "blob" => Base.encode64(@png)}

      assert {:ok, [%ContentPart{type: :image, data: @png, media_type: "image/png"}]} =
               format([image])

      assert {:ok,
              [
                %ContentPart{
                  type: :text,
                  text: "Contents of a://0:\ncaption\nContents of a://1:"
                },
                %ContentPart{type: :image}
              ]} =
               format([%{"uri" => "a://0", "text" => "caption"}, image])
    end

    test "describes other blobs and images it can't pass on, without their data" do
      for item <- [
            %{"uri" => "a://1", "mimeType" => "application/zip", "blob" => Base.encode64("PK")},
            %{"uri" => "a://1", "mimeType" => "image/png", "blob" => Base.encode64("not a png")},
            %{"uri" => "a://1", "mimeType" => "image/png", "blob" => "not base64!"}
          ] do
        assert {:ok, text} = format([item])

        assert Jason.decode!(text) == %{
                 "uri" => "a://1",
                 "mimeType" => item["mimeType"],
                 "note" => "binary content omitted"
               }
      end
    end
  end

  describe "req_llm_tools/3 with resources: true" do
    test "adds list and read tools, sorted among the server's tools" do
      definitions = [
        %{
          "name" => "search",
          "description" => "Search docs",
          "inputSchema" => %{"type" => "object"}
        }
      ]

      names =
        router()
        |> connect()
        |> Client.req_llm_tools(definitions, resources: true)
        |> Enum.map(fn {tool, _callback} -> tool.name end)

      assert names == ~w(mcp__docs__list_resources mcp__docs__read_resource mcp__docs__search)

      tools = tools(connect(router()))
      {list, _} = tools["mcp__docs__list_resources"]
      {read, _} = tools["mcp__docs__read_resource"]

      assert list.description =~ "Read one with mcp__docs__read_resource"
      assert read.description =~ "listed by mcp__docs__list_resources"
      assert read.parameter_schema["required"] == ["uri"]
      assert Map.keys(list.parameter_schema["properties"]) == ["cursor"]
    end

    test "are off by default" do
      assert Client.req_llm_tools(connect(router()), []) == []
    end

    test "list_resources pages through resources, with templates on the first page" do
      tools = router(Keyword.put(@router_opts, :list_page_size, 1)) |> connect() |> tools()

      assert {:ok, first} = call(tools, "mcp__docs__list_resources", %{})

      assert %{
               "resources" => [%{"uri" => "docs://archive.zip", "name" => "archive"}],
               "resourceTemplates" => [_, _],
               "nextCursor" => cursor
             } = Jason.decode!(first)

      assert {:ok, second} = call(tools, "mcp__docs__list_resources", %{"cursor" => cursor})
      assert %{"resources" => [%{"uri" => "docs://readme"}]} = page = Jason.decode!(second)
      refute Map.has_key?(page, "resourceTemplates")
      refute Map.has_key?(page, "nextCursor")
    end

    test "list_resources leaves out icons and _meta, and copes without templates" do
      tools =
        fake(fn conn, message ->
          case message["method"] do
            "resources/list" ->
              result(conn, message, %{
                "resources" => [
                  %{
                    "uri" => "a://1",
                    "name" => "one",
                    "size" => 3,
                    "annotations" => %{"audience" => ["assistant"]},
                    "icons" => [%{"src" => "data:image/png;base64,AAAA"}],
                    "_meta" => %{"com.example/secret" => true}
                  }
                ]
              })

            "resources/templates/list" ->
              error(conn, message, -32_601, "Method not found")
          end
        end)
        |> connect()
        |> tools()

      assert {:ok, page} = call(tools, "mcp__docs__list_resources", %{})

      assert Jason.decode!(page) == %{
               "resources" => [
                 %{
                   "uri" => "a://1",
                   "name" => "one",
                   "size" => 3,
                   "annotations" => %{"audience" => ["assistant"]}
                 }
               ],
               "resourceTemplates" => []
             }
    end

    test "read_resource reads text and images" do
      tools = router() |> connect() |> tools()

      assert call(tools, "mcp__docs__read_resource", %{"uri" => "notes://3"}) == {:ok, "note 3"}

      assert {:ok, [%ContentPart{type: :image, data: @png}]} =
               call(tools, "mcp__docs__read_resource", %{"uri" => "photos://3"})
    end

    test "read_resource reports a missing resource and a missing uri to the model" do
      tools = router() |> connect() |> tools()

      assert {:error, error} = call(tools, "mcp__docs__read_resource", %{"uri" => "docs://nope"})

      assert Jason.decode!(error) == %{
               "error" => "The docs MCP server rejected the call: Resource not found"
             }

      for arguments <- [%{}, %{"uri" => ""}, %{"uri" => 1}] do
        assert {:error, error} = call(tools, "mcp__docs__read_resource", arguments)
        assert Jason.decode!(error) == %{"error" => "uri must be a non-empty string"}
      end

      assert requests() |> Enum.map(& &1.message["method"]) == ["resources/read"]
    end

    test "keeps a server's own tool of the same name" do
      definitions = [
        %{"name" => "read_resource", "description" => "The server's own", "inputSchema" => %{}}
      ]

      {tools, log} =
        with_log(fn -> router() |> connect() |> tools(definitions) end)

      assert log =~ "The docs MCP server has its own mcp__docs__read_resource tool"
      assert {%{description: "The server's own"}, _} = tools["mcp__docs__read_resource"]
      assert Map.has_key?(tools, "mcp__docs__list_resources")
    end

    test "connect on each call when given a server" do
      tools = router() |> server() |> tools()
      assert requests() == []

      assert call(tools, "mcp__docs__read_resource", %{"uri" => "notes://1"}) == {:ok, "note 1"}

      assert requests() |> Enum.map(& &1.message["method"]) == [
               "server/discover",
               "resources/read"
             ]
    end

    test "pause the loop when the server needs authorization" do
      tools = router() |> server(auth: {NoAuth, []}) |> tools()

      assert {:pause, {:authorization_required, %{}}} =
               call(tools, "mcp__docs__read_resource", %{"uri" => "notes://1"})

      assert {:pause, {:authorization_required, %{}}} =
               call(tools, "mcp__docs__list_resources", %{})
    end

    test "take the server's provider options and a custom formatter" do
      tools =
        router()
        |> connect()
        |> tools([],
          resources: true,
          provider_options: fn definition -> [anthropic: [cache: definition["name"]]] end,
          format_resource: fn %{contents: [item]} -> {:ok, "custom: " <> item["text"]} end
        )

      {read, _} = tools["mcp__docs__read_resource"]
      assert ReqLLM.Tool.provider_options(read, :anthropic) == %{cache: "read_resource"}

      assert call(tools, "mcp__docs__read_resource", %{"uri" => "notes://5"}) ==
               {:ok, "custom: note 5"}
    end

    test "work as ToolLoop extra_tools" do
      {_tools, registry} =
        AshAi.Tools.build_tools_and_registry(
          extra_tools: router() |> connect() |> Client.req_llm_tools([], resources: true),
          tools: false
        )

      assert {:ok, "note 9", _raw} =
               registry["mcp__docs__read_resource"].(%{"uri" => "notes://9"}, %{})
    end
  end
end
