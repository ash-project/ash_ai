# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.ClientTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog
  import Plug.Conn

  alias AshAi.Mcp.Client
  alias AshAi.Mcp.Client.{Headers, SSE}

  defmodule Widget do
    use Ash.Resource,
      domain: AshAi.Mcp.ClientTest.Domain,
      data_layer: Ash.DataLayer.Ets

    ets do
      private?(true)
    end

    actions do
      action :echo, :string do
        description "Echo a message back."
        argument :message, :string, allow_nil?: false

        run fn input, _ctx -> {:ok, "echo: #{input.arguments.message}"} end
      end
    end
  end

  defmodule Domain do
    use Ash.Domain, extensions: [AshAi]

    resources do
      resource Widget
    end

    tools do
      tool :echo, Widget, :echo
    end
  end

  defmodule RefreshingAuth do
    @behaviour AshAi.Mcp.Client.Auth

    @impl true
    def headers(_server_url, opts) do
      case Process.get(opts[:key]) do
        nil -> {:error, {:authorization_required, %{}}}
        token -> {:ok, [{"authorization", "Bearer " <> token}]}
      end
    end

    @impl true
    def handle_challenge(server_url, challenge, opts) do
      send(self(), {:challenge, server_url, challenge})

      case opts[:refresh_to] do
        nil ->
          {:error, {:authorization_required, %{www_authenticate: challenge.www_authenticate}}}

        token ->
          Process.put(opts[:key], token)
          :retry
      end
    end
  end

  @router_opts [actions: [{Widget, :*}], mcp_resources: []]
  @url "https://mcp.example.com/mcp"

  # Image data with the signatures the client checks for
  @png <<0x89, "PNG", 0x0D, 0x0A, 0x1A, 0x0A, "png bytes">>
  @webp "RIFF" <> <<0, 0, 0, 0>> <> "WEBP" <> "webp bytes"

  defp server(plug, opts \\ []) do
    Client.server(Keyword.merge([name: "test", url: @url, req_options: [plug: plug]], opts))
  end

  # Records each request, then lets the real router answer it
  defp router(opts \\ @router_opts) do
    fn conn ->
      {conn, message} = read_message(conn)
      router(conn, message, opts)
    end
  end

  defp router(conn, message, opts) do
    # The router is mounted at the endpoint path, as with `forward "/mcp"`
    conn = %{conn | path_info: [], body_params: if(is_map(message), do: message, else: %{})}
    AshAi.Mcp.Router.call(conn, AshAi.Mcp.Router.init(opts))
  end

  # A server that only speaks the initialize-based revisions, answering a
  # modern request the way common legacy SDKs do
  defp legacy_router do
    fn conn ->
      {conn, message} = read_message(conn)

      if get_in(message || %{}, ["params", "_meta", "io.modelcontextprotocol/protocolVersion"]) do
        json(conn, 400, %{
          "jsonrpc" => "2.0",
          "id" => nil,
          "error" => %{"code" => -32_000, "message" => "Bad Request: Server not initialized"}
        })
      else
        router(conn, message, @router_opts)
      end
    end
  end

  # A scripted server: `handler` gets the decoded message and answers it
  defp fake(handler) do
    fn conn ->
      {conn, message} = read_message(conn)
      handler.(conn, message)
    end
  end

  defp read_message(conn) do
    {:ok, body, conn} = read_body(conn)
    message = if body == "", do: nil, else: Jason.decode!(body)
    send(self(), {:mcp_request, conn.method, conn.req_headers, message})
    {conn, message}
  end

  defp json(conn, status, body) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(body))
  end

  defp result(conn, %{"id" => id}, result) do
    json(conn, 200, %{"jsonrpc" => "2.0", "id" => id, "result" => result})
  end

  defp discover_result(conn, message) do
    result(conn, message, %{
      "resultType" => "complete",
      "supportedVersions" => ["2026-07-28"],
      "capabilities" => %{"tools" => %{}}
    })
  end

  defp header(headers, name) do
    case List.keyfind(headers, name, 0) do
      {^name, value} -> value
      nil -> nil
    end
  end

  defp requests do
    receive_requests([])
  end

  defp receive_requests(acc) do
    receive do
      {:mcp_request, method, headers, message} ->
        receive_requests([%{method: method, headers: headers, message: message} | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end

  defp guarded(token) do
    fn conn ->
      if get_req_header(conn, "authorization") == ["Bearer " <> token] do
        router().(conn)
      else
        conn
        |> put_resp_header(
          "www-authenticate",
          ~s(Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource")
        )
        |> send_resp(401, "")
      end
    end
  end

  describe "revision 2026-07-28" do
    test "discovers the server, lists tools, and calls one" do
      assert {:ok, conn} = Client.connect(server(router()))
      assert conn.era == :modern
      assert conn.protocol_version == "2026-07-28"
      assert conn.session_id == nil
      assert is_map(conn.server_info)
      assert "2025-11-25" in conn.supported_versions

      assert {:ok, [tool]} = Client.list_tools(conn)
      assert tool["name"] == "echo"
      assert tool["description"] == "Echo a message back."

      assert {:ok, result} =
               Client.call_tool(conn, "echo", %{"input" => %{"message" => "hi"}})

      assert result.is_error == false
      assert [%{"type" => "text", "text" => text}] = result.content
      assert text =~ "echo: hi"

      [discover, list, call] = requests()

      assert discover.message["method"] == "server/discover"
      assert header(discover.headers, "mcp-protocol-version") == "2026-07-28"
      assert header(discover.headers, "accept") == "application/json, text/event-stream"

      meta = call.message["params"]["_meta"]
      assert meta["io.modelcontextprotocol/protocolVersion"] == "2026-07-28"
      assert meta["io.modelcontextprotocol/clientCapabilities"] == %{}
      assert meta["io.modelcontextprotocol/clientInfo"]["name"] == "ash_ai"
      assert header(call.headers, "mcp-method") == "tools/call"
      assert header(call.headers, "mcp-name") == "echo"
      assert header(list.headers, "mcp-name") == nil
    end

    test "a known modern version skips the probe" do
      server = server(router(), protocol_version: "2026-07-28")

      assert {:ok, conn} = Client.connect(server)
      assert conn.era == :modern
      assert requests() == []

      assert {:ok, [_tool]} = Client.list_tools(conn)
    end

    test "encodes names that aren't plain header values" do
      {:ok, conn} = Client.connect(server(router(), protocol_version: "2026-07-28"))

      # The router decodes the sentinel and compares it to the body, so a wrong
      # encoding would come back as HeaderMismatch (-32020)
      assert {:error, {:jsonrpc_error, -32_602, "Tool not found: héllo", _}} =
               Client.call_tool(conn, "héllo", %{})

      [call] = requests()
      assert header(call.headers, "mcp-name") == "=?base64?" <> Base.encode64("héllo") <> "?="
    end

    test "maps JSON-RPC errors" do
      {:ok, conn} = Client.connect(server(router()))

      assert {:error, {:jsonrpc_error, -32_602, "Tool not found: missing", nil}} =
               Client.call_tool(conn, "missing", %{})
    end

    test "returns input_required results as errors" do
      plug =
        fake(fn conn, message ->
          case message["method"] do
            "server/discover" ->
              discover_result(conn, message)

            "tools/call" ->
              result(conn, message, %{
                "resultType" => "input_required",
                "inputRequests" => %{"login" => %{"method" => "elicitation/create"}}
              })
          end
        end)

      {:ok, conn} = Client.connect(server(plug))

      assert {:error, {:input_required, %{"inputRequests" => %{"login" => _}}}} =
               Client.call_tool(conn, "login", %{})
    end

    test "follows nextCursor pagination" do
      plug =
        fake(fn conn, message ->
          case {message["method"], message["params"]["cursor"]} do
            {"server/discover", _} ->
              discover_result(conn, message)

            {"tools/list", nil} ->
              result(conn, message, %{
                "tools" => [%{"name" => "a", "inputSchema" => %{"type" => "object"}}],
                "nextCursor" => "page-2"
              })

            {"tools/list", "page-2"} ->
              result(conn, message, %{
                "tools" => [%{"name" => "b", "inputSchema" => %{"type" => "object"}}],
                "nextCursor" => "page-3"
              })

            {"tools/list", "page-3"} ->
              result(conn, message, %{
                "tools" => [%{"name" => "c", "inputSchema" => %{"type" => "object"}}]
              })
          end
        end)

      {:ok, conn} = Client.connect(server(plug))

      assert {:ok, tools} = Client.list_tools(conn)
      assert Enum.map(tools, & &1["name"]) == ["a", "b", "c"]
    end

    test "reads a chunked SSE response, skipping notifications" do
      plug =
        fake(fn conn, message ->
          case message["method"] do
            "server/discover" ->
              discover_result(conn, message)

            "tools/call" ->
              progress =
                Jason.encode!(%{
                  "jsonrpc" => "2.0",
                  "method" => "notifications/progress",
                  "params" => %{"progressToken" => 1, "progress" => 0.5}
                })

              response =
                Jason.encode!(%{
                  "jsonrpc" => "2.0",
                  "id" => message["id"],
                  "result" => %{
                    "resultType" => "complete",
                    "content" => [%{"type" => "text", "text" => "streamed"}]
                  }
                })

              stream =
                ": keep-alive\r\n\r\nevent: message\r\ndata: #{progress}\r\n\r\ndata: #{response}\r\n\r\n"

              # Split mid-event and inside a CRLF
              {first, rest} = String.split_at(stream, 40)
              {second, third} = String.split_at(rest, String.length(rest) - 3)

              conn =
                conn
                |> put_resp_content_type("text/event-stream")
                |> send_chunked(200)

              Enum.reduce([first, second, third], conn, fn chunk, conn ->
                {:ok, conn} = chunk(conn, chunk)
                conn
              end)
          end
        end)

      {:ok, conn} = Client.connect(server(plug))

      assert {:ok, %{content: [%{"text" => "streamed"}]}} = Client.call_tool(conn, "slow", %{})
    end

    test "mirrors x-mcp-header parameters and skips tools with invalid annotations" do
      region_tool = %{
        "name" => "execute_sql",
        "inputSchema" => %{
          "type" => "object",
          "properties" => %{
            "region" => %{"type" => "string", "x-mcp-header" => "Region"},
            "options" => %{
              "type" => "object",
              "properties" => %{"dry_run" => %{"type" => "boolean", "x-mcp-header" => "DryRun"}}
            },
            "query" => %{"type" => "string"}
          }
        }
      }

      invalid_tool = %{
        "name" => "bad",
        "inputSchema" => %{
          "type" => "object",
          "properties" => %{
            "ids" => %{
              "type" => "array",
              "items" => %{"type" => "string", "x-mcp-header" => "Id"}
            }
          }
        }
      }

      plug =
        fake(fn conn, message ->
          case message["method"] do
            "server/discover" ->
              discover_result(conn, message)

            "tools/list" ->
              result(conn, message, %{"tools" => [region_tool, invalid_tool]})

            "tools/call" ->
              result(conn, message, %{"content" => [%{"type" => "text", "text" => "ok"}]})
          end
        end)

      {:ok, conn} = Client.connect(server(plug))

      log =
        capture_log(fn ->
          assert {:ok, [%{"name" => "execute_sql"}]} = Client.list_tools(conn)
        end)

      assert log =~ ~s(Skipping tool "bad")

      requests()

      assert {:ok, _} =
               Client.call_tool(
                 conn,
                 "execute_sql",
                 %{
                   "region" => "Zürich",
                   "options" => %{"dry_run" => true},
                   "query" => "SELECT 1"
                 },
                 definition: region_tool
               )

      [call] = requests()

      assert header(call.headers, "mcp-param-region") ==
               "=?base64?" <> Base.encode64("Zürich") <> "?="

      assert header(call.headers, "mcp-param-dryrun") == "true"
    end
  end

  describe "initialize-based fallback" do
    test "falls back when a modern request is rejected without a modern error" do
      assert {:ok, conn} = Client.connect(server(legacy_router()))
      assert conn.era == :legacy
      assert conn.protocol_version == "2025-11-25"
      assert is_binary(conn.session_id)
      assert conn.server_info["name"]

      assert {:ok, [%{"name" => "echo"}]} = Client.list_tools(conn)

      assert {:ok, %{is_error: false, content: [%{"text" => text}]}} =
               Client.call_tool(conn, "echo", %{"input" => %{"message" => "legacy"}})

      assert text =~ "echo: legacy"

      assert :ok = Client.close(conn)

      [discover, initialize, initialized, list, call, delete] = requests()

      assert discover.message["method"] == "server/discover"
      assert initialize.message["method"] == "initialize"
      assert initialize.message["params"]["protocolVersion"] == "2025-11-25"
      assert initialize.message["params"]["clientInfo"]["name"] == "ash_ai"
      refute header(initialize.headers, "mcp-protocol-version")

      assert initialized.message == %{"jsonrpc" => "2.0", "method" => "notifications/initialized"}

      for request <- [initialized, list, call, delete] do
        assert header(request.headers, "mcp-session-id") == conn.session_id
        assert header(request.headers, "mcp-protocol-version") == "2025-11-25"
      end

      refute Map.has_key?(list.message["params"], "_meta")
      assert delete.method == "DELETE"
    end

    test "a known legacy version initializes directly" do
      assert {:ok, conn} = Client.connect(server(router(), protocol_version: "2025-06-18"))
      assert conn.era == :legacy
      assert conn.protocol_version == "2025-06-18"

      assert [%{message: %{"method" => "initialize"}}, %{message: %{"method" => _}}] =
               requests()
    end

    test "retries with a version from UnsupportedProtocolVersionError" do
      plug =
        fake(fn conn, message ->
          case message["method"] do
            "server/discover" ->
              json(conn, 400, %{
                "jsonrpc" => "2.0",
                "id" => message["id"],
                "error" => %{
                  "code" => -32_022,
                  "message" => "Unsupported protocol version",
                  "data" => %{"supported" => ["2025-06-18"], "requested" => "2026-07-28"}
                }
              })

            "initialize" ->
              conn
              |> put_resp_header("mcp-session-id", "session-1")
              |> result(message, %{"protocolVersion" => "2025-06-18", "capabilities" => %{}})

            "notifications/initialized" ->
              send_resp(conn, 202, "")
          end
        end)

      assert {:ok, conn} = Client.connect(server(plug))
      assert conn.protocol_version == "2025-06-18"
      assert conn.session_id == "session-1"
    end

    test "does not fall back on other modern errors" do
      plug =
        fake(fn conn, message ->
          json(conn, 400, %{
            "jsonrpc" => "2.0",
            "id" => message["id"],
            "error" => %{"code" => -32_020, "message" => "Header mismatch"}
          })
        end)

      assert {:error, {:jsonrpc_error, -32_020, "Header mismatch", nil}} =
               Client.connect(server(plug))

      assert [%{message: %{"method" => "server/discover"}}] = requests()
    end

    test "answers a legacy server's requests on a response stream" do
      plug =
        fake(fn conn, message ->
          case message do
            %{"method" => "server/discover"} ->
              send_resp(conn, 404, "Not Found")

            %{"method" => "initialize"} ->
              conn
              |> put_resp_header("mcp-session-id", "session-1")
              |> result(message, %{"protocolVersion" => "2025-11-25", "capabilities" => %{}})

            %{"method" => "tools/call", "id" => id} ->
              events =
                [
                  %{"jsonrpc" => "2.0", "method" => "notifications/message", "params" => %{}},
                  %{"jsonrpc" => "2.0", "id" => "srv-1", "method" => "sampling/createMessage"},
                  %{"jsonrpc" => "2.0", "id" => "srv-2", "method" => "ping"},
                  %{
                    "jsonrpc" => "2.0",
                    "id" => id,
                    "result" => %{"content" => [%{"type" => "text", "text" => "done"}]}
                  }
                ]
                |> Enum.map_join(fn event ->
                  "event: message\ndata: #{Jason.encode!(event)}\n\n"
                end)

              conn
              |> put_resp_content_type("text/event-stream")
              |> send_resp(200, events)

            # notifications/initialized and the client's answers
            _no_id ->
              send_resp(conn, 202, "")
          end
        end)

      {:ok, conn} = Client.connect(server(plug))
      requests()

      assert {:ok, %{content: [%{"text" => "done"}]}} = Client.call_tool(conn, "work", %{})

      [_call, sampling_answer, ping_answer] = requests()

      assert %{"id" => "srv-1", "error" => %{"code" => -32_601}} = sampling_answer.message
      assert ping_answer.message == %{"jsonrpc" => "2.0", "id" => "srv-2", "result" => %{}}
      assert header(sampling_answer.headers, "mcp-session-id") == "session-1"
    end
  end

  describe "auth" do
    test "adds the auth module's headers and retries once after it refreshes" do
      Process.put(:token, "stale")
      auth = {RefreshingAuth, key: :token, refresh_to: "fresh"}

      assert {:ok, conn} = Client.connect(server(guarded("fresh"), auth: auth))
      assert conn.era == :modern

      assert_received {:challenge, @url, %{status: 401, www_authenticate: www_authenticate}}
      assert www_authenticate =~ "resource_metadata="

      assert {:ok, [_tool]} = Client.list_tools(conn)
      refute_received {:challenge, _, _}
    end

    test "returns the auth module's error when it can't refresh" do
      Process.put(:token, "stale")
      auth = {RefreshingAuth, key: :token}

      assert {:error, {:authorization_required, %{www_authenticate: "Bearer " <> _}}} =
               Client.connect(server(guarded("fresh"), auth: auth))
    end

    test "returns the auth module's error without sending a request" do
      auth = {RefreshingAuth, key: :missing_token}

      assert {:error, {:authorization_required, %{}}} =
               Client.connect(server(router(), auth: auth))

      assert requests() == []
    end

    test "without auth, a 401 is an HTTP error carrying the challenge" do
      assert {:error, {:http_error, 401, "Bearer resource_metadata=" <> _}} =
               Client.connect(server(guarded("fresh")))
    end

    test "sends static headers" do
      plug = fn conn ->
        assert get_req_header(conn, "x-api-key") == ["secret"]
        router().(conn)
      end

      assert {:ok, _conn} =
               Client.connect(server(plug, headers: fn -> [{"x-api-key", "secret"}] end))
    end

    test "doesn't follow redirects" do
      test_pid = self()

      plug = fn conn ->
        send(test_pid, {:request, conn.host})

        conn
        |> put_resp_header("location", "https://elsewhere.example/mcp")
        |> send_resp(307, "")
      end

      assert {:error, {:http_error, 307, _}} =
               Client.connect(server(plug, headers: [{"x-api-key", "secret"}]))

      assert_received {:request, "mcp.example.com"}
      refute_received {:request, "elsewhere.example"}
    end

    test "inspect leaves out headers, auth, and Req options" do
      server =
        server(router(),
          headers: [{"x-api-key", "secret"}],
          auth: {RefreshingAuth, key: :token, refresh_to: "secret"}
        )

      refute inspect(server) =~ "secret"
      refute inspect(%AshAi.Mcp.Client.Connection{server: server}) =~ "secret"
    end
  end

  test "takes clientInfo and capabilities as JSON objects" do
    server =
      Client.server(
        name: "test",
        url: @url,
        client_info: %{"name" => "my_app", "version" => "1.0.0"},
        capabilities: %{"roots" => %{}}
      )

    assert server.client_info == %{"name" => "my_app", "version" => "1.0.0"}
  end

  describe "req_llm_tools/3" do
    test "names tools after the server and sanitizes them deterministically" do
      assert Client.tool_name("linear", "create_issue") == "mcp__linear__create_issue"
      assert Client.tool_name("linear", "get-team") == "mcp__linear__get-team"

      dotted = Client.tool_name("linear", "admin.tools.list")
      assert dotted =~ ~r/^mcp__linear__admin_tools_list_[0-9a-f]{8}$/
      assert dotted == Client.tool_name("linear", "admin.tools.list")
      refute dotted == Client.tool_name("linear", "admin_tools.list")

      long = Client.tool_name("a-server-with-a-long-name", String.duplicate("very_long_", 8))
      assert byte_size(long) == 64
      assert ReqLLM.Tool.valid_name?(long)

      assert ReqLLM.Tool.valid_name?(Client.tool_name("srv", "trailing-"))
      assert ReqLLM.Tool.valid_name?(Client.tool_name("srv", "double--hyphen"))
      assert ReqLLM.Tool.valid_name?(Client.tool_name("srv", "spaces and ünïcode"))
    end

    test "drops schema keywords providers reject, keeping property names and data" do
      definition = %{
        "name" => "search",
        "inputSchema" => %{
          "$schema" => "http://json-schema.org/draft-07/schema#",
          "type" => "object",
          "x-vendor" => true,
          "properties" => %{
            "region" => %{"type" => "string", "x-mcp-header" => "Region"},
            "x-custom" => %{"type" => "string", "default" => %{"x-kept" => 1}},
            "tags" => %{"type" => "array", "items" => %{"type" => "string", "x-hint" => "tag"}}
          },
          "anyOf" => [%{"required" => ["region"], "x-note" => "either"}]
        }
      }

      {:ok, conn} = Client.connect(server(router(), protocol_version: "2026-07-28"))
      [{tool, _callback}] = Client.req_llm_tools(conn, [definition])

      assert tool.parameter_schema == %{
               "type" => "object",
               "properties" => %{
                 "region" => %{"type" => "string"},
                 "x-custom" => %{"type" => "string", "default" => %{"x-kept" => 1}},
                 "tags" => %{"type" => "array", "items" => %{"type" => "string"}}
               },
               "anyOf" => [%{"required" => ["region"]}]
             }
    end

    test "builds sorted ReqLLM tools whose callbacks call the server" do
      {:ok, conn} = Client.connect(server(router()))
      {:ok, definitions} = Client.list_tools(conn)

      extra = %{
        "name" => "aaa",
        "description" => "Sorts first.",
        "inputSchema" => %{"type" => "object"}
      }

      assert [{first, _}, {tool, callback}] =
               Client.req_llm_tools(conn, definitions ++ [extra],
                 provider_options: [anthropic: [defer_loading: true]]
               )

      assert first.name == "mcp__test__aaa"
      assert tool.name == "mcp__test__echo"
      assert tool.description == "Echo a message back."
      assert tool.parameter_schema == hd(definitions)["inputSchema"]
      assert tool.strict == false
      assert ReqLLM.Tool.provider_options(tool, :anthropic) == %{defer_loading: true}

      assert {:ok, text} = callback.(%{"input" => %{"message" => "via tool"}}, %{})
      assert text =~ "echo: via tool"

      assert {:ok, text} = ReqLLM.Tool.execute(tool, %{"input" => %{"message" => "direct"}})
      assert text =~ "echo: direct"
    end

    test "works as ToolLoop extra_tools" do
      {:ok, conn} = Client.connect(server(router()))
      {:ok, definitions} = Client.list_tools(conn)

      {_tools, registry} =
        AshAi.Tools.build_tools_and_registry(
          extra_tools: Client.req_llm_tools(conn, definitions),
          tools: false
        )

      assert {:ok, normalized, _raw} =
               registry["mcp__test__echo"].(%{"input" => %{"message" => "loop"}}, %{})

      assert normalized =~ "echo: loop"
    end

    test "maps error results, transport failures, and non-text content" do
      plug =
        fake(fn conn, message ->
          case {message["method"], get_in(message, ["params", "name"])} do
            {"server/discover", _} ->
              discover_result(conn, message)

            {"tools/call", "fails"} ->
              result(conn, message, %{
                "content" => [%{"type" => "text", "text" => "bad date"}],
                "isError" => true
              })

            {"tools/call", "image"} ->
              result(conn, message, %{
                "content" => [
                  %{"type" => "text", "text" => "here"},
                  %{"type" => "image", "data" => Base.encode64(@png), "mimeType" => "image/png"}
                ]
              })

            {"tools/call", "structured"} ->
              result(conn, message, %{"content" => [], "structuredContent" => %{"n" => 1}})

            {"tools/call", "broken"} ->
              send_resp(conn, 500, "kaboom")
          end
        end)

      {:ok, conn} = Client.connect(server(plug))

      definitions =
        for name <- ~w(fails image structured broken),
            do: %{"name" => name, "inputSchema" => %{"type" => "object"}}

      callbacks =
        conn
        |> Client.req_llm_tools(definitions)
        |> Map.new(fn {tool, callback} -> {tool.name, callback} end)

      assert {:error, "bad date"} = callbacks["mcp__test__fails"].(%{}, %{})

      assert {:ok, [text, image]} = callbacks["mcp__test__image"].(%{}, %{})
      assert %ReqLLM.Message.ContentPart{type: :text, text: "here"} = text

      assert %ReqLLM.Message.ContentPart{type: :image, data: @png, media_type: "image/png"} =
               image

      assert {:ok, ~s({"n":1})} = callbacks["mcp__test__structured"].(%{}, %{})

      assert {:error, error} = callbacks["mcp__test__broken"].(%{}, %{})
      assert Jason.decode!(error) == %{"error" => "The test MCP server answered with HTTP 500"}
    end

    test "looks up annotations by ReqLLM tool name" do
      definitions = [
        %{"name" => "delete_issue", "annotations" => %{"destructiveHint" => true}},
        %{name: "list_issues", annotations: %{readOnlyHint: true}}
      ]

      server = Client.server(name: "linear", url: @url)

      assert Client.annotations(server, definitions, "mcp__linear__delete_issue") == %{
               "destructiveHint" => true
             }

      assert Client.annotations(server, definitions, "mcp__linear__list_issues") == %{
               "readOnlyHint" => true
             }

      assert Client.annotations(server, definitions, "mcp__linear__missing") == nil

      assert %{"mcp__linear__list_issues" => %{server: "linear", name: "list_issues"}} =
               Client.tool_info(server, definitions)
    end
  end

  describe "SSE parsing" do
    test "keeps incomplete events and split CRLFs for the next chunk" do
      assert {[], "data: one"} = SSE.parse("", "data: one")
      assert {[], "data: one\n\r"} = SSE.parse("", "data: one\r\n\r")
      assert {[%{data: "one", event: nil}], ""} = SSE.parse("", "data: one\r\n\r\n")

      # The held CR rejoins the LF that starts the next chunk
      assert {[], "data: one\r"} = SSE.parse("", "data: one\r")
      assert {[%{data: "one"}], ""} = SSE.parse("data: one\r", "\n\r\n")

      # An event can end with the LF that ended the previous chunk
      assert {[], "data: one\n"} = SSE.parse("", "data: one\n")
      assert {[%{data: "one"}], "x"} = SSE.parse("data: one\n", "\nx")
    end

    test "joins multi-line data and ignores comments and empty events" do
      assert {[%{data: "a\nb", event: "message", id: "7"}], "rest"} =
               SSE.parse("", ": hi\n\nevent: message\nid: 7\ndata: a\ndata:b\n\nrest")
    end

    test "parses an event that arrives a byte at a time" do
      bytes = "event: message\r\ndata: hello\r\n\r\n"

      {events, rest} =
        bytes
        |> :binary.bin_to_list()
        |> Enum.reduce({[], ""}, fn byte, {events, rest} ->
          {new, rest} = SSE.parse(rest, <<byte>>)
          {events ++ new, rest}
        end)

      assert [%{event: "message", data: "hello"}] = events
      assert rest == ""
    end
  end

  describe "untrustworthy servers" do
    test "malformed results are errors, and malformed entries are skipped" do
      plug =
        fake(fn conn, message ->
          case message["method"] do
            "server/discover" ->
              discover_result(conn, message)

            "tools/list" ->
              result(conn, message, %{"tools" => [1, "x", %{"name" => "ok"}]})

            "tools/call" ->
              json(conn, 200, %{"jsonrpc" => "2.0", "id" => message["id"], "result" => 5})
          end
        end)

      {:ok, conn} = Client.connect(server(plug))

      assert {:ok, [%{"name" => "ok"}]} = Client.list_tools(conn)
      assert {:error, {:invalid_response, "result"}} = Client.call_tool(conn, "ok", %{})
    end

    test "non-object messages in an event stream are skipped" do
      plug =
        fake(fn conn, message ->
          case message["method"] do
            "server/discover" ->
              discover_result(conn, message)

            "tools/list" ->
              response = %{
                "jsonrpc" => "2.0",
                "id" => message["id"],
                "result" => %{"tools" => []}
              }

              conn
              |> put_resp_content_type("text/event-stream")
              |> send_resp(200, "data: [1, \"x\"]\n\ndata: #{Jason.encode!(response)}\n\n")
          end
        end)

      {:ok, conn} = Client.connect(server(plug))
      assert {:ok, []} = Client.list_tools(conn)
    end

    test "server URLs must be absolute HTTPS, apart from local and allowed private hosts" do
      for url <- [
            "http://mcp.example.com/mcp",
            "https://user:secret@mcp.example.com/mcp",
            "https://mcp.example.com/mcp#fragment",
            "/mcp",
            "ftp://mcp.example.com"
          ] do
        assert_raise ArgumentError, fn -> Client.server(name: "test", url: url) end
      end

      assert %Client.Server{} = Client.server(name: "test", url: "http://localhost:4000/mcp")

      assert %Client.Server{} =
               Client.server(
                 name: "test",
                 url: "http://mcp.internal/mcp",
                 allowed_private_hosts: ["mcp.internal"]
               )
    end

    test "inspect leaves out a connection's session id" do
      connection = %AshAi.Mcp.Client.Connection{server: server(router()), session_id: "s3cr3t"}
      refute inspect(connection) =~ "s3cr3t"
    end
  end

  describe "format_result/1" do
    alias ReqLLM.Message.ContentPart

    defp format(content, opts \\ []) do
      Client.format_result(%{
        content: content,
        structured_content: opts[:structured],
        is_error: Keyword.get(opts, :error, false)
      })
    end

    defp image(data, type \\ "image/png"),
      do: %{"type" => "image", "data" => Base.encode64(data), "mimeType" => type}

    test "keeps text-only results as text" do
      assert {:ok, "a\nb"} =
               format([%{"type" => "text", "text" => "a"}, %{"type" => "text", "text" => "b"}])

      assert {:ok, ~s({"n":1})} = format([], structured: %{"n" => 1})
    end

    test "returns images as image parts, with runs of text joined" do
      assert {:ok, [first, png, last]} =
               format([
                 %{"type" => "text", "text" => "a"},
                 %{"type" => "text", "text" => "b"},
                 image(@png),
                 %{"type" => "text", "text" => "c"}
               ])

      assert %ContentPart{type: :text, text: "a\nb"} = first
      assert %ContentPart{type: :image, data: @png, media_type: "image/png"} = png
      assert %ContentPart{type: :text, text: "c"} = last
    end

    test "returns embedded image resources as image parts" do
      resource = %{
        "type" => "resource",
        "resource" => %{
          "uri" => "file:///chart.webp",
          "mimeType" => "image/webp",
          "blob" => Base.encode64(@webp)
        }
      }

      assert {:ok, [%ContentPart{type: :image, data: @webp, media_type: "image/webp"}]} =
               format([resource])
    end

    test "describes images it can't pass on, audio, and other binary resources" do
      oversized = image(:binary.copy("x", 3_750_001))
      svg = image("<svg/>", "image/svg+xml")
      invalid = %{"type" => "image", "data" => "not base64!", "mimeType" => "image/png"}
      audio = %{"type" => "audio", "data" => Base.encode64("wav"), "mimeType" => "audio/wav"}

      pdf = %{
        "type" => "resource",
        "resource" => %{
          "uri" => "file:///a.pdf",
          "mimeType" => "application/pdf",
          "blob" => "AA=="
        }
      }

      for block <- [oversized, svg, invalid, audio, pdf] do
        assert {:ok, text} = format([block])
        assert text =~ "binary content omitted"
        refute text =~ ~s("data")
        refute text =~ ~s("blob")
      end
    end

    test "types images by their contents, not the type the server gave" do
      assert {:ok, [%ContentPart{type: :image, media_type: "image/png"}]} =
               format([image(@png, "image/jpeg")])

      # Data that isn't an image would fail every request that replays it
      assert {:ok, text} = format([image("not a png", "image/png")])
      assert Jason.decode!(text)["note"] == "binary content omitted"
    end

    test "describes images in error results" do
      assert {:error, text} = format([image(@png)], error: true)
      assert Jason.decode!(text)["note"] == "binary content omitted"
    end
  end

  describe "header values" do
    test "uses the Base64 sentinel only when needed" do
      assert Headers.encode_value("us-west1") == "us-west1"
      assert Headers.encode_value(" padded ") == "=?base64?IHBhZGRlZCA=?="
      assert Headers.encode_value("line1\nline2") == "=?base64?bGluZTEKbGluZTI=?="
      assert Headers.encode_value("=?base64?literal?=") == "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?="
    end

    test "rejects duplicate and non-primitive annotations" do
      duplicate = %{
        "properties" => %{
          "a" => %{"type" => "string", "x-mcp-header" => "Region"},
          "b" => %{"type" => "string", "x-mcp-header" => "region"}
        }
      }

      assert {:error, _} = Headers.params(duplicate)

      number = %{"properties" => %{"a" => %{"type" => "number", "x-mcp-header" => "N"}}}
      assert {:error, _} = Headers.params(number)

      named_like_annotation = %{"properties" => %{"x-mcp-header" => %{"type" => "string"}}}
      assert {:ok, []} = Headers.params(named_like_annotation)
    end
  end
end
