# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.ResultMetaTest do
  use ExUnit.Case, async: true
  import ExUnit.CaptureLog
  import Plug.{Conn, Test}

  alias AshAi.Mcp.Router

  defmodule ViewMeta do
    use AshAi.Tool.ResultMeta

    @impl true
    def result_meta(result, opts, _context) do
      %{"com.example/view" => %{"label" => opts[:label], "title" => result.title}}
    end
  end

  defmodule Record do
    use Ash.Resource,
      domain: AshAi.Mcp.ResultMetaTest.Domain,
      data_layer: Ash.DataLayer.Ets

    ets do
      private? true
    end

    attributes do
      uuid_primary_key :id
      attribute :name, :string, public?: true, allow_nil?: false
    end

    actions do
      defaults [:read, create: [:name]]

      read :unpaged

      read :paged do
        pagination offset?: true, default_limit: 10
      end

      action :report, :map do
        argument :title, :string, allow_nil?: false
        run fn input, _context -> {:ok, %{title: input.arguments.title}} end
      end

      action :failing, :map do
        run fn _input, _context -> {:error, "failed intentionally"} end
      end
    end
  end

  defmodule Domain do
    use Ash.Domain, extensions: [AshAi]

    resources do
      resource Record
    end

    tools do
      tool :report, Record, :report,
        _meta: %{"ui" => %{"resourceUri" => "ui://example/report.html"}},
        result_meta: fn result, context ->
          send(self(), {:result_meta, result, context})
          %{"com.example/view" => %{"title" => result.title}, ui: %{label: "Report"}}
        end

      tool :report_module, Record, :report do
        result_meta {ViewMeta, label: "From module"}
      end

      tool :list_records, Record, :unpaged do
        result_meta fn records, _context ->
          %{"com.example/ids" => Enum.map(records, & &1.id)}
        end
      end

      tool :paged_records, Record, :paged do
        result_meta fn page, _context ->
          send(self(), {:result_meta, page})
          nil
        end
      end

      tool :raising, Record, :report,
        _meta: %{"ui" => %{"resourceUri" => "ui://example/report.html"}},
        result_meta: fn _result, _context -> raise "view exploded" end

      tool :bad_return, Record, :report do
        result_meta fn _result, _context -> [:not_a_map] end
      end

      tool :unencodable, Record, :report do
        result_meta fn _result, _context -> %{"pid" => self()} end
      end

      tool :failing, Record, :failing do
        result_meta fn result, _context ->
          send(self(), {:result_meta, result})
          %{}
        end
      end

      tool :plain, Record, :report
    end
  end

  @opts [actions: [{Record, :*}], mcp_resources: [], actor: %{id: "actor-1"}]
  @report_args %{"input" => %{"title" => "Q3"}}

  describe "initialize-based revisions" do
    test "deep-merges the callback's map over the static _meta" do
      result = call_tool(initialize(), "report", @report_args)

      assert result["isError"] == false
      [%{"text" => text}] = result["content"]
      assert Jason.decode!(text) == %{"title" => "Q3"}

      assert result["_meta"] == %{
               "ui" => %{"resourceUri" => "ui://example/report.html", "label" => "Report"},
               "com.example/view" => %{"title" => "Q3"}
             }
    end

    test "passes the unserialized result and the call's context" do
      call_tool(initialize(), "report", @report_args)

      assert_received {:result_meta, %{title: "Q3"}, %AshAi.Tool.ResultMeta.Context{} = context}
      assert context.tool.name == :report
      assert context.arguments == @report_args
      assert context.actor == %{id: "actor-1"}
      assert context.client_capabilities == nil
    end

    test "leaves tools/list unchanged" do
      tools = initialize() |> request("tools/list", %{}) |> result() |> Map.fetch!("tools")

      assert find_tool(tools, "report")["_meta"] == %{
               "ui" => %{"resourceUri" => "ui://example/report.html"}
             }

      refute Map.has_key?(find_tool(tools, "list_records"), "_meta")
    end

    test "calls a module with its options" do
      result = call_tool(initialize(), "report_module", @report_args)

      assert result["_meta"] == %{
               "com.example/view" => %{"label" => "From module", "title" => "Q3"}
             }
    end

    test "receives the records an unpaginated read returns" do
      record = create_record("first")

      result = call_tool(initialize(), "list_records")

      assert result["_meta"] == %{"com.example/ids" => [record.id]}
    end

    test "receives the page a paginated read returns, and nil adds nothing" do
      create_record("first")

      result = call_tool(initialize(), "paged_records")

      assert result["isError"] == false
      refute Map.has_key?(result, "_meta")
      assert_received {:result_meta, %Ash.Page.Offset{results: [%Record{name: "first"}]}}
    end

    test "a raising callback is logged and the result is sent without it" do
      session_id = initialize()

      log =
        capture_log(fn ->
          result = call_tool(session_id, "raising", @report_args)

          assert result["isError"] == false
          assert result["_meta"] == %{"ui" => %{"resourceUri" => "ui://example/report.html"}}
        end)

      assert log =~ "result_meta for tool :raising raised"
      assert log =~ "view exploded"
    end

    test "a non-map or unencodable return is logged and dropped" do
      session_id = initialize()

      for {tool, message} <- [
            {"bad_return", "must return a map or nil, got: [:not_a_map]"},
            {"unencodable", "returned a map that can't be JSON-encoded"}
          ] do
        log =
          capture_log(fn ->
            result = call_tool(session_id, tool, @report_args)

            assert result["isError"] == false
            refute Map.has_key?(result, "_meta")
          end)

        assert log =~ message
      end
    end

    test "is not called when the action fails" do
      result = call_tool(initialize(), "failing")

      assert result["isError"] == true
      refute Map.has_key?(result, "_meta")
      refute_received {:result_meta, _}
    end

    test "a tool without it or a static _meta sends no _meta" do
      result = call_tool(initialize(), "plain", @report_args)

      assert result["isError"] == false
      refute Map.has_key?(result, "_meta")
    end
  end

  describe "2026-07-28" do
    test "passes the request's client capabilities and keeps the server's _meta" do
      capabilities = %{
        "extensions" => %{
          "io.modelcontextprotocol/ui" => %{"mimeTypes" => ["text/html;profile=mcp-app"]}
        }
      }

      result =
        "tools/call"
        |> per_request(%{"name" => "report", "arguments" => @report_args}, capabilities)
        |> result()

      assert result["_meta"]["com.example/view"] == %{"title" => "Q3"}

      assert result["_meta"]["ui"] == %{
               "resourceUri" => "ui://example/report.html",
               "label" => "Report"
             }

      assert is_map(result["_meta"]["io.modelcontextprotocol/serverInfo"])
      assert_received {:result_meta, _, %{client_capabilities: ^capabilities}}
    end
  end

  defp create_record(name) do
    Record
    |> Ash.Changeset.for_create(:create, %{name: name})
    |> Ash.create!()
  end

  defp initialize do
    conn(:post, "/", %{
      "jsonrpc" => "2.0",
      "id" => "init",
      "method" => "initialize",
      "params" => %{"protocolVersion" => "2025-06-18", "capabilities" => %{}}
    })
    |> Router.call(@opts)
    |> get_resp_header("mcp-session-id")
    |> List.first()
  end

  defp request(session_id, method, params) do
    conn(:post, "/", %{"jsonrpc" => "2.0", "id" => method, "method" => method, "params" => params})
    |> put_req_header("mcp-session-id", session_id)
    |> Router.call(@opts)
  end

  defp call_tool(session_id, name, arguments \\ %{}) do
    session_id
    |> request("tools/call", %{"name" => name, "arguments" => arguments})
    |> result()
  end

  defp per_request(method, params, client_capabilities) do
    meta = %{
      "io.modelcontextprotocol/protocolVersion" => "2026-07-28",
      "io.modelcontextprotocol/clientCapabilities" => client_capabilities,
      "io.modelcontextprotocol/clientInfo" => %{"name" => "test", "version" => "1"}
    }

    params = Map.put(params, "_meta", meta)

    conn(:post, "/", %{"jsonrpc" => "2.0", "id" => method, "method" => method, "params" => params})
    |> put_req_header("mcp-protocol-version", "2026-07-28")
    |> put_req_header("mcp-method", method)
    |> put_req_header("mcp-name", params["name"])
    |> Router.call(@opts)
  end

  defp result(response), do: Jason.decode!(response.resp_body)["result"]
  defp find_tool(tools, name), do: Enum.find(tools, &(&1["name"] == name))
end
