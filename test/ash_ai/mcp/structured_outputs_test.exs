# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.StructuredOutputsTest do
  use ExUnit.Case, async: true
  import Plug.{Conn, Test}

  alias AshAi.Mcp.Router

  defmodule Result do
    use Ash.TypedStruct

    typed_struct do
      field :created_at, :utc_datetime, allow_nil?: false
      field :status, :atom, allow_nil?: false, constraints: [one_of: [:ready, :pending]]
    end
  end

  defmodule DiscoveryOnly do
    use Ash.Policy.SimpleCheck

    def match?(_actor, %{context: %{private: %{ash_ai_pre_check?: true}}}, _opts), do: true
    def match?(_actor, _context, _opts), do: false
    def describe(_opts), do: "allowed only during tool discovery"
  end

  defmodule Resource do
    use Ash.Resource,
      domain: AshAi.Mcp.StructuredOutputsTest.Domain,
      authorizers: [Ash.Policy.Authorizer],
      data_layer: Ash.DataLayer.Ets

    ets do
      private? true
    end

    attributes do
      uuid_primary_key :id
      attribute :name, :string, public?: true, allow_nil?: false
    end

    actions do
      create :create_record do
        accept [:name]
      end

      action :typed_result, Result do
        run fn _input, _context ->
          send(self(), :typed_result_executed)
          {:ok, Result.new!(%{created_at: ~U[2026-08-11 12:30:00Z], status: :ready})}
        end
      end

      action :map_result, :map do
        run fn _input, _context -> {:ok, %{runtime: "shape"}} end
      end

      action :scalar_result, :string do
        run fn _input, _context -> {:ok, "scalar"} end
      end

      action :array_result, {:array, :integer} do
        run fn _input, _context -> {:ok, [1, 2]} end
      end

      action :nil_result, :map do
        allow_nil? true
        run fn _input, _context -> {:ok, nil} end
      end

      action :unencodable_result, :map do
        run fn _input, _context -> {:ok, %{pid: self()}} end
      end

      action :failing_result, :map do
        run fn _input, _context -> {:error, "failed intentionally"} end
      end

      action :cast_failure, :map do
        argument :count, :integer, allow_nil?: false
        run fn _input, _context -> {:error, "should not execute"} end
      end

      action :protected_result, :map do
        run fn _input, _context -> {:error, "should not execute"} end
      end
    end

    policies do
      policy action(:protected_result) do
        authorize_if DiscoveryOnly
      end

      policy always() do
        authorize_if always()
      end
    end
  end

  defmodule Domain do
    use Ash.Domain, extensions: [AshAi]

    resources do
      resource Resource
    end

    tools do
      tool :typed_result, Resource, :typed_result,
        _meta: %{"ui" => %{"resourceUri" => "ui://example/result.html"}}

      tool :create_record, Resource, :create_record
      tool :map_result, Resource, :map_result
      tool :scalar_result, Resource, :scalar_result
      tool :array_result, Resource, :array_result
      tool :nil_result, Resource, :nil_result
      tool :unencodable_result, Resource, :unencodable_result
      tool :failing_result, Resource, :failing_result
      tool :cast_failure, Resource, :cast_failure
      tool :protected_result, Resource, :protected_result
    end
  end

  @opts [actions: [{Resource, :*}], mcp_resources: []]

  describe "initialize-based public router" do
    test "returns serialized JSON objects as structured content and preserves text" do
      session_id = initialize()
      tools = session_id |> request("tools/list", %{}) |> result() |> Map.fetch!("tools")
      typed_tool = find_tool(tools, "typed_result")

      assert typed_tool["_meta"]["ui"]["resourceUri"] == "ui://example/result.html"

      typed_result = call_tool(session_id, "typed_result")
      [%{"type" => "text", "text" => typed_text}] = typed_result["content"]

      assert typed_result["isError"] == false
      assert typed_result["_meta"] == typed_tool["_meta"]
      assert typed_result["structuredContent"] == Jason.decode!(typed_text)
      assert typed_result["structuredContent"]["status"] == "ready"
      assert typed_result["structuredContent"]["created_at"] == "2026-08-11T12:30:00Z"
      assert_received :typed_result_executed
      refute_received :typed_result_executed

      map_result = call_tool(session_id, "map_result")
      [%{"type" => "text", "text" => map_text}] = map_result["content"]
      assert map_result["structuredContent"] == Jason.decode!(map_text)

      create_result =
        call_tool(session_id, "create_record", %{"input" => %{"name" => "created"}})

      [%{"type" => "text", "text" => create_text}] = create_result["content"]
      assert create_result["structuredContent"] == Jason.decode!(create_text)
      assert create_result["structuredContent"]["name"] == "created"
    end

    test "preserves text-only behavior for non-object results" do
      session_id = initialize()

      for name <- ["scalar_result", "array_result", "nil_result"] do
        call_result = call_tool(session_id, name)

        assert call_result["isError"] == false
        assert [%{"type" => "text", "text" => _text}] = call_result["content"]
        refute Map.has_key?(call_result, "structuredContent")
      end
    end

    test "casting, authorization, and execution errors never contain structured content" do
      session_id = initialize()

      calls = [
        {"cast_failure", %{"input" => %{"count" => "not-an-integer"}}},
        {"protected_result", %{}},
        {"failing_result", %{}},
        {"unencodable_result", %{}}
      ]

      for {name, arguments} <- calls do
        call_result = call_tool(session_id, name, arguments)

        assert call_result["isError"] == true,
               "expected #{name} to return a tool error, got: #{inspect(call_result)}"

        refute Map.has_key?(call_result, "structuredContent")
      end
    end
  end

  describe "2026-07-28 public router" do
    test "returns the same structured content without a session" do
      call_result =
        per_request("tools/call", %{"name" => "map_result", "arguments" => %{}})
        |> result()

      [%{"text" => text}] = call_result["content"]
      assert call_result["structuredContent"] == Jason.decode!(text)
    end
  end

  defp initialize do
    response =
      conn(:post, "/", %{
        "jsonrpc" => "2.0",
        "id" => "init",
        "method" => "initialize",
        "params" => %{"protocolVersion" => "2025-06-18", "capabilities" => %{}}
      })
      |> Router.call(@opts)

    response
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

  defp per_request(method, params) do
    params = Map.put(params, "_meta", request_meta())

    conn(:post, "/", %{"jsonrpc" => "2.0", "id" => method, "method" => method, "params" => params})
    |> put_req_header("mcp-protocol-version", "2026-07-28")
    |> put_req_header("mcp-method", method)
    |> put_req_header("mcp-name", params["name"])
    |> Router.call(@opts)
  end

  defp request_meta do
    %{
      "io.modelcontextprotocol/protocolVersion" => "2026-07-28",
      "io.modelcontextprotocol/clientCapabilities" => %{},
      "io.modelcontextprotocol/clientInfo" => %{"name" => "test", "version" => "1"}
    }
  end

  defp result(response), do: Jason.decode!(response.resp_body)["result"]
  defp find_tool(tools, name), do: Enum.find(tools, &(&1["name"] == name))
end
