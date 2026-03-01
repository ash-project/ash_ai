# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.ReqLLMToolTest do
  use ExUnit.Case, async: true
  alias __MODULE__.{TestDomain, TestResource}

  defmodule TestResource do
    use Ash.Resource, domain: TestDomain, data_layer: Ash.DataLayer.Ets

    attributes do
      uuid_v7_primary_key(:id, writable?: true)
      attribute :name, :string, public?: true, allow_nil?: false
      attribute :status, :string, public?: true
    end

    actions do
      defaults([:read, :create, :update, :destroy])
      default_accept([:id, :name, :status])

      action :custom_action, :string do
        argument :message, :string, allow_nil?: false

        run(fn input, _context ->
          {:ok, "Processed: #{input.arguments.message}"}
        end)
      end
    end
  end

  defmodule TestDomain do
    use Ash.Domain, extensions: [AshAi]

    resources do
      resource TestResource
    end

    tools do
      tool :read_test_resources, TestResource, :read
      tool :create_test_resource, TestResource, :create
      tool :update_test_resource, TestResource, :update
      tool :destroy_test_resource, TestResource, :destroy
      tool :custom_test_action, TestResource, :custom_action
    end
  end

  describe "AshAi.Tools.build/2" do
    test "creates valid ReqLLM.Tool and callback from AshAi tool definition" do
      tool_def =
        AshAi.exposed_tools(actions: [{TestResource, :*}])
        |> Enum.find(&(&1.name == :read_test_resources))

      {req_tool, callback} = AshAi.Tools.build(tool_def)

      assert %ReqLLM.Tool{} = req_tool
      assert req_tool.name == "read_test_resources"
      assert is_binary(req_tool.description)
      assert is_map(req_tool.parameter_schema)
      assert is_function(callback, 2)
    end
  end

  describe "list_tools/1 and registry" do
    test "returns all exposed ReqLLM tools" do
      tools = AshAi.list_tools(actions: [{TestResource, :*}])
      tool_names = Enum.map(tools, & &1.name)

      assert "read_test_resources" in tool_names
      assert "create_test_resource" in tool_names
      assert "update_test_resource" in tool_names
      assert "destroy_test_resource" in tool_names
      assert "custom_test_action" in tool_names
    end

    test "build_tools_and_registry returns callbacks keyed by tool name" do
      {tools, registry} = AshAi.build_tools_and_registry(actions: [{TestResource, :*}])

      assert length(tools) == map_size(registry)
      assert is_function(registry["read_test_resources"], 2)
      assert is_function(registry["custom_test_action"], 2)
    end
  end

  describe "tool callback execution" do
    test "executes read action and returns JSON result" do
      {:ok, _resource} =
        TestResource
        |> Ash.Changeset.for_create(:create, %{name: "Test Item", status: "active"})
        |> Ash.create(domain: TestDomain)

      {_tools, registry} = AshAi.build_tools_and_registry(actions: [{TestResource, :*}])

      {:ok, result, _raw} = registry["read_test_resources"].(%{}, context())

      assert is_binary(result)
      assert {:ok, decoded} = Jason.decode(result)
      assert is_list(decoded)
    end

    test "executes create action" do
      {_tools, registry} = AshAi.build_tools_and_registry(actions: [{TestResource, :*}])

      {:ok, result, _raw} =
        registry["create_test_resource"].(%{"input" => %{"name" => "New Item"}}, context())

      assert {:ok, decoded} = Jason.decode(result)
      assert decoded["name"] == "New Item"
    end

    test "executes custom action" do
      {_tools, registry} = AshAi.build_tools_and_registry(actions: [{TestResource, :*}])

      {:ok, result, _raw} =
        registry["custom_test_action"].(%{"input" => %{"message" => "Hello"}}, context())

      assert result == "\"Processed: Hello\""
    end

    test "handles nil arguments" do
      {:ok, _resource} =
        TestResource
        |> Ash.Changeset.for_create(:create, %{name: "Test for nil args"})
        |> Ash.create(domain: TestDomain)

      {_tools, registry} = AshAi.build_tools_and_registry(actions: [{TestResource, :*}])
      {:ok, result, _raw} = registry["read_test_resources"].(nil, context())
      assert is_binary(result)
    end

    test "returns JSON:API-style errors for invalid tool input" do
      {_tools, registry} = AshAi.build_tools_and_registry(actions: [{TestResource, :*}])

      assert {:error, json_error} =
               registry["create_test_resource"].(%{"input" => %{}}, context())

      assert {:ok, [first_error | _]} = Jason.decode(json_error)
      assert first_error["status"] == "400"
      assert is_binary(first_error["detail"])
    end
  end

  describe "options validation" do
    test "model option defaults to openai:gpt-4o-mini" do
      opts = AshAi.Options.validate!(actions: [{TestResource, :*}])
      assert opts.model == "openai:gpt-4o-mini"
    end

    test "model option can be overridden" do
      opts =
        AshAi.Options.validate!(
          actions: [{TestResource, :*}],
          model: "anthropic:claude-haiku-4-5"
        )

      assert opts.model == "anthropic:claude-haiku-4-5"
    end

    test "req_llm option defaults to ReqLLM module" do
      opts = AshAi.Options.validate!(actions: [{TestResource, :*}])
      assert opts.req_llm == ReqLLM
    end

    test "max_iterations accepts :infinity" do
      opts = AshAi.Options.validate!(actions: [{TestResource, :*}], max_iterations: :infinity)
      assert opts.max_iterations == :infinity
    end

    test "max_iterations defaults to 10 when not set" do
      opts = AshAi.Options.validate!(actions: [{TestResource, :*}])
      assert opts.max_iterations == 10
    end
  end

  defp context do
    %{actor: nil, tenant: nil, context: %{}, tool_callbacks: %{}}
  end
end
