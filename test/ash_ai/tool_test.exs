defmodule AshAi.ToolTest do
  use ExUnit.Case, async: true
  alias AshAi.ChatFaker
  alias LangChain.Chains.LLMChain
  alias LangChain.Message
  alias __MODULE__.{TestDomain, TestResource}

  defmodule TestResource do
    use Ash.Resource, domain: TestDomain, data_layer: Ash.DataLayer.Ets

    attributes do
      uuid_v7_primary_key(:id, writable?: true)

      # Public attributes
      attribute :public_name, :string, public?: true
      attribute :public_email, :string, public?: true

      # Private attributes (default is public?: false)
      attribute :private_notes, :string
      attribute :internal_status, :string
    end

    actions do
      defaults [:read, :create]
      default_accept [:id, :public_name, :public_email, :private_notes, :internal_status]
    end
  end

  defmodule TestDomain do
    use Ash.Domain, extensions: [AshAi]

    resources do
      resource TestResource
    end

    tools do
      tool :read_test_resources, TestResource, :read, load: [:internal_status]
    end
  end

  describe "tool response" do
    setup do
      # Create test data with both public and private attributes
      resource =
        TestResource
        |> Ash.Changeset.for_create(:create, %{
          id: "0197b375-4daa-7112-a9d8-7f0104485646",
          public_name: "John Doe",
          public_email: "john@example.com",
          private_notes: "Secret internal notes",
          internal_status: "classified"
        })
        |> Ash.create!(domain: TestDomain)

      {:ok, resource: resource}
    end

    test "includes public and loaded fields" do
      tool_call = %LangChain.Message.ToolCall{
        status: :complete,
        type: :function,
        call_id: "call_id",
        name: "read_test_resources",
        arguments: %{},
        index: 0
      }

      {:ok, chain} = chain() |> run_chain(tool_call)

      tool_result =
        chain.messages
        |> Enum.find(&(is_nil(&1.tool_results) == false))
        |> Map.get(:tool_results)
        |> Enum.at(0)

      # ID is included because it's a primary key
      # Public name and email are included because they're public attributes
      # Internal status is included because it's a loaded field
      assert tool_result.content ==
               "[{\"id\":\"0197b375-4daa-7112-a9d8-7f0104485646\",\"public_name\":\"John Doe\",\"public_email\":\"john@example.com\",\"internal_status\":\"classified\"}]"
    end

    test "handles nil arguments from LangChain/MCP clients" do
      # Simulate LangChain/MCP sending nil instead of empty map
      tool_call = %LangChain.Message.ToolCall{
        status: :complete,
        type: :function,
        call_id: "call_id",
        name: "read_test_resources",
        arguments: nil,  # This is what some LangChain/MCP clients send
        index: 0
      }

      # Should not crash with BadMapError
      {:ok, chain} = chain() |> run_chain(tool_call)

      tool_result =
        chain.messages
        |> Enum.find(&(is_nil(&1.tool_results) == false))
        |> Map.get(:tool_results)
        |> Enum.at(0)

      # Should return the resource data without crashing
      assert tool_result.content ==
               "[{\"id\":\"0197b375-4daa-7112-a9d8-7f0104485646\",\"public_name\":\"John Doe\",\"public_email\":\"john@example.com\",\"internal_status\":\"classified\"}]"
    end
  end

  describe "tool parameter schema visibility" do
    test "filter parameters only include public attributes" do
      tool = get_test_tool()

      assert tool.name == "read_test_resources"
      filter_properties = tool.parameters_schema["properties"]["filter"]["properties"]

      # Public attributes are present
      assert Map.has_key?(filter_properties, "id")
      assert Map.has_key?(filter_properties, "public_name")
      assert Map.has_key?(filter_properties, "public_email")

      # Private attributes are not present
      refute Map.has_key?(filter_properties, "private_notes")
      refute Map.has_key?(filter_properties, "internal_status")
    end

    test "sort field options only include public attributes" do
      tool = get_test_tool()

      sort_field_enum =
        tool.parameters_schema["properties"]["sort"]["items"]["properties"]["field"]["enum"]

      # Public attributes are present
      assert "id" in sort_field_enum
      assert "public_name" in sort_field_enum
      assert "public_email" in sort_field_enum

      # Private attributes are not present
      refute "private_notes" in sort_field_enum
      refute "internal_status" in sort_field_enum
    end

    test "aggregate field options only include public attributes" do
      tool = get_test_tool()

      result_type_options = tool.parameters_schema["properties"]["result_type"]["oneOf"]

      aggregate_option =
        Enum.find(result_type_options, fn opt ->
          Map.has_key?(opt, "properties") && Map.has_key?(opt["properties"], "aggregate")
        end)

      aggregate_field_enum = aggregate_option["properties"]["field"]["enum"]

      # Public attributes are present
      assert "id" in aggregate_field_enum
      assert "public_name" in aggregate_field_enum
      assert "public_email" in aggregate_field_enum

      # Private attributes are not present
      refute "private_notes" in aggregate_field_enum
      refute "internal_status" in aggregate_field_enum
    end
  end

  defp chain do
    actions =
      AshAi.Info.tools(TestDomain)
      |> Enum.group_by(& &1.resource, & &1.action)
      |> Map.to_list()

    %{llm: ChatFaker.new!(%{})}
    |> LLMChain.new!()
    |> AshAi.setup_ash_ai(actions: actions)
  end

  defp run_chain(chain, tool_call) do
    chain
    |> LLMChain.add_message(Message.new_assistant!(%{status: :complete, tool_calls: [tool_call]}))
    |> LLMChain.run(mode: :while_needs_response)
  end

  defp get_test_tool do
    actions =
      AshAi.Info.tools(TestDomain)
      |> Enum.group_by(& &1.resource, & &1.action)
      |> Map.to_list()

    %{llm: ChatFaker.new!(%{})}
    |> LLMChain.new!()
    |> AshAi.setup_ash_ai(actions: actions)
    |> Map.get(:tools)
    |> Enum.at(0)
  end
end
