# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.LiveLLM.ToolCallingTest do
  @moduledoc """
  Live integration tests for tool calling with real LLM providers.

  These tests verify that the ToolLoop correctly:
  - Builds tools from Ash actions
  - Sends tool schemas to LLMs
  - Processes tool calls from LLM responses
  - Executes Ash actions and returns results
  """
  use AshAi.LiveLLMCase, async: false

  alias AshAi.ToolLoop
  alias ReqLLM.Context

  defmodule Item do
    use Ash.Resource,
      domain: AshAi.LiveLLM.ToolCallingTest.TestDomain,
      data_layer: Ash.DataLayer.Ets

    attributes do
      uuid_v7_primary_key(:id, writable?: true)
      attribute :name, :string, public?: true, allow_nil?: false
      attribute :category, :string, public?: true
    end

    actions do
      defaults [:read, :create, :destroy]
      default_accept [:id, :name, :category]
    end
  end

  defmodule TestDomain do
    use Ash.Domain, extensions: [AshAi]

    resources do
      resource Item
    end

    tools do
      tool :list_items, Item, :read do
        description "List all items in the inventory"
      end

      tool :create_item, Item, :create do
        description "Create a new item with a name and optional category"
      end

      tool :delete_item, Item, :destroy do
        description "Delete an item by its ID"
      end
    end
  end

  setup do
    :ok
  end

  describe "OpenAI tool calling" do
    @tag :live_llm
    @tag live_llm: :openai
    test "single tool call - list items" do
      require_provider!(:openai)

      {:ok, _} =
        Item
        |> Ash.Changeset.for_create(:create, %{name: "Test Widget", category: "gadgets"})
        |> Ash.create(domain: TestDomain)

      messages = [
        Context.system(
          "You are a helpful inventory assistant. Use the available tools to answer questions."
        ),
        Context.user("What items are in the inventory?")
      ]

      {:ok, result} =
        ToolLoop.run(messages,
          actions: [{Item, :*}],
          model: @openai_model
        )

      assert result.iterations >= 1
      assert result.tool_calls_made != []

      tool_names = Enum.map(result.tool_calls_made, & &1.name)
      assert "list_items" in tool_names

      assert result.final_text =~ "Widget" or result.final_text =~ "gadget" or
               result.final_text =~ "item"
    end

    @tag :live_llm
    @tag live_llm: :openai
    test "create item tool call" do
      require_provider!(:openai)

      messages = [
        Context.system(
          "You are a helpful inventory assistant. Use the create_item tool to create items. After creating, respond with what you created."
        ),
        Context.user("Create an item called 'Magic Hammer' in the 'tools' category.")
      ]

      result =
        ToolLoop.run(messages,
          actions: [{Item, :*}],
          model: @openai_model
        )

      items = Ash.read!(Item, domain: TestDomain)

      assert Enum.any?(items, &(&1.name == "Magic Hammer")),
             "Item 'Magic Hammer' should have been created. Result: #{inspect(result)}"
    end

    @tag :live_llm
    @tag live_llm: :openai
    test "handles tool with no results gracefully" do
      require_provider!(:openai)

      messages = [
        Context.system("You are a helpful inventory assistant."),
        Context.user("List all items in the inventory.")
      ]

      {:ok, result} =
        ToolLoop.run(messages,
          actions: [{Item, :*}],
          model: @openai_model
        )

      assert result.iterations >= 1

      assert result.final_text =~ ~r/no items|empty|nothing/i or result.tool_calls_made != []
    end
  end

  describe "Anthropic tool calling" do
    @tag :live_llm
    @tag live_llm: :anthropic
    test "single tool call - list items" do
      require_provider!(:anthropic)

      {:ok, _} =
        Item
        |> Ash.Changeset.for_create(:create, %{name: "Anthropic Widget", category: "ai"})
        |> Ash.create(domain: TestDomain)

      messages = [
        Context.system(
          "You are a helpful inventory assistant. Use the available tools to answer questions."
        ),
        Context.user("What items are in the inventory?")
      ]

      {:ok, result} =
        ToolLoop.run(messages,
          actions: [{Item, :*}],
          model: @anthropic_model
        )

      assert result.iterations >= 1
      assert result.tool_calls_made != []

      tool_names = Enum.map(result.tool_calls_made, & &1.name)
      assert "list_items" in tool_names
    end

    @tag :live_llm
    @tag live_llm: :anthropic
    test "create item tool call" do
      require_provider!(:anthropic)

      messages = [
        Context.system(
          "You are a helpful inventory assistant. Use the create_item tool to create items. After creating, respond with what you created."
        ),
        Context.user("Create an item called 'Claude Pen' in the 'writing' category.")
      ]

      result =
        ToolLoop.run(messages,
          actions: [{Item, :*}],
          model: @anthropic_model
        )

      items = Ash.read!(Item, domain: TestDomain)

      assert Enum.any?(items, &(&1.name == "Claude Pen")),
             "Item 'Claude Pen' should have been created. Result: #{inspect(result)}"
    end
  end

  describe "tool callbacks" do
    @tag :live_llm
    @tag live_llm: :openai
    test "on_tool_start and on_tool_end are called" do
      require_provider!(:openai)

      test_pid = self()

      {:ok, _} =
        Item
        |> Ash.Changeset.for_create(:create, %{name: "Callback Test Item"})
        |> Ash.create(domain: TestDomain)

      messages = [
        Context.system("You are a helpful assistant."),
        Context.user("List all items.")
      ]

      {:ok, _result} =
        ToolLoop.run(messages,
          actions: [{Item, :*}],
          model: @openai_model,
          on_tool_start: fn event ->
            send(test_pid, {:tool_start, event.tool_name})
          end,
          on_tool_end: fn event ->
            send(test_pid, {:tool_end, event.tool_name})
          end
        )

      assert_receive {:tool_start, "list_items"}, 30_000
      assert_receive {:tool_end, "list_items"}, 30_000
    end
  end
end
