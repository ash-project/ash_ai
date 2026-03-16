# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.LiveLLM.StreamingTest do
  @moduledoc """
  Live integration tests for streaming with real LLM providers.

  These tests verify that ToolLoop.stream/2 correctly:
  - Streams content chunks as they arrive
  - Emits tool call events
  - Emits tool result events
  - Completes with a done event
  """
  use AshAi.LiveLLMCase, async: false

  alias AshAi.ToolLoop
  alias ReqLLM.Context

  defmodule StreamItem do
    use Ash.Resource,
      domain: AshAi.LiveLLM.StreamingTest.TestDomain,
      data_layer: Ash.DataLayer.Ets

    attributes do
      uuid_v7_primary_key(:id, writable?: true)
      attribute :name, :string, public?: true, allow_nil?: false
    end

    actions do
      defaults [:read, :create]
      default_accept [:id, :name]
    end
  end

  defmodule TestDomain do
    use Ash.Domain, extensions: [AshAi]

    resources do
      resource StreamItem
    end

    tools do
      tool :list_stream_items, StreamItem, :read do
        description "List all items"
      end

      tool :create_stream_item, StreamItem, :create do
        description "Create a new item with a name"
      end
    end
  end

  setup do
    :ok
  end

  describe "OpenAI streaming" do
    @tag :live_llm
    @tag live_llm: :openai
    test "streams content chunks" do
      require_provider!(:openai)

      messages = [
        Context.system("You are a helpful assistant. Give a brief response."),
        Context.user("Say hello in exactly 5 words.")
      ]

      stream =
        ToolLoop.stream(messages,
          actions: [{StreamItem, :*}],
          model: @openai_model
        )

      events = Enum.to_list(stream)

      content_events =
        Enum.filter(events, fn
          {:content, _} -> true
          _ -> false
        end)

      assert content_events != []

      done_events =
        Enum.filter(events, fn
          {:done, _} -> true
          _ -> false
        end)

      assert done_events |> Enum.take(2) |> length() == 1

      {:done, result} = List.last(events)
      assert %ToolLoop.Result{} = result
      assert result.final_text != ""
    end

    @tag :live_llm
    @tag live_llm: :openai
    test "streams tool call and result events" do
      require_provider!(:openai)

      {:ok, _} =
        StreamItem
        |> Ash.Changeset.for_create(:create, %{name: "Stream Test Item"})
        |> Ash.create(domain: TestDomain)

      messages = [
        Context.system("You are a helpful assistant. Use tools when needed."),
        Context.user("List all items.")
      ]

      stream =
        ToolLoop.stream(messages,
          actions: [{StreamItem, :*}],
          model: @openai_model
        )

      events = Enum.to_list(stream)

      tool_call_events =
        Enum.filter(events, fn
          {:tool_call, _} -> true
          _ -> false
        end)

      tool_result_events =
        Enum.filter(events, fn
          {:tool_result, _} -> true
          _ -> false
        end)

      assert tool_call_events != []
      assert tool_result_events != []

      {:tool_call, tool_call} = hd(tool_call_events)
      assert tool_call.name == "list_stream_items"

      {:tool_result, tool_result} = hd(tool_result_events)
      assert Map.has_key?(tool_result, :id)
      assert Map.has_key?(tool_result, :result)
    end

    @tag :live_llm
    @tag live_llm: :openai
    test "streams iteration events for multi-turn" do
      require_provider!(:openai)

      messages = [
        Context.system("You are a helpful assistant. Use tools to complete tasks."),
        Context.user("Create an item named 'Streamed Item' then list all items.")
      ]

      stream =
        ToolLoop.stream(messages,
          actions: [{StreamItem, :*}],
          model: @openai_model,
          max_iterations: 5
        )

      events = Enum.to_list(stream)

      iteration_events =
        Enum.filter(events, fn
          {:iteration, _} -> true
          _ -> false
        end)

      assert iteration_events != []

      {:done, result} = List.last(events)
      assert result.iterations >= 2
    end

    @tag :live_llm
    @tag live_llm: :openai
    test "can process stream with Enum.reduce" do
      require_provider!(:openai)

      messages = [
        Context.system("You are a helpful assistant."),
        Context.user("Say 'hello' and nothing else.")
      ]

      stream =
        ToolLoop.stream(messages,
          actions: [{StreamItem, :*}],
          model: @openai_model
        )

      {text, result} =
        Enum.reduce(stream, {"", nil}, fn event, {text, result} ->
          case event do
            {:content, chunk} -> {text <> chunk, result}
            {:done, r} -> {text, r}
            _ -> {text, result}
          end
        end)

      assert text != ""
      assert %ToolLoop.Result{} = result
    end
  end

  describe "Anthropic streaming" do
    @tag :live_llm
    @tag live_llm: :anthropic
    test "streams content chunks" do
      require_provider!(:anthropic)

      messages = [
        Context.system("You are a helpful assistant. Give a brief response."),
        Context.user("Say hello in exactly 5 words.")
      ]

      stream =
        ToolLoop.stream(messages,
          actions: [{StreamItem, :*}],
          model: @anthropic_model
        )

      events = Enum.to_list(stream)

      content_events =
        Enum.filter(events, fn
          {:content, _} -> true
          _ -> false
        end)

      assert content_events != []

      {:done, result} = List.last(events)
      assert %ToolLoop.Result{} = result
    end

    @tag :live_llm
    @tag live_llm: :anthropic
    test "streams tool call events" do
      require_provider!(:anthropic)

      {:ok, _} =
        StreamItem
        |> Ash.Changeset.for_create(:create, %{name: "Anthropic Stream Item"})
        |> Ash.create(domain: TestDomain)

      messages = [
        Context.system("You are a helpful assistant. Use tools when needed."),
        Context.user("List all items.")
      ]

      stream =
        ToolLoop.stream(messages,
          actions: [{StreamItem, :*}],
          model: @anthropic_model
        )

      events = Enum.to_list(stream)

      tool_call_events =
        Enum.filter(events, fn
          {:tool_call, _} -> true
          _ -> false
        end)

      assert tool_call_events != []
    end
  end
end
