# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.ToolLoopTest do
  use ExUnit.Case, async: true

  alias AshAi.ToolLoop
  alias ReqLLM.Context

  defmodule TestResource do
    use Ash.Resource,
      domain: AshAi.ToolLoopTest.TestDomain,
      data_layer: Ash.DataLayer.Ets

    ets do
      private?(true)
    end

    actions do
      default_accept([:*])

      action :echo, :string do
        argument :message, :string, allow_nil?: true

        run fn input, _ctx ->
          {:ok, "echo: #{input.arguments.message || "ok"}"}
        end
      end
    end
  end

  defmodule TestDomain do
    use Ash.Domain, extensions: [AshAi]

    resources do
      resource TestResource
    end

    tools do
      tool :echo_tool, TestResource, :echo
    end
  end

  defmodule FakeReqLLMStreamError do
    def stream_text(_model, _messages, _opts \\ []), do: {:error, :stream_failed}
  end

  defmodule FakeReqLLMMalformedToolArguments do
    def stream_text(_model, _messages, _opts \\ []) do
      count = Process.get({__MODULE__, :call_count}, 0)
      Process.put({__MODULE__, :call_count}, count + 1)

      if count == 0 do
        {:ok,
         %ReqLLM.StreamResponse{
           stream: [
             %ReqLLM.StreamChunk{
               type: :tool_call,
               name: "echo_tool",
               arguments: "{not_valid_json",
               metadata: %{}
             },
             ReqLLM.StreamChunk.meta(%{finish_reason: :tool_calls})
           ],
           metadata_handle: :ignored,
           cancel: fn -> :ok end,
           model: "openai:gpt-4o",
           context: ReqLLM.Context.new([])
         }}
      else
        {:ok,
         %ReqLLM.StreamResponse{
           stream: [
             ReqLLM.StreamChunk.text("done"),
             ReqLLM.StreamChunk.meta(%{finish_reason: :stop})
           ],
           metadata_handle: :ignored,
           cancel: fn -> :ok end,
           model: "openai:gpt-4o",
           context: ReqLLM.Context.new([])
         }}
      end
    end
  end

  defmodule FakeReqLLMCallIdOnly do
    def stream_text(_model, _messages, _opts \\ []) do
      count = Process.get({__MODULE__, :call_count}, 0)
      Process.put({__MODULE__, :call_count}, count + 1)

      if count == 0 do
        {:ok,
         %ReqLLM.StreamResponse{
           stream: [
             ReqLLM.StreamChunk.tool_call("echo_tool", %{"input" => %{"message" => "hi"}}, %{
               "call_id" => "call_from_chunk",
               "index" => 0
             }),
             ReqLLM.StreamChunk.meta(%{finish_reason: :tool_calls})
           ],
           metadata_handle: :ignored,
           cancel: fn -> :ok end,
           model: "openai:gpt-4o",
           context: ReqLLM.Context.new([])
         }}
      else
        {:ok,
         %ReqLLM.StreamResponse{
           stream: [
             ReqLLM.StreamChunk.text("done"),
             ReqLLM.StreamChunk.meta(%{finish_reason: :stop})
           ],
           metadata_handle: :ignored,
           cancel: fn -> :ok end,
           model: "openai:gpt-4o",
           context: ReqLLM.Context.new([])
         }}
      end
    end
  end

  defmodule FakeReqLLMSequentialToolCalls do
    def stream_text(_model, _messages, _opts \\ []) do
      count = Process.get({__MODULE__, :call_count}, 0)
      Process.put({__MODULE__, :call_count}, count + 1)

      case count do
        0 ->
          {:ok,
           %ReqLLM.StreamResponse{
             stream: [
               ReqLLM.StreamChunk.tool_call("echo_tool", %{"input" => %{"message" => "first"}}, %{
                 id: "call_1",
                 index: 0
               }),
               ReqLLM.StreamChunk.meta(%{finish_reason: :tool_calls})
             ],
             metadata_handle: :ignored,
             cancel: fn -> :ok end,
             model: "openai:gpt-4o",
             context: ReqLLM.Context.new([])
           }}

        1 ->
          {:ok,
           %ReqLLM.StreamResponse{
             stream: [
               ReqLLM.StreamChunk.tool_call(
                 "echo_tool",
                 %{"input" => %{"message" => "second"}},
                 %{
                   id: "call_2",
                   index: 0
                 }
               ),
               ReqLLM.StreamChunk.meta(%{finish_reason: :tool_calls})
             ],
             metadata_handle: :ignored,
             cancel: fn -> :ok end,
             model: "openai:gpt-4o",
             context: ReqLLM.Context.new([])
           }}

        _ ->
          {:ok,
           %ReqLLM.StreamResponse{
             stream: [
               ReqLLM.StreamChunk.text("done"),
               ReqLLM.StreamChunk.meta(%{finish_reason: :stop})
             ],
             metadata_handle: :ignored,
             cancel: fn -> :ok end,
             model: "openai:gpt-4o",
             context: ReqLLM.Context.new([])
           }}
      end
    end
  end

  defmodule FakeReqLLMRepeatedToolCalls do
    def stream_text(_model, _messages, _opts \\ []) do
      count = Process.get({__MODULE__, :call_count}, 0)
      Process.put({__MODULE__, :call_count}, count + 1)

      case count do
        0 ->
          {:ok,
           %ReqLLM.StreamResponse{
             stream: [
               ReqLLM.StreamChunk.tool_call("echo_tool", %{"input" => %{"message" => "first"}}, %{
                 id: "call_1",
                 index: 0
               }),
               ReqLLM.StreamChunk.meta(%{finish_reason: :tool_calls})
             ],
             metadata_handle: :ignored,
             cancel: fn -> :ok end,
             model: "openai:gpt-4o",
             context: ReqLLM.Context.new([])
           }}

        1 ->
          {:ok,
           %ReqLLM.StreamResponse{
             stream: [
               ReqLLM.StreamChunk.tool_call(
                 "echo_tool",
                 %{"input" => %{"message" => "first_again"}},
                 %{
                   id: "call_1",
                   index: 0
                 }
               ),
               ReqLLM.StreamChunk.tool_call(
                 "echo_tool",
                 %{"input" => %{"message" => "second"}},
                 %{
                   id: "call_2",
                   index: 1
                 }
               ),
               ReqLLM.StreamChunk.meta(%{finish_reason: :tool_calls})
             ],
             metadata_handle: :ignored,
             cancel: fn -> :ok end,
             model: "openai:gpt-4o",
             context: ReqLLM.Context.new([])
           }}

        _ ->
          {:ok,
           %ReqLLM.StreamResponse{
             stream: [
               ReqLLM.StreamChunk.text("done"),
               ReqLLM.StreamChunk.meta(%{finish_reason: :stop})
             ],
             metadata_handle: :ignored,
             cancel: fn -> :ok end,
             model: "openai:gpt-4o",
             context: ReqLLM.Context.new([])
           }}
      end
    end
  end

  defmodule FakeReqLLMToolCallsWithInterleavedText do
    def stream_text(_model, _messages, _opts \\ []) do
      count = Process.get({__MODULE__, :call_count}, 0)
      Process.put({__MODULE__, :call_count}, count + 1)

      case count do
        0 ->
          {:ok,
           %ReqLLM.StreamResponse{
             stream: [
               ReqLLM.StreamChunk.text("First tool pass."),
               ReqLLM.StreamChunk.tool_call("echo_tool", %{"input" => %{"message" => "first"}}, %{
                 id: "call_1",
                 index: 0
               }),
               ReqLLM.StreamChunk.meta(%{finish_reason: :tool_calls})
             ],
             metadata_handle: :ignored,
             cancel: fn -> :ok end,
             model: "openai:gpt-4o",
             context: ReqLLM.Context.new([])
           }}

        1 ->
          {:ok,
           %ReqLLM.StreamResponse{
             stream: [
               ReqLLM.StreamChunk.text("Second tool pass."),
               ReqLLM.StreamChunk.tool_call(
                 "echo_tool",
                 %{"input" => %{"message" => "second"}},
                 %{
                   id: "call_2",
                   index: 0
                 }
               ),
               ReqLLM.StreamChunk.meta(%{finish_reason: :tool_calls})
             ],
             metadata_handle: :ignored,
             cancel: fn -> :ok end,
             model: "openai:gpt-4o",
             context: ReqLLM.Context.new([])
           }}

        _ ->
          {:ok,
           %ReqLLM.StreamResponse{
             stream: [
               ReqLLM.StreamChunk.text("done"),
               ReqLLM.StreamChunk.meta(%{finish_reason: :stop})
             ],
             metadata_handle: :ignored,
             cancel: fn -> :ok end,
             model: "openai:gpt-4o",
             context: ReqLLM.Context.new([])
           }}
      end
    end
  end

  test "run/2 returns {:error, reason} when req_llm.stream_text fails" do
    messages = [Context.user("hello")]

    assert {:error, :stream_failed} =
             ToolLoop.run(messages,
               actions: [{TestResource, :*}],
               model: "openai:gpt-4o",
               req_llm: FakeReqLLMStreamError
             )
  end

  test "stream/2 emits error event and done result when req_llm.stream_text fails" do
    messages = [Context.user("hello")]

    events =
      ToolLoop.stream(messages,
        actions: [{TestResource, :*}],
        model: "openai:gpt-4o",
        req_llm: FakeReqLLMStreamError
      )
      |> Enum.to_list()

    assert Enum.any?(events, &match?({:error, :stream_failed}, &1))
    assert match?({:done, %ToolLoop.Result{}}, List.last(events))
  end

  test "stream/2 does not crash on invalid tool argument JSON and returns tool error" do
    Process.delete({FakeReqLLMMalformedToolArguments, :call_count})
    messages = [Context.user("trigger tool")]

    events =
      ToolLoop.stream(messages,
        actions: [{TestResource, :*}],
        model: "openai:gpt-4o",
        req_llm: FakeReqLLMMalformedToolArguments
      )
      |> Enum.to_list()

    assert Enum.any?(events, fn
             {:tool_result, %{result: {:error, content}}} ->
               is_binary(content) && content =~ "Invalid tool arguments JSON"

             _ ->
               false
           end)

    assert match?({:done, %ToolLoop.Result{}}, List.last(events))
  end

  test "stream/2 prefers chunk call_id when classified tool call id is missing" do
    Process.delete({FakeReqLLMCallIdOnly, :call_count})
    messages = [Context.user("trigger tool")]

    events =
      ToolLoop.stream(messages,
        actions: [{TestResource, :*}],
        model: "openai:gpt-4o",
        req_llm: FakeReqLLMCallIdOnly
      )
      |> Enum.to_list()

    assert Enum.any?(events, fn
             {:tool_call, %{id: "call_from_chunk", name: "echo_tool"}} -> true
             _ -> false
           end)

    assert Enum.any?(events, fn
             {:tool_result, %{id: "call_from_chunk", result: {:ok, _content, _raw}}} -> true
             _ -> false
           end)

    assert match?({:done, %ToolLoop.Result{final_text: "done"}}, List.last(events))
  end

  test "run/2 merges sequential tool-call assistant turns into a single pending group" do
    Process.delete({FakeReqLLMSequentialToolCalls, :call_count})
    messages = [Context.user("trigger tools")]

    assert {:ok, %ToolLoop.Result{final_text: "done", messages: final_messages}} =
             ToolLoop.run(messages,
               actions: [{TestResource, :*}],
               model: "openai:gpt-4o",
               req_llm: FakeReqLLMSequentialToolCalls
             )

    assistant_tool_turns =
      Enum.filter(final_messages, fn message ->
        message.role == :assistant && List.wrap(message.tool_calls) != []
      end)

    assert length(assistant_tool_turns) == 1

    assert Enum.map(hd(assistant_tool_turns).tool_calls, & &1.id) == ["call_1", "call_2"]

    tool_result_turns =
      Enum.filter(final_messages, fn message ->
        message.role == :tool
      end)

    assert Enum.map(tool_result_turns, & &1.tool_call_id) == ["call_1", "call_2"]
  end

  test "stream/2 does not re-execute already processed tool_call ids" do
    Process.delete({FakeReqLLMRepeatedToolCalls, :call_count})
    messages = [Context.user("trigger tools")]

    events =
      ToolLoop.stream(messages,
        actions: [{TestResource, :*}],
        model: "openai:gpt-4o",
        req_llm: FakeReqLLMRepeatedToolCalls
      )
      |> Enum.to_list()

    tool_result_ids =
      events
      |> Enum.flat_map(fn
        {:tool_result, %{id: id}} -> [id]
        _ -> []
      end)

    assert tool_result_ids == ["call_1", "call_2"]
    assert match?({:done, %ToolLoop.Result{final_text: "done"}}, List.last(events))
  end

  test "run/2 merges tool-call turns even when each turn includes assistant text" do
    Process.delete({FakeReqLLMToolCallsWithInterleavedText, :call_count})
    messages = [Context.user("trigger tools")]

    assert {:ok, %ToolLoop.Result{final_text: "done", messages: final_messages}} =
             ToolLoop.run(messages,
               actions: [{TestResource, :*}],
               model: "openai:gpt-4o",
               req_llm: FakeReqLLMToolCallsWithInterleavedText
             )

    assistant_tool_turns =
      Enum.filter(final_messages, fn message ->
        message.role == :assistant && List.wrap(message.tool_calls) != []
      end)

    assert length(assistant_tool_turns) == 1

    assistant_text =
      assistant_tool_turns
      |> hd()
      |> Map.get(:content, [])
      |> Enum.map(fn
        %{type: :text, text: text} when is_binary(text) -> text
        _ -> ""
      end)
      |> Enum.join("")

    assert assistant_text =~ "First tool pass."
    assert assistant_text =~ "Second tool pass."
    assert Enum.map(hd(assistant_tool_turns).tool_calls, & &1.id) == ["call_1", "call_2"]
  end
end
