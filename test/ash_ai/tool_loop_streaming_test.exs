# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.ToolLoopStreamingTest do
  use ExUnit.Case, async: true

  alias AshAi.ToolLoop
  alias ReqLLM.{Context, StreamChunk}

  defmodule FakeReqLLM do
    @moduledoc "The test releases each chunk and final metadata independently."

    def stream_text(model, messages, opts) do
      owner = Keyword.fetch!(opts, :owner)
      ref = Keyword.fetch!(opts, :ref)

      {:ok, metadata_handle} =
        ReqLLM.StreamResponse.MetadataHandle.start_link(fn ->
          send(owner, {ref, :metadata_waiting, self()})

          receive do
            {^ref, :metadata, metadata} -> metadata
          end
        end)

      stream =
        Stream.resource(
          fn ->
            send(owner, {ref, :started, self(), metadata_handle, messages})
            :open
          end,
          fn :open ->
            send(owner, {ref, :demand})

            receive do
              {^ref, :chunk, chunk} -> {[chunk], :open}
              {^ref, :finish} -> {:halt, :exhausted}
              {^ref, :raise} -> raise "upstream failed"
            end
          end,
          fn status -> send(owner, {ref, :upstream_closed, status}) end
        )

      {:ok,
       %ReqLLM.StreamResponse{
         stream: stream,
         metadata_handle: metadata_handle,
         cancel: fn -> send(owner, {ref, :cancelled}) end,
         model: model,
         context: Context.new(messages)
       }}
    end
  end

  test "stream/2 emits content before the response and metadata finish" do
    {ref, consumer} = start_consumer()
    assert_receive {^ref, :started, ^consumer, handle, _}, 1_000
    assert_receive {^ref, :metadata_waiting, metadata}, 1_000
    monitor = Process.monitor(handle)

    for text <- ["hello", " world"] do
      assert_receive {^ref, :demand}, 1_000
      send(consumer, {ref, :chunk, StreamChunk.text(text)})
      assert_receive {^ref, :event, {:content, ^text}}, 1_000
    end

    assert_receive {^ref, :demand}, 1_000
    send(consumer, {ref, :finish})
    assert_receive {^ref, :upstream_closed, :exhausted}, 1_000
    refute_receive {^ref, :event, {:done, _}}

    send(metadata, {ref, :metadata, %{usage: %{input_tokens: 3, output_tokens: 2}}})
    assert_receive {^ref, :event, {:done, result}}, 1_000
    assert result.final_text == "hello world"
    assert result.usage == %{input_tokens: 3, output_tokens: 2}
    assert_receive {^ref, :finished}, 1_000
    assert_receive {:DOWN, ^monitor, :process, ^handle, :normal}, 1_000
    refute_receive {^ref, :event, _}
  end

  test "stream/2 closes the response when the caller stops after one event" do
    {ref, consumer} = start_consumer(&Stream.take(&1, 1))
    assert_receive {^ref, :started, ^consumer, handle, _}, 1_000
    monitor = Process.monitor(handle)
    assert_receive {^ref, :demand}, 1_000
    send(consumer, {ref, :chunk, StreamChunk.text("first")})

    assert_receive {^ref, :event, {:content, "first"}}, 1_000
    assert_receive {^ref, :upstream_closed, :open}, 1_000
    assert_receive {^ref, :cancelled}, 1_000
    assert_receive {:DOWN, ^monitor, :process, ^handle, :normal}, 1_000
    assert_receive {^ref, :finished}, 1_000
    refute_receive {^ref, :demand}
    refute_receive {^ref, :event, _}
  end

  test "stream/2 closes the response when the consumer raises" do
    {ref, consumer} =
      start_consumer(fn events ->
        Stream.map(events, fn _event -> raise "consumer failed" end)
      end)

    assert_receive {^ref, :started, ^consumer, handle, _}, 1_000
    monitor = Process.monitor(handle)
    assert_receive {^ref, :demand}, 1_000
    send(consumer, {ref, :chunk, StreamChunk.text("first")})

    assert_receive {^ref, :upstream_closed, :open}, 1_000
    assert_receive {^ref, :cancelled}, 1_000
    assert_receive {:DOWN, ^monitor, :process, ^handle, :normal}, 1_000
    assert_receive {^ref, :raised, :error, %RuntimeError{message: "consumer failed"}}, 1_000
    refute_receive {^ref, :upstream_closed, _}
  end

  test "stream/2 cleans up once and reraises when the provider fails after content" do
    {ref, consumer} = start_consumer()
    assert_receive {^ref, :started, ^consumer, handle, _}, 1_000
    monitor = Process.monitor(handle)
    assert_receive {^ref, :demand}, 1_000
    send(consumer, {ref, :chunk, StreamChunk.text("first")})
    assert_receive {^ref, :event, {:content, "first"}}, 1_000

    assert_receive {^ref, :demand}, 1_000
    send(consumer, {ref, :raise})
    assert_receive {^ref, :upstream_closed, :open}, 1_000
    assert_receive {^ref, :cancelled}, 1_000
    assert_receive {:DOWN, ^monitor, :process, ^handle, :normal}, 1_000
    assert_receive {^ref, :raised, :error, %RuntimeError{message: "upstream failed"}}, 1_000
    refute_receive {^ref, :upstream_closed, _}
    refute_receive {^ref, :event, _}
  end

  test "stream/2 emits error and done events when response assembly fails after content" do
    {ref, consumer} = start_consumer()
    assert_receive {^ref, :started, ^consumer, handle, _}, 1_000
    assert_receive {^ref, :metadata_waiting, metadata}, 1_000
    monitor = Process.monitor(handle)
    assert_receive {^ref, :demand}, 1_000
    send(consumer, {ref, :chunk, StreamChunk.text("partial")})
    assert_receive {^ref, :event, {:content, "partial"}}, 1_000

    finish_response(ref, consumer, metadata, %{error: :response_failed})
    assert_receive {^ref, :event, {:error, :response_failed}}, 1_000

    assert_receive {^ref, :event, {:done, %ToolLoop.Result{iterations: 0, final_text: ""}}},
                   1_000

    assert_receive {^ref, :finished}, 1_000
    assert_receive {:DOWN, ^monitor, :process, ^handle, :normal}, 1_000
  end

  test "stream/2 preserves history and sums usage across incrementally consumed tool rounds" do
    {ref, consumer} = start_consumer(&Function.identity/1, extra_tools: [lookup_tool()])
    assert_receive {^ref, :started, ^consumer, first_handle, initial}, 1_000
    assert_receive {^ref, :metadata_waiting, first_metadata}, 1_000
    first_monitor = Process.monitor(first_handle)

    assert_receive {^ref, :demand}, 1_000
    send(consumer, {ref, :chunk, StreamChunk.text("Looking up.")})
    assert_receive {^ref, :event, {:content, "Looking up."}}, 1_000
    assert_receive {^ref, :demand}, 1_000
    send(consumer, {ref, :chunk, StreamChunk.tool_call("lookup", %{}, %{id: "call_1"})})
    assert_receive {^ref, :demand}, 1_000
    refute_receive {:tool_executed, _}
    send(consumer, {ref, :finish})
    assert_receive {^ref, :upstream_closed, :exhausted}, 1_000
    refute_receive {:tool_executed, _}
    send(first_metadata, {ref, :metadata, %{usage: %{input_tokens: 10, output_tokens: 2}}})

    assert_receive {^ref, :event, {:tool_call, %{id: "call_1"}}}, 1_000
    assert_receive {:tool_executed, ^consumer}, 1_000
    assert_receive {^ref, :event, {:tool_result, %{id: "call_1"}}}, 1_000
    assert_receive {^ref, :event, {:iteration, %ToolLoop.IterationEvent{iteration: 2}}}, 1_000
    assert_receive {:DOWN, ^first_monitor, :process, ^first_handle, :normal}, 1_000

    assert_receive {^ref, :started, ^consumer, second_handle, messages}, 1_000
    assert_receive {^ref, :metadata_waiting, second_metadata}, 1_000
    second_monitor = Process.monitor(second_handle)
    assert Enum.take(messages, length(initial)) == initial
    assert [_, assistant, tool_result] = messages
    assert [%{text: "Looking up."}] = assistant.content
    assert [%{id: "call_1", function: %{name: "lookup"}}] = assistant.tool_calls
    assert tool_result.tool_call_id == "call_1"

    assert_receive {^ref, :demand}, 1_000
    send(consumer, {ref, :chunk, StreamChunk.text("Found it.")})
    assert_receive {^ref, :event, {:content, "Found it."}}, 1_000

    finish_response(ref, consumer, second_metadata, %{
      usage: %{input_tokens: 20, output_tokens: 3}
    })

    assert_receive {^ref, :event, {:done, result}}, 1_000
    assert result.final_text == "Found it."
    assert result.iterations == 2
    assert result.usage == %{input_tokens: 30, output_tokens: 5}
    assert length(result.tool_calls_made) == 1
    assert Enum.take(result.messages, length(messages)) == messages
    assert_receive {^ref, :finished}, 1_000
    assert_receive {:DOWN, ^second_monitor, :process, ^second_handle, :normal}, 1_000
    refute_receive {^ref, :started, _, _, _}
    refute_receive {^ref, :event, _}
    refute_receive {:tool_executed, _}
  end

  test "stream/2 does not run tools or start another turn after the caller halts" do
    {ref, consumer} = start_consumer(&Stream.take(&1, 1), extra_tools: [lookup_tool()])
    assert_receive {^ref, :started, ^consumer, _handle, _}, 1_000
    assert_receive {^ref, :metadata_waiting, metadata}, 1_000
    assert_receive {^ref, :demand}, 1_000
    send(consumer, {ref, :chunk, StreamChunk.tool_call("lookup", %{}, %{id: "call_1"})})
    finish_response(ref, consumer, metadata, %{})

    assert_receive {^ref, :event, {:tool_call, %{id: "call_1"}}}, 1_000
    assert_receive {^ref, :finished}, 1_000
    refute_receive {:tool_executed, _}
    refute_receive {^ref, :started, _, _, _}
  end

  defp finish_response(ref, consumer, metadata, value) do
    assert_receive {^ref, :demand}, 1_000
    send(consumer, {ref, :finish})
    assert_receive {^ref, :upstream_closed, :exhausted}, 1_000
    send(metadata, {ref, :metadata, value})
  end

  defp start_consumer(transform \\ &Function.identity/1, opts \\ []) do
    owner = self()
    ref = make_ref()

    consumer =
      start_supervised!(
        {Task,
         fn ->
           opts =
             Keyword.merge(
               [
                 model: %LLMDB.Model{provider: :openai, id: "stream-test"},
                 tools: false,
                 req_llm: FakeReqLLM,
                 req_llm_opts: [owner: owner, ref: ref]
               ],
               opts
             )

           try do
             ToolLoop.stream([Context.user("hello")], opts)
             |> transform.()
             |> Enum.each(&send(owner, {ref, :event, &1}))

             send(owner, {ref, :finished})
           catch
             kind, reason -> send(owner, {ref, :raised, kind, reason})
           end
         end}
      )

    {ref, consumer}
  end

  defp lookup_tool do
    owner = self()

    ReqLLM.Tool.new!(
      name: "lookup",
      description: "Look up a test value",
      parameter_schema: [],
      callback: fn _arguments ->
        send(owner, {:tool_executed, self()})
        {:ok, "found"}
      end
    )
  end
end
