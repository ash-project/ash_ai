# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.ToolLoopHistoryTest do
  use ExUnit.Case, async: true

  alias AshAi.ToolLoop
  alias ReqLLM.{Context, Message, StreamChunk}

  defmodule FakeReqLLM do
    def stream_text(model, messages, _opts) do
      [{chunks, metadata} | remaining] = Process.get(:history_responses)
      Process.put(:history_responses, remaining)
      send(self(), {:history_request, messages})

      stream =
        Stream.map(chunks, fn chunk ->
          send(self(), :history_chunk)
          chunk
        end)

      {:ok,
       %ReqLLM.StreamResponse{
         stream: stream,
         metadata_handle: AshAi.Test.StreamHelpers.metadata_handle(metadata),
         cancel: fn -> :ok end,
         model: model,
         context: ReqLLM.Context.new(messages)
       }}
    end
  end

  for interface <- [:run, :stream], provider <- [:openai, :anthropic, :openrouter] do
    @interface interface
    @provider provider

    test "#{interface}/2 preserves history and reasoning through 16 #{provider} tool rounds" do
      model = %LLMDB.Model{provider: @provider, id: "history-test"}
      rounds = Enum.map(1..16, &tool_round(&1, @provider))
      final_round = {[StreamChunk.text("done")], %{finish_reason: :stop}}
      Process.put(:history_responses, rounds ++ [final_round])
      initial = [Context.system("Keep the history."), Context.user("Run the steps.")]

      result = run_loop(@interface, initial, model)

      requests =
        for _ <- 1..17 do
          assert_receive {:history_request, messages}
          messages
        end

      assert hd(requests) == initial

      for [previous, next] <- Enum.chunk_every(requests, 2, 1, :discard) do
        assert Enum.take(next, length(previous)) == previous
        previous_wire = encode(previous, @provider)
        next_wire = encode(next, @provider)
        assert Enum.take(next_wire, length(previous_wire)) == previous_wire
      end

      for {{chunks, metadata}, index} <- Enum.with_index(rounds) do
        {:ok, expected} =
          ReqLLM.Provider.ResponseBuilder.for_model(model).build_response(chunks, metadata,
            model: model,
            context: Context.new()
          )

        assert Enum.at(result.messages, 2 + index * 2) == expected.message
        assert Enum.at(result.messages, 3 + index * 2).tool_call_id == "call_#{index + 1}"
        assert_receive {:history_tool, %{step: step}}
        assert step == index + 1
      end

      assert result.final_text == "done"
      assert length(result.tool_calls_made) == 16
      refute_receive {:history_tool, _}

      chunk_count =
        Enum.sum(Enum.map(rounds ++ [final_round], fn {chunks, _} -> length(chunks) end))

      for _ <- 1..chunk_count, do: assert_receive(:history_chunk)
      refute_receive :history_chunk
    end
  end

  for interface <- [:run, :stream] do
    @interface interface

    test "#{interface}/2 keeps parallel calls together and filters repeated IDs without changing prior turns" do
      Process.put(:history_responses, [
        {[
           StreamChunk.tool_call("lookup", %{"step" => 1}, %{id: "call_1", index: 0}),
           StreamChunk.tool_call("lookup", %{"step" => 2}, %{id: "call_2", index: 1})
         ], %{finish_reason: :tool_calls}},
        {[
           StreamChunk.tool_call("lookup", %{"step" => 1}, %{id: "call_1", index: 0}),
           StreamChunk.tool_call("lookup", %{"step" => 3}, %{id: "call_3", index: 1})
         ], %{finish_reason: :tool_calls}},
        {[StreamChunk.tool_call("lookup", %{"step" => 3}, %{id: "call_3", index: 0})],
         %{finish_reason: :tool_calls}}
      ])

      initial = [Context.user("Run the steps.")]
      result = run_loop(@interface, initial, "openai:gpt-4o")

      assert [_, first, result1, result2, second, result3] = result.messages
      assert Enum.map(first.tool_calls, & &1.id) == ["call_1", "call_2"]
      assert Enum.map(second.tool_calls, & &1.id) == ["call_3"]

      assert Enum.map([result1, result2, result3], & &1.tool_call_id) == [
               "call_1",
               "call_2",
               "call_3"
             ]

      for step <- 1..3, do: assert_receive({:history_tool, %{step: ^step}})
      refute_receive {:history_tool, _}
      assert length(result.tool_calls_made) == 3
    end

    test "#{interface}/2 assigns distinct IDs to separate calls without IDs" do
      Process.put(:history_responses, [
        {[StreamChunk.tool_call("lookup", %{"step" => 1})], %{finish_reason: :tool_calls}},
        {[StreamChunk.tool_call("lookup", %{"step" => 2})], %{finish_reason: :tool_calls}},
        {[StreamChunk.text("done")], %{finish_reason: :stop}}
      ])

      result = run_loop(@interface, [Context.user("Run the steps.")], "openai:gpt-4o")
      ids = Enum.map(result.tool_calls_made, & &1.id)
      assert length(Enum.uniq(ids)) == 2
      refute "nil" in ids
      assert [_, first, result1, second, result2, _] = result.messages
      assert Enum.map(first.tool_calls ++ second.tool_calls, & &1.id) == ids
      assert Enum.map([result1, result2], & &1.tool_call_id) == ids
    end

    test "#{interface}/2 returns response materialization errors without executing tools" do
      Process.put(:history_responses, [
        {[StreamChunk.tool_call("lookup", %{"step" => 1}, %{id: "call_1"})],
         %{error: :response_failed}}
      ])

      opts = loop_opts("openai:gpt-4o")

      case @interface do
        :run ->
          assert {:error, :response_failed} = ToolLoop.run([Context.user("Run.")], opts)

        :stream ->
          events = ToolLoop.stream([Context.user("Run.")], opts) |> Enum.to_list()
          assert {:error, :response_failed} in events
          assert {:done, %ToolLoop.Result{}} = List.last(events)
      end

      refute_receive {:history_tool, _}
    end
  end

  defp run_loop(interface, messages, model) do
    opts = loop_opts(model)

    case interface do
      :run ->
        assert {:ok, result} = ToolLoop.run(messages, opts)
        result

      :stream ->
        events = ToolLoop.stream(messages, opts) |> Enum.to_list()
        refute Enum.any?(events, &match?({:error, _}, &1))
        assert {:done, result} = List.last(events)
        result
    end
  end

  defp loop_opts(model) do
    [
      model: fn -> model end,
      tools: false,
      max_iterations: 20,
      req_llm: FakeReqLLM,
      extra_tools: [
        ReqLLM.Tool.new!(
          name: "lookup",
          description: "Run one test step",
          parameter_schema: [step: [type: :integer, required: true]],
          callback: fn args ->
            send(self(), {:history_tool, args})
            {:ok, args}
          end
        )
      ]
    ]
  end

  defp tool_round(index, provider) do
    {text, thinking} =
      case rem(index, 3) do
        1 -> {"", ""}
        2 -> {" Step #{index} \n", "Reason #{index}"}
        0 -> {"", "Reason #{index}"}
      end

    details =
      if thinking == "" do
        []
      else
        [
          %Message.ReasoningDetails{
            provider: provider,
            format: "anthropic-v1",
            index: 0,
            text: thinking,
            signature: "signature_#{index}"
          }
        ]
      end

    chunks = [
      StreamChunk.thinking(thinking),
      StreamChunk.text(text),
      StreamChunk.meta(%{reasoning_details: details}),
      StreamChunk.tool_call("lookup", %{"step" => index}, %{
        id: "call_#{index}",
        index: 0,
        thought_signature: "tool_signature_#{index}"
      }),
      StreamChunk.meta(%{finish_reason: :tool_calls})
    ]

    {chunks, %{finish_reason: :tool_calls, response_id: "response_#{index}"}}
  end

  defp encode(messages, :anthropic) do
    ReqLLM.Providers.Anthropic.Context.encode_request(Context.new(messages), "history-test").messages
  end

  defp encode(messages, _provider) do
    ReqLLM.Provider.Defaults.encode_context_to_openai_format(
      Context.new(messages),
      "history-test"
    ).messages
  end
end
