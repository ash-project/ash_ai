# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.TranscriptTest do
  use ExUnit.Case, async: true

  alias AshAi.Transcript
  alias ReqLLM.{Context, Message, StreamChunk}
  alias ReqLLM.Message.ContentPart

  for provider <- [:anthropic, :openai, :openrouter] do
    @provider provider

    test "#{provider} turns survive a JSON round trip unchanged on the wire" do
      messages = turn(@provider)
      parts = messages |> Transcript.to_parts() |> json_round_trip()

      restored = Transcript.from_parts(parts)

      assert restored == messages
      assert encode(restored, @provider) == encode(messages, @provider)
    end
  end

  test "parts of consecutive messages concatenate" do
    messages = turn(:anthropic)

    assert Enum.flat_map(messages, &Transcript.to_parts([&1])) == Transcript.to_parts(messages)
  end

  test "reasoning: false leaves out thinking and reasoning details" do
    parts = Transcript.to_parts(turn(:anthropic), reasoning: false)

    refute Enum.any?(parts, &(&1["type"] == "reasoning"))
    refute Enum.any?(parts, &Map.has_key?(&1, "reasoning_details"))

    restored = Transcript.from_parts(json_round_trip(parts))
    assert restored == Transcript.strip_reasoning(turn(:anthropic))
  end

  test "text, tool results, and pending calls are readable from parts" do
    [assistant, result, _final] = turn(:anthropic)
    pending = %{assistant | tool_calls: assistant.tool_calls ++ [tool_call("call_2")]}
    parts = Transcript.to_parts([pending, result])

    assert Transcript.text(parts) == "Checking."
    assert [%{"id" => "call_2"}] = Transcript.pending_tool_calls(parts)
    assert %{"content" => "3 items"} = Enum.find(parts, &(&1["type"] == "tool_result"))
  end

  test "tool results with metadata and multiple parts round trip" do
    message =
      Context.tool_result("call_1", %ReqLLM.ToolResult{
        content: [ContentPart.text("a"), ContentPart.text("b")],
        metadata: %{source: "cache", sources: ["one", "two"]}
      })

    assert [restored] =
             [message] |> Transcript.to_parts() |> json_round_trip() |> Transcript.from_parts()

    assert restored == message
  end

  test "fingerprint changes with the system prompt and tools" do
    tool = ReqLLM.Tool.new!(name: "a", description: "a", callback: fn _ -> {:ok, nil} end)

    assert Transcript.fingerprint("x", [tool]) == Transcript.fingerprint("x", [tool])
    refute Transcript.fingerprint("x", [tool]) == Transcript.fingerprint("y", [tool])
    refute Transcript.fingerprint("x", [tool]) == Transcript.fingerprint("x", [])
  end

  # An assistant turn with reasoning, a provider block, and a tool call; its
  # result; and a final answer, built the way ReqLLM builds responses.
  defp turn(provider) do
    model = %LLMDB.Model{provider: provider, id: "transcript-test"}

    first =
      build(model, [
        StreamChunk.thinking("Let me look.", %{signature: "sig_1"}),
        StreamChunk.text("Checking."),
        StreamChunk.meta(%{
          reasoning_details: [
            %Message.ReasoningDetails{
              provider: provider,
              format: "anthropic-v1",
              index: 0,
              text: "Let me look.",
              signature: "sig_1"
            }
          ]
        }),
        StreamChunk.tool_call("list_items", %{"limit" => 3}, %{id: "call_1", index: 0}),
        StreamChunk.meta(%{finish_reason: :tool_calls})
      ])

    first = %{
      first
      | content:
          first.content ++
            [
              ContentPart.provider_block(:anthropic, %{
                "type" => "server_tool_use",
                "id" => "srv_1",
                "name" => "tool_search_tool_bm25",
                "input" => %{"query" => "items"}
              })
            ]
    }

    final =
      build(model, [StreamChunk.text("You have 3."), StreamChunk.meta(%{finish_reason: :stop})])

    [first, Context.tool_result("call_1", "3 items"), %{final | tool_calls: nil}]
  end

  defp build(model, chunks) do
    {:ok, response} =
      ReqLLM.Provider.ResponseBuilder.for_model(model).build_response(
        chunks,
        %{finish_reason: :stop, response_id: "resp_1"},
        model: model,
        context: Context.new()
      )

    response.message
  end

  defp tool_call(id), do: ReqLLM.ToolCall.new(id, "delete_item", ~s({"id":1}))

  defp json_round_trip(parts), do: parts |> Jason.encode!() |> Jason.decode!()

  defp encode(messages, :anthropic) do
    ReqLLM.Providers.Anthropic.Context.encode_request(
      Context.new([Context.user("Hi.") | messages]),
      "transcript-test"
    ).messages
  end

  defp encode(messages, _provider) do
    ReqLLM.Provider.Defaults.encode_context_to_openai_format(
      Context.new([Context.user("Hi.") | messages]),
      "transcript-test"
    ).messages
  end
end
