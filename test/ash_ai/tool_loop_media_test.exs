# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.ToolLoopMediaTest do
  use ExUnit.Case, async: true

  alias AshAi.ToolLoop
  alias ReqLLM.{Context, StreamChunk}
  alias ReqLLM.Message.ContentPart

  # Answers with the scripted responses and reports the messages it was sent
  defmodule FakeReqLLM do
    def stream_text(model, messages, _opts) do
      [chunks | remaining] = Process.get(:responses)
      Process.put(:responses, remaining)
      send(self(), {:messages, messages})

      {:ok,
       %ReqLLM.StreamResponse{
         stream: chunks,
         metadata_handle: AshAi.Test.StreamHelpers.metadata_handle(),
         cancel: fn -> :ok end,
         model: model,
         context: ReqLLM.Context.new(messages)
       }}
    end
  end

  @image ContentPart.image("png bytes", "image/png")

  defp run(model, images \\ :auto) do
    chart =
      ReqLLM.Tool.new!(
        name: "chart",
        description: "Draws a chart.",
        parameter_schema: %{"type" => "object", "properties" => %{}},
        callback: fn _args -> {:ok, ""} end
      )

    Process.put(:responses, [
      [
        StreamChunk.tool_call("chart", %{}, %{id: "c1"}),
        StreamChunk.meta(%{finish_reason: :tool_calls})
      ],
      [StreamChunk.text("Done."), StreamChunk.meta(%{finish_reason: :stop})]
    ])

    {:ok, result} =
      ToolLoop.run([Context.user("Chart it.")],
        model: model,
        tools: false,
        req_llm: FakeReqLLM,
        tool_result_images: images,
        extra_tools: [
          {chart, fn _args, _context -> {:ok, [ContentPart.text("Here:"), @image]} end}
        ]
      )

    assert_received {:messages, _first_request}
    assert_received {:messages, second_request}

    {tool_message(second_request), tool_message(result.messages)}
  end

  defp tool_message(messages), do: Enum.find(messages, &(&1.role == :tool))

  defp model(provider, input) do
    %LLMDB.Model{provider: provider, id: "test", modalities: %{input: input, output: [:text]}}
  end

  test "sends images to models whose provider carries them in tool results" do
    {sent, kept} = run(model(:anthropic, [:text, :image]))

    assert [%ContentPart{type: :text, text: "Here:"}, @image] = sent.content
    assert kept.content == sent.content
  end

  test "describes images for models that don't accept image input" do
    {sent, kept} = run(model(:anthropic, [:text]))

    assert [
             %ContentPart{type: :text, text: "Here:"},
             %ContentPart{type: :text, text: description}
           ] =
             sent.content

    assert %{"type" => "image", "mimeType" => "image/png", "note" => "image omitted" <> _} =
             Jason.decode!(description)

    # The conversation keeps the image for a later model that accepts it
    assert [_text, @image] = kept.content
  end

  test "describes images for Chat Completions style providers" do
    {sent, _kept} = run(model(:groq, [:text, :image]))
    refute Enum.any?(sent.content, &(&1.type == :image))
  end

  test "follows ReqLLM's choice of OpenAI API" do
    {sent, _kept} = run(ReqLLM.model!("openai:gpt-4o"))
    assert [_text, @image] = sent.content
  end

  test "tool_result_images: false always describes images" do
    {sent, kept} = run(model(:anthropic, [:text, :image]), false)

    refute Enum.any?(sent.content, &(&1.type == :image))
    assert [_text, @image] = kept.content
  end

  test "tool_result_images: true always sends images" do
    {sent, _kept} = run(model(:groq, [:text]), true)
    assert [_text, @image] = sent.content
  end
end
