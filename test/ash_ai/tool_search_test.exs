# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.ToolSearchTest do
  use ExUnit.Case, async: true

  alias AshAi.ToolLoop
  alias ReqLLM.{Context, StreamChunk}

  defmodule FakeReqLLM do
    def stream_text(model, messages, opts) do
      [chunks | remaining] = Process.get(:responses)
      Process.put(:responses, remaining)
      send(self(), {:request, messages, opts})

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

  defp respond(responses), do: Process.put(:responses, responses)

  defp text(text), do: [StreamChunk.text(text), StreamChunk.meta(%{finish_reason: :stop})]

  defp tool(name, description) do
    ReqLLM.Tool.new!(
      name: name,
      description: description,
      parameter_schema: %{"type" => "object", "properties" => %{}},
      callback: fn _args ->
        send(self(), {:ran, name})
        {:ok, "#{name} ran"}
      end
    )
  end

  defp tools do
    [
      tool("echo", "Echo a message"),
      tool("list_items", "List the items in the user's loop"),
      tool("delete_item", "Delete an item"),
      tool("get_weather", "Current weather for a city")
    ]
  end

  defp opts(provider, search, extra \\ []) do
    Keyword.merge(
      [
        model: %LLMDB.Model{provider: provider, id: "search-test"},
        tools: false,
        req_llm: FakeReqLLM,
        extra_tools: tools(),
        tool_search: Keyword.merge([always_load: ["echo"]], search)
      ],
      extra
    )
  end

  defp requests(count) do
    for _ <- 1..count do
      assert_receive {:request, messages, opts}
      {messages, opts}
    end
  end

  defp tool_names(opts), do: Enum.map(opts[:tools], &(Map.get(&1, :name) || &1["type"]))

  describe "the provider's built-in search" do
    test "uses Anthropic's hosted search" do
      respond([text("Hi.")])
      assert {:ok, _} = ToolLoop.run([Context.user("Hi")], opts(:anthropic, []))

      assert [{_, opts}] = requests(1)
      assert opts[:provider_options][:tool_search] == %{variant: :bm25}
      assert tool_names(opts) == ["echo", "list_items", "delete_item", "get_weather"]

      deferred =
        for tool <- opts[:tools],
            ReqLLM.Tool.provider_options(tool, :anthropic)[:defer_loading],
            do: tool.name

      assert deferred == ["list_items", "delete_item", "get_weather"]
    end

    test "uses OpenAI's hosted search" do
      respond([text("Hi.")])
      assert {:ok, _} = ToolLoop.run([Context.user("Hi")], opts(:openai, []))

      assert [{_, opts}] = requests(1)
      assert List.last(opts[:tools]) == %{"type" => "tool_search"}
      refute ReqLLM.Tool.provider_options(hd(opts[:tools]), :openai)[:defer_loading]
      assert ReqLLM.Tool.provider_options(Enum.at(opts[:tools], 1), :openai)[:defer_loading]
    end

    test "sends every tool normally to providers without deferred loading" do
      respond([text("Hi.")])
      assert {:ok, _} = ToolLoop.run([Context.user("Hi")], opts(:google, []))

      assert [{_, opts}] = requests(1)
      assert opts[:tools] == tools()
      refute opts[:provider_options][:tool_search]
    end
  end

  test "tools are sent normally when nothing is deferred" do
    respond([text("Hi.")])

    assert {:ok, _} =
             ToolLoop.run(
               [Context.user("Hi")],
               opts(:openai, always_load: Enum.map(tools(), & &1.name))
             )

    assert [{_, opts}] = requests(1)
    assert opts[:tools] == tools()
  end
end
