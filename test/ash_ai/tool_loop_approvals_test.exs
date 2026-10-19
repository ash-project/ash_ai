# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.ToolLoopApprovalsTest do
  use ExUnit.Case, async: true

  alias AshAi.{ToolLoop, Transcript}
  alias ReqLLM.{Context, StreamChunk}

  defmodule FakeReqLLM do
    def stream_text(model, messages, _opts) do
      [chunks | remaining] = Process.get(:responses)
      Process.put(:responses, remaining)
      send(self(), {:request, messages})

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

  defp calls(calls) do
    Enum.map(calls, fn {id, name, args} -> StreamChunk.tool_call(name, args, %{id: id}) end) ++
      [StreamChunk.meta(%{finish_reason: :tool_calls})]
  end

  defp text(text), do: [StreamChunk.text(text), StreamChunk.meta(%{finish_reason: :stop})]

  defp opts(extra \\ []) do
    Keyword.merge(
      [
        model: %LLMDB.Model{provider: :openai, id: "approvals-test"},
        tools: false,
        req_llm: FakeReqLLM,
        extra_tools: [tool("read_items"), tool("delete_item")],
        approve_tool_call: fn
          %{name: "delete_item"}, _context -> :ask
          _call, _context -> :ok
        end
      ],
      extra
    )
  end

  defp tool(name) do
    ReqLLM.Tool.new!(
      name: name,
      description: name,
      parameter_schema: %{"type" => "object", "properties" => %{}},
      callback: fn args ->
        send(self(), {:ran, name, args})
        {:ok, "#{name} ran"}
      end
    )
  end

  test "stops for approval after running the round's approved calls" do
    respond([calls([{"c1", "delete_item", %{"id" => 1}}, {"c2", "read_items", %{}}])])

    events = ToolLoop.stream([Context.user("Clean up.")], opts()) |> Enum.to_list()

    assert_receive {:ran, "read_items", _}
    refute_receive {:ran, "delete_item", _}

    assert Enum.any?(
             events,
             &match?({:approval_required, [%{id: "c1", name: "delete_item"}]}, &1)
           )

    assert {:done, result} = List.last(events)
    assert result.status == :awaiting_approval
    assert [%{id: "c1"}] = result.pending_approvals

    assert [_user, %{role: :assistant}, %{role: :tool, tool_call_id: "c2"}] = result.messages
    assert [%{id: "c1"}] = ToolLoop.pending_tool_calls(result.messages)

    # Every message the loop added was emitted, so storing the events stores the turn.
    emitted = for {:message, message} <- events, do: message
    assert emitted == tl(result.messages)
  end

  test "resumes an approved call from the returned messages" do
    respond([calls([{"c1", "delete_item", %{"id" => 1}}])])
    assert {:ok, paused} = ToolLoop.run([Context.user("Delete it.")], opts())
    assert paused.status == :awaiting_approval
    assert_receive {:request, _}

    respond([text("Deleted.")])
    assert {:ok, result} = ToolLoop.resume(paused.messages, %{"c1" => :approve}, opts())

    assert_receive {:ran, "delete_item", %{"id" => 1}}
    assert result.status == :complete
    assert result.final_text == "Deleted."
    assert_receive {:request, sent}
    assert [_user, %{role: :assistant}, %{role: :tool, tool_call_id: "c1"}] = sent
  end

  test "resumes from stored parts" do
    respond([calls([{"c1", "delete_item", %{"id" => 1}}])])
    events = ToolLoop.stream([Context.user("Delete it.")], opts()) |> Enum.to_list()

    parts =
      for({:message, message} <- events, do: message)
      |> Transcript.to_parts()
      |> Jason.encode!()
      |> Jason.decode!()

    assert [%{"name" => "delete_item"}] = Transcript.pending_tool_calls(parts)

    respond([text("Deleted.")])
    messages = [Context.user("Delete it.") | Transcript.from_parts(parts)]
    assert {:ok, result} = ToolLoop.resume(messages, %{"c1" => :approve}, opts())
    assert result.final_text == "Deleted."
    assert_receive {:ran, "delete_item", _}
  end

  test "a denied call gets an error result and the model continues" do
    respond([calls([{"c1", "delete_item", %{"id" => 1}}])])
    assert {:ok, paused} = ToolLoop.run([Context.user("Delete it.")], opts())

    respond([text("Okay, I won't.")])

    assert {:ok, result} =
             ToolLoop.resume(paused.messages, %{"c1" => {:deny, "keep it"}}, opts())

    refute_receive {:ran, "delete_item", _}
    assert result.final_text == "Okay, I won't."
    tool_message = Enum.find(result.messages, &(&1.role == :tool))
    assert [%{text: text}] = tool_message.content
    assert text =~ "denied this tool call: keep it"
  end

  test "a call without a decision asks again without calling the model" do
    respond([calls([{"c1", "delete_item", %{}}])])
    assert {:ok, paused} = ToolLoop.run([Context.user("Delete it.")], opts())
    assert_receive {:request, _}

    assert {:ok, again} = ToolLoop.resume(paused.messages, %{}, opts())
    assert again.status == :awaiting_approval
    assert again.messages == paused.messages
    refute_receive {:request, _}
  end

  test "an approved call that pauses keeps its approval in the result" do
    respond([calls([{"c1", "delete_item", %{}}])])
    assert {:ok, paused} = ToolLoop.run([Context.user("Delete it.")], opts())
    assert paused.status == :awaiting_approval
    assert paused.approvals == %{}

    # Approved, but the tool can't run yet (say, it needs authorization).
    pausing =
      ReqLLM.Tool.new!(
        name: "delete_item",
        description: "delete_item",
        parameter_schema: %{"type" => "object", "properties" => %{}},
        callback: fn _args -> {:pause, :authorization_required} end
      )

    opts = opts(extra_tools: [tool("read_items"), pausing])

    assert {:ok, again} = ToolLoop.resume(paused.messages, %{"c1" => :approve}, opts)
    assert again.status == :paused
    assert [%{call: %{id: "c1"}, reason: :authorization_required}] = again.paused_calls
    assert again.approvals == %{"c1" => :approve}

    # Passing the stored approvals back runs the call without asking again.
    respond([text("Deleted.")])
    assert {:ok, done} = ToolLoop.resume(again.messages, again.approvals, opts())
    assert done.status == :complete
    assert_receive {:ran, "delete_item", _}
  end

  test "unanswered calls get a fixed result when the conversation moves on" do
    respond([calls([{"c1", "delete_item", %{}}, {"c2", "read_items", %{}}])])
    assert {:ok, paused} = ToolLoop.run([Context.user("Delete it.")], opts())
    assert_receive {:request, _}

    history = paused.messages ++ [Context.user("Never mind.")]
    assert ToolLoop.pending_tool_calls(history) == []

    for _ <- 1..2 do
      respond([text("Okay.")])
      assert {:ok, _} = ToolLoop.run(history, opts())
    end

    assert_receive {:request, first}
    assert_receive {:request, second}
    assert first == second

    assert [_, %{role: :assistant}, %{tool_call_id: "c2"}, not_run, %{role: :user}] = first
    assert not_run.tool_call_id == "c1"
    assert [%{text: text}] = not_run.content
    assert text =~ "Not run"
    refute_receive {:ran, "delete_item", _}
  end
end
