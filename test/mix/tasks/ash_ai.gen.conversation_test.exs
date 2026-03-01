# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule Mix.Tasks.AshAi.Gen.ChatTest do
  use ExUnit.Case

  import Igniter.Test
  import Igniter.Project.Module, only: [module_exists: 2]

  setup do
    %{argv: ["--user", "MyApp.Accounts.User", "--extend", "ets"]}
  end

  test "--live flag doesnt explode", %{argv: argv} do
    argv = argv ++ ["--live"]

    igniter =
      phx_test_project()
      |> Igniter.compose_task("ash_ai.gen.chat", argv)
      |> apply_igniter!()

    assert igniter |> module_exists(Test.Chat.Conversation) |> elem(0)
    assert igniter |> module_exists(Test.Chat.Message) |> elem(0)
    assert igniter |> module_exists(TestWeb.ChatLive) |> elem(0)
  end

  test "--live with --domain uses domain suffix for LiveView module name", %{argv: argv} do
    argv = argv ++ ["--live", "--domain", "Test.SupportChat"]

    igniter =
      phx_test_project()
      |> Igniter.compose_task("ash_ai.gen.chat", argv)
      |> apply_igniter!()

    assert igniter |> module_exists(TestWeb.SupportChatLive) |> elem(0)
  end

  test "--live-component generates component with name derived from --domain", %{argv: argv} do
    argv = argv ++ ["--live-component", "--domain", "Test.SupportChat"]

    igniter =
      phx_test_project()
      |> Igniter.compose_task("ash_ai.gen.chat", argv)
      |> apply_igniter!()

    assert igniter |> module_exists(TestWeb.SupportChatComponent) |> elem(0)
  end

  test "--route option sets the live route path in router.ex", %{argv: argv} do
    argv = argv ++ ["--live", "--live-component", "--domain", "Test.SupportChat"]
    argv = argv ++ ["--route", "/support/chat", "--provider", "openai"]

    phx_test_project()
    |> Igniter.Project.Module.find_and_update_module!(TestWeb.Router, fn zipper ->
      {:ok,
       Igniter.Code.Common.add_code(zipper, """
       ash_authentication_live_session :authenticated do
       end
       """)}
    end)
    |> apply_igniter!()
    |> Igniter.compose_task("ash_ai.gen.chat", argv)
    |> assert_has_patch("lib/test_web/router.ex", """
    +|live "/support/chat", SupportChatLive
    +|live "/support/chat/:conversation_id", SupportChatLive
    """)
    |> assert_has_patch("config/runtime.exs", """
    + |config :req_llm, openai_api_key: System.get_env("OPENAI_API_KEY")
    """)
    |> apply_igniter!()
  end

  test "default provider is openai when --provider is not supplied", %{argv: argv} do
    argv = argv ++ ["--live"]

    phx_test_project()
    |> Igniter.compose_task("ash_ai.gen.chat", argv)
    |> assert_has_patch("config/runtime.exs", """
    + |config :req_llm, openai_api_key: System.get_env("OPENAI_API_KEY")
    """)
    |> apply_igniter!()
  end

  test "generated respond change handles stream errors and keeps accumulator shapes safe", %{
    argv: argv
  } do
    argv = argv ++ ["--live"]

    phx_test_project()
    |> Igniter.compose_task("ash_ai.gen.chat", argv)
    |> assert_has_patch("lib/test/chat/message/changes/respond.ex", """
    |Enum.reduce(%{text: "", tool_calls: [], tool_results: [], stream_error: nil}, fn
    """)
    |> assert_has_patch("lib/test/chat/message/changes/respond.ex", """
    |%{acc | tool_calls: append_event(acc.tool_calls, tool_call)}
    """)
    |> assert_has_patch("lib/test/chat/message/changes/respond.ex", """
    |defp append_event(items, value) when is_list(items), do: items ++ [value]
    """)
    |> assert_has_patch("lib/test/chat/message/changes/respond.ex", """
    |{:error, reason}, acc ->
    |  %{acc | stream_error: reason}
    """)
    |> assert_has_patch("lib/test/chat/message/changes/respond.ex", """
    |if final_state.stream_error ||
    """)
    |> assert_has_patch("lib/test/chat/message/changes/respond.ex", """
    |defp stream_error_text(:max_iterations_reached) do
    """)
  end

  test "generated respond change replays text-only history to avoid stale tool call ids", %{
    argv: argv
  } do
    argv = argv ++ ["--live"]

    igniter =
      phx_test_project()
      |> Igniter.compose_task("ash_ai.gen.chat", argv)
      |> apply_igniter!()

    respond_content =
      igniter.rewrite.sources["lib/test/chat/message/changes/respond.ex"]
      |> Rewrite.Source.get(:content)

    assert respond_content =~ "Context.assistant(text || \"\")"
    refute respond_content =~ "normalize_tool_calls(message.tool_calls || [])"
    refute respond_content =~ "normalize_tool_result_message"
    refute respond_content =~ "Context.tool_result(id, content || \"\")"
  end

  test "--live with --user guards unauthenticated actor-required flows", %{argv: argv} do
    argv = argv ++ ["--live"]

    phx_test_project()
    |> Igniter.compose_task("ash_ai.gen.chat", argv)
    |> assert_has_patch("lib/test_web/live/chat_live.ex", """
    |if @actor_required? && is_nil(socket.assigns.current_user) do
    """)
    |> assert_has_patch("lib/test_web/live/chat_live.ex", """
    |{:noreply, put_flash(socket, :error, "You must sign in to send messages")}
    """)
    |> assert_has_patch("lib/test_web/live/chat_live.ex", """
    ||> put_flash(:error, "You must sign in to access conversations")
    """)
    |> apply_igniter!()
  end

  test "when --user is not provided, generated conversation create action does not relate actor" do
    igniter =
      phx_test_project()
      |> Igniter.compose_task("ash_ai.gen.chat", ["--live"])
      |> apply_igniter!()

    conversation_content =
      igniter.rewrite.sources["lib/test/chat/conversation.ex"]
      |> Rewrite.Source.get(:content)

    refute conversation_content =~ "change relate_actor(:user)"
  end

  test "generated chat domain includes AshAi extension and starter tools", %{argv: argv} do
    igniter =
      phx_test_project()
      |> Igniter.compose_task("ash_ai.gen.chat", argv)
      |> apply_igniter!()

    chat_content =
      igniter.rewrite.sources["lib/test/chat.ex"]
      |> Rewrite.Source.get(:content)

    assert chat_content =~ "use Ash.Domain"
    assert chat_content =~ "AshPhoenix"
    assert chat_content =~ "AshAi"
    assert chat_content =~ "tools do"

    assert chat_content =~
             "tool :chat_list_conversations, Test.Chat.Conversation, :my_conversations do"

    assert chat_content =~ "tool :chat_message_history, Test.Chat.Message, :for_conversation do"
  end

  test "generated starter tools use :read when --user is not provided" do
    igniter =
      phx_test_project()
      |> Igniter.compose_task("ash_ai.gen.chat", [])
      |> apply_igniter!()

    chat_content =
      igniter.rewrite.sources["lib/test/chat.ex"]
      |> Rewrite.Source.get(:content)

    assert chat_content =~ "tool :chat_list_conversations, Test.Chat.Conversation, :read do"
  end

  test "generated UI delegates tool extraction to AshAi.ChatUI.Tools with warning handling", %{
    argv: argv
  } do
    argv = argv ++ ["--live", "--live-component"]

    igniter =
      phx_test_project()
      |> Igniter.compose_task("ash_ai.gen.chat", argv)
      |> apply_igniter!()

    live_content =
      igniter.rewrite.sources["lib/test_web/live/chat_live.ex"]
      |> Rewrite.Source.get(:content)

    component_content =
      igniter.rewrite.sources["lib/test_web/chat_component.ex"]
      |> Rewrite.Source.get(:content)

    assert live_content =~ "@chat_ui_tools AshAi.ChatUI.Tools"
    assert live_content =~ "defp tool_calls(message), do: safe_extract(message).tool_calls"
    assert live_content =~ "defp tool_results(message), do: safe_extract(message).tool_results"
    assert live_content =~ "put_flash(:warning, \"Some tool call data could not be displayed.\")"
    assert live_content =~ "Phoenix.Flash.get(@flash, :warning)"
    assert live_content =~ "tool_call.arguments_preview"
    assert live_content =~ "tool_result.content_preview"
    refute live_content =~ "defp normalize_tool_call_arguments("
    refute live_content =~ "defp tool_result_preview("

    assert component_content =~ "@chat_ui_tools AshAi.ChatUI.Tools"
    assert component_content =~ "defp tool_calls(message), do: safe_extract(message).tool_calls"

    assert component_content =~
             "defp tool_results(message), do: safe_extract(message).tool_results"

    assert component_content =~
             "put_flash(:warning, \"Some tool call data could not be displayed.\")"

    assert component_content =~ "Phoenix.Flash.get(@flash, :warning)"
    assert component_content =~ "tool_call.arguments_preview"
    assert component_content =~ "tool_result.content_preview"
    refute component_content =~ "defp normalize_tool_call_arguments("
    refute component_content =~ "defp tool_result_preview("
  end
end
