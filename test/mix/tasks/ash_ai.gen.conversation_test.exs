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

  test "generated respond change initializes tool call accumulator as a list", %{argv: argv} do
    argv = argv ++ ["--live"]

    phx_test_project()
    |> Igniter.compose_task("ash_ai.gen.chat", argv)
    |> assert_has_patch("lib/test/chat/message/changes/respond.ex", """
    |Enum.reduce(%{text: "", tool_calls: [], tool_results: []}, fn
    """)
    |> assert_has_patch("lib/test/chat/message/changes/respond.ex", """
    |%{acc | tool_calls: append_event(acc.tool_calls, tool_call)}
    """)
    |> assert_has_patch("lib/test/chat/message/changes/respond.ex", """
    |defp append_event(items, value) when is_list(items), do: items ++ [value]
    """)
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

  test "tool call arguments are preserved and previewed in both generated UI branches", %{
    argv: argv
  } do
    argv = argv ++ ["--live", "--live-component"]

    phx_test_project()
    |> Igniter.compose_task("ash_ai.gen.chat", argv)
    |> assert_has_patch("lib/test_web/live/chat_live.ex", """
    |arguments: normalize_tool_call_arguments(message_field(call, :arguments))
    """)
    |> assert_has_patch("lib/test_web/live/chat_live.ex", """
    |tool_call_arguments_preview(tool_call.arguments)
    """)
    |> assert_has_patch("lib/test_web/chat_component.ex", """
    |arguments: normalize_tool_call_arguments(message_field(call, :arguments))
    """)
    |> assert_has_patch("lib/test_web/chat_component.ex", """
    |tool_call_arguments_preview(tool_call.arguments)
    """)
  end
end
