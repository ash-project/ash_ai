# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule Mix.Tasks.AshAi.Gen.ChatTest do
  use ExUnit.Case
  import Igniter.Test

  test "it doesnt explode" do
    phx_test_project()
    |> Igniter.compose_task("ash_ai.gen.chat", [
      "--user",
      "MyApp.Accounts.User",
      "--extend",
      "ets"
    ])
    |> apply_igniter!()
  end
end
