# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule Mix.Tasks.AshAi.InstallTest do
  use ExUnit.Case

  import Igniter.Test

  test "adds req_llm as a dependency by default" do
    phx_test_project()
    |> Igniter.compose_task("ash_ai.install", ["--yes"])
    |> assert_has_patch("mix.exs", """
    + |      {:req_llm, "~> 1.18"},
    """)
  end

  test "--no-req-llm skips adding the req_llm dependency" do
    igniter =
      phx_test_project()
      |> Igniter.compose_task("ash_ai.install", ["--yes", "--no-req-llm"])

    assert_unchanged(igniter, "mix.exs")
  end
end
