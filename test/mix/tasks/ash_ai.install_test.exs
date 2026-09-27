# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule Mix.Tasks.AshAi.InstallTest do
  use ExUnit.Case

  import Igniter.Test

  test "adds req_llm as a dependency by default" do
    igniter =
      phx_test_project()
      |> Igniter.compose_task("ash_ai.install", ["--yes"])
      |> assert_has_patch("mix.exs", """
      + |      {:req_llm, "~> 1.18"},
      """)

    assert {"deps.get", []} in igniter.tasks
  end

  test "installs the dev MCP without pinning an old protocol version" do
    igniter =
      phx_test_project()
      |> Igniter.compose_task("ash_ai.install", ["--yes"])

    endpoint_diff =
      igniter.rewrite.sources
      |> Map.take(["lib/test_web/endpoint.ex"])
      |> Igniter.diff(color?: false)

    assert endpoint_diff =~ "plug AshAi.Mcp.Dev"
    refute endpoint_diff =~ "protocol_version_statement"
  end

  test "--no-req-llm skips adding the req_llm dependency" do
    igniter =
      phx_test_project()
      |> Igniter.compose_task("ash_ai.install", ["--yes", "--no-req-llm"])

    assert_unchanged(igniter, "mix.exs")
    refute {"deps.get", []} in igniter.tasks
  end
end
