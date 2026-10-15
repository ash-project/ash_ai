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

  test "warns with an example plug when the endpoint has no code_reloading? block" do
    igniter =
      phx_test_project()
      |> Igniter.update_elixir_file("lib/test_web/endpoint.ex", fn zipper ->
        Igniter.Code.Common.remove(zipper, fn zipper ->
          Igniter.Code.Function.function_call?(zipper, :if, 2)
        end)
      end)
      |> Mix.Tasks.AshAi.Gen.Mcp.add_plug_to_endpoint(TestWeb.Endpoint, :test)

    assert [warning] = igniter.warnings
    assert warning =~ "if code_reloading? do"
    assert warning =~ "plug AshAi.Mcp.Dev,"
    assert warning =~ "otp_app: :test,"
    refute warning =~ "code_relading?"
  end

  test "--no-req-llm skips adding the req_llm dependency" do
    igniter =
      phx_test_project()
      |> Igniter.compose_task("ash_ai.install", ["--yes", "--no-req-llm"])

    assert_unchanged(igniter, "mix.exs")
    refute {"deps.get", []} in igniter.tasks
  end
end
