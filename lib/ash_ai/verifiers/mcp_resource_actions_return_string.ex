# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Verifiers.McpResourceActionsReturnString do
  @moduledoc """
  Verifies that all MCP resource actions return strings.

  This verifier ensures that actions used as MCP resources have a return type
  of `Ash.Type.String`, which is required for MCP protocol compatibility.
  """
  use Spark.Dsl.Verifier

  @impl true
  def verify(dsl_state) do
    dsl_state
    |> AshAi.Info.mcp_resources()
    |> Enum.map(&%{&1 | action: Ash.Resource.Info.action(&1.resource, &1.action)})
    |> Enum.filter(fn %{action: action} ->
      action.returns != Ash.Type.String
    end)
    |> case do
      [] ->
        :ok

      invalid_mcp_resources ->
        {:error,
         Spark.Error.DslError.exception(
           message: """
           All mcp resource actions must return strings.

           The following mcp_resources do not return strings: 
           #{Enum.map_join(invalid_mcp_resources, "\n", &"  :#{to_string(&1.name)}")}

           """,
           path: [:mcp_resources, :mpc_resource, :action],
           module: Spark.Dsl.Verifier.get_persisted(dsl_state, :module)
         )}
    end
  end
end
