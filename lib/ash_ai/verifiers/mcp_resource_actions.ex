# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Verifiers.McpResourceActions do
  @moduledoc """
  Verifies that each `mcp_resource` can be read.

    * Its action is a generic action.
    * Without `contents`, the action returns `:string` (sent as text) or
      `:binary` (sent as a blob). With `contents`, it returns a value of any type.
    * Each variable of a URI template is an argument of the action.
  """
  use Spark.Dsl.Verifier

  @impl true
  def verify(dsl_state) do
    dsl_state
    |> AshAi.Info.mcp_action_resources()
    |> Enum.flat_map(fn mcp_resource ->
      mcp_resource.resource
      |> Ash.Resource.Info.action(mcp_resource.action)
      |> problems(mcp_resource)
      |> Enum.map(&"  :#{mcp_resource.name} - #{&1}")
    end)
    |> case do
      [] ->
        :ok

      problems ->
        {:error,
         Spark.Error.DslError.exception(
           message: """
           Invalid mcp_resources:

           #{Enum.join(problems, "\n")}
           """,
           path: [:mcp_resources, :mcp_resource],
           module: Spark.Dsl.Verifier.get_persisted(dsl_state, :module)
         )}
    end
  end

  defp problems(nil, mcp_resource),
    do: ["#{inspect(mcp_resource.resource)} has no action #{inspect(mcp_resource.action)}"]

  defp problems(%{type: :action} = action, mcp_resource),
    do: return_problems(action, mcp_resource) ++ template_problems(action, mcp_resource)

  defp problems(action, _mcp_resource),
    do: [
      "#{inspect(action.name)} is a #{action.type} action; resources must use a generic action"
    ]

  defp return_problems(%{returns: nil} = action, _mcp_resource),
    do: ["#{inspect(action.name)} must return a value"]

  defp return_problems(%{returns: returns}, %{contents: nil})
       when returns in [Ash.Type.String, Ash.Type.Binary],
       do: []

  defp return_problems(action, %{contents: nil}) do
    [
      "#{inspect(action.name)} returns #{inspect(action.returns)}; without `contents`, " <>
        "it must return :string (sent as text) or :binary (sent as a blob)"
    ]
  end

  defp return_problems(_action, _mcp_resource), do: []

  defp template_problems(_action, %{uri_template: nil}), do: []

  defp template_problems(action, %{uri_template: template}) do
    arguments = Enum.map(action.arguments, &to_string(&1.name))

    for variable <- AshAi.Mcp.UriTemplate.variables(template), variable not in arguments do
      "the URI template variable `#{variable}` isn't an argument of #{inspect(action.name)}"
    end
  end
end
