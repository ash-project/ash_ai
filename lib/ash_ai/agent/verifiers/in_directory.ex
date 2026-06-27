# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Agent.Verifiers.InDirectory do
  @moduledoc """
  Verifies at compile time that the agent resource is listed in its configured
  directory's `agents` list. Catches mistakes where you add an agent but forget
  to register it in the directory.
  """
  use Spark.Dsl.Verifier

  @impl true
  def verify(dsl) do
    resource = Spark.Dsl.Verifier.get_persisted(dsl, :module)
    directory = AshAi.Agent.Info.agent_directory!(dsl)
    registered = AshAi.Agents.Directory.Info.directory_agents!(directory)

    if resource in registered do
      :ok
    else
      {:error,
       Spark.Error.DslError.exception(
         module: resource,
         path: [:agent, :directory],
         message: """
         #{inspect(resource)} is configured to register in directory \
         #{inspect(directory)}, but it is not listed in that directory's `agents` \
         list.

         Add it to the directory:

             directory do
               agents [#{inspect(resource)}, ...]
             end
         """
       )}
    end
  end
end
