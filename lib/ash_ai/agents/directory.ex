# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Agents.Directory do
  @moduledoc """
  Resource extension for the polymorphic agent identity table.

  Every agent — regardless of which `AshAi.Agent`-extended resource it belongs
  to — has exactly one row in the directory. The directory record's id matches
  the source agent's id, so the same uuid identifies both the per-type record
  and its directory entry. The directory is the canonical "this agent exists"
  record that everything else (Message FKs, the policy actor, etc.) references.

  ## Usage

      defmodule MyApp.Agents.Agent do
        use Ash.Resource,
          extensions: [AshAi.Agents.Directory],
          data_layer: AshPostgres.DataLayer

        actions do
          defaults [:create, :read, :update, :destroy]
        end

        postgres do
          table "agents"
          repo MyApp.Repo
        end
      end

  The extension injects:

    * `:id` — uuid_v7 primary key, writable (no default), set to the source
      agent's id at create time
    * `:agent_resource` — the inspect form of the source resource module (e.g.
      `"MyApp.Agents.Chat"`)
    * `:inserted_at`, `:updated_at` timestamps

  Agents using `AshAi.Agent` with the `directory` option pointing at this
  resource will auto-insert a row here on create and remove it on destroy.
  """

  @directory_section %Spark.Dsl.Section{
    name: :directory,
    describe: "Configures the agent directory.",
    schema: [
      agents: [
        type: {:list, {:spark, Ash.Resource}},
        required: true,
        doc: ~S"""
        List of agent resource modules registered in this directory. Each
        agent's `AshAi.Agent` extension verifies at compile time that its
        resource appears here.
        """
      ]
    ]
  }

  use Spark.Dsl.Extension,
    sections: [@directory_section],
    transformers: [AshAi.Agents.Directory.Transformer]
end
