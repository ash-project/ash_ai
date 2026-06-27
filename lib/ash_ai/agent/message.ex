# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Agent.Message do
  @moduledoc """
  Resource extension that injects the schema for an agent's conversation messages.

  Each row represents one message in an agent's lifecycle: a user input, an
  assistant output, a tool call, a tool result, an event delivered from another
  agent, or a compaction summary. The same table holds both pending inbox events
  (awaiting handling by the receiving agent) and the active conversation history,
  distinguished by the `pending` flag and grouped into memory eras by `generation`.

  ## Usage

      defmodule MyApp.Agents.Message do
        use Ash.Resource,
          extensions: [AshAi.Agent.Message],
          data_layer: AshPostgres.DataLayer

        message do
          directory MyApp.Agents.Agent
        end

        actions do
          defaults [:read, :create]
        end

        postgres do
          table "agent_messages"
          repo MyApp.Repo
        end
      end

  When `directory` is configured (pointing at an `AshAi.Agents.Directory`-extended
  resource), the extension wires `agent_id` and `sender_id` as proper `belongs_to`
  relationships to the directory, giving you DB-level referential integrity for
  cross-agent references. Without it, both fields are plain uuid columns.

  See the moduledoc of `AshAi.Agent.Message.Transformer` for the full list of
  injected attributes.
  """

  @message_section %Spark.Dsl.Section{
    name: :message,
    describe: "Configures the message resource.",
    schema: [
      directory: [
        type: {:spark, Ash.Resource},
        required: false,
        doc: ~S"""
        The `AshAi.Agents.Directory` resource that `agent_id` / `sender_id`
        reference. When set, `agent_id` and `sender_id` become `belongs_to`
        relationships to the directory (DB-level referential integrity). When
        omitted, both remain plain uuid columns.
        """
      ]
    ]
  }

  use Spark.Dsl.Extension,
    sections: [@message_section],
    transformers: [AshAi.Agent.Message.Transformer]
end
