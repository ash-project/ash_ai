# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Agent.Transformer do
  @moduledoc false
  use Spark.Dsl.Transformer

  import Ash.Resource.Builder

  def before?(Ash.Resource.Transformers.CachePrimaryKey), do: true
  def before?(_), do: false

  def transform(dsl) do
    messages_module = AshAi.Agent.Info.agent_messages!(dsl)
    {:ok, message_arg} = build_action_argument(:message, :string, allow_nil?: true)

    dsl
    |> add_new_attribute(:id, :uuid_v7,
      primary_key?: true,
      allow_nil?: false,
      default: &Ash.UUIDv7.generate/0,
      writable?: false,
      public?: true
    )
    # current_generation is internal (used by compaction's memory-era
    # filtering). Not surfaced to LLMs or in tool responses — leave
    # private so it stays out of state-dumps.
    |> add_new_attribute(:current_generation, :integer,
      allow_nil?: false,
      default: 0,
      public?: false
    )
    # Observable lifecycle state for UIs / monitoring. Updated at turn
    # boundaries and around compaction; not enforced as a strict guard.
    |> add_new_attribute(:state, :atom,
      allow_nil?: false,
      default: :idle,
      constraints: [one_of: [:idle, :working, :compacting, :stopped, :errored]],
      public?: true
    )
    # Last-turn failure detail (set when state transitions to :errored).
    |> add_new_attribute(:last_error, :string,
      allow_nil?: true,
      public?: true
    )
    # Tracking timestamp; not LLM-relevant.
    |> add_new_update_timestamp(:updated_at, public?: false)
    |> add_new_relationship(:has_many, :messages, messages_module,
      destination_attribute: :agent_id,
      public?: true
    )
    |> add_new_action(:update, :run_turn,
      transaction?: false,
      require_atomic?: false,
      accept: [],
      arguments: [message_arg],
      changes: [
        %Ash.Resource.Change{
          change: {AshAi.Agent.Changes.RunTurn, []},
          on: nil,
          only_when_valid?: true,
          description: nil,
          always_atomic?: false,
          where: []
        }
      ]
    )
    # Internal action used by AshAi.Agent.Server to update lifecycle state
    # (`:state`, `:last_error`) without touching anything else.
    |> add_new_action(:update, :update_lifecycle_state,
      accept: [:state, :last_error],
      require_atomic?: false
    )
    # Internal action used by compaction to advance the memory generation.
    |> add_new_action(:update, :bump_generation,
      accept: [:current_generation],
      require_atomic?: false
    )
    |> add_change({AshAi.Agent.Changes.SyncDirectory, []})
  end
end
