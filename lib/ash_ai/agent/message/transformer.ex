# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Agent.Message.Transformer do
  @moduledoc false
  use Spark.Dsl.Transformer

  import Ash.Resource.Builder
  import Spark.Dsl.Builder

  @roles [:system, :user, :assistant, :tool_call, :tool_result, :event, :summary, :agent]

  def before?(Ash.Resource.Transformers.CachePrimaryKey), do: true
  def before?(_), do: false

  def transform(dsl) do
    dsl
    |> add_new_attribute(:id, :uuid_v7,
      primary_key?: true,
      allow_nil?: false,
      default: &Ash.UUIDv7.generate/0,
      # Writable so callers can pre-allocate the id (via `Ash.UUIDv7.generate/0`)
      # and use it as a correlation handle in streaming events before the row
      # actually exists. Default still fires when no id is provided.
      writable?: true
    )
    |> add_new_attribute(:agent_id, :uuid,
      allow_nil?: false,
      public?: true
    )
    |> add_new_attribute(:sender_id, :uuid,
      allow_nil?: true,
      public?: true
    )
    |> add_new_attribute(:role, :atom,
      allow_nil?: false,
      constraints: [one_of: @roles],
      public?: true
    )
    |> add_new_attribute(:message, :string,
      allow_nil?: false,
      public?: true
    )
    |> add_new_attribute(:data, :map,
      allow_nil?: true,
      public?: true
    )
    |> add_new_attribute(:tool_call_id, :string,
      allow_nil?: true,
      public?: true
    )
    |> add_new_attribute(:token_count, :integer,
      allow_nil?: true,
      public?: true
    )
    |> add_new_attribute(:pending, :boolean,
      allow_nil?: false,
      default: false,
      public?: true
    )
    |> add_new_attribute(:generation, :integer,
      allow_nil?: true,
      public?: true
    )
    |> add_new_attribute(:metadata, :map,
      allow_nil?: false,
      default: %{},
      public?: true
    )
    |> add_new_create_timestamp(:inserted_at, public?: true)
    |> add_new_action(:update, :update,
      accept: [:pending, :generation],
      require_atomic?: false
    )
    |> add_directory_relationships()
  end

  defbuilder add_directory_relationships(dsl) do
    case Spark.Dsl.Extension.get_opt(dsl, [:message], :directory, nil) do
      nil ->
        # No directory configured — agent_id/sender_id stay plain uuid columns.
        dsl

      directory ->
        dsl
        |> add_new_relationship(:belongs_to, :agent, directory,
          source_attribute: :agent_id,
          define_attribute?: false,
          allow_nil?: false,
          public?: true
        )
        |> add_new_relationship(:belongs_to, :sender, directory,
          source_attribute: :sender_id,
          define_attribute?: false,
          allow_nil?: true,
          public?: true
        )
    end
  end
end
