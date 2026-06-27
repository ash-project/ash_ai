# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Agents.Directory.Transformer do
  @moduledoc false
  use Spark.Dsl.Transformer

  import Ash.Resource.Builder

  def before?(Ash.Resource.Transformers.CachePrimaryKey), do: true
  def before?(_), do: false

  def transform(dsl) do
    agents = AshAi.Agents.Directory.Info.directory_agents!(dsl)

    types =
      Enum.map(agents, fn agent ->
        AshAi.Agent.Info.agent_type!(agent)
      end)

    union_types =
      Enum.zip(types, agents)
      |> Enum.map(fn {type, agent} ->
        {type, [type: :struct, constraints: [instance_of: agent]]}
      end)

    agents_by_type = Map.new(Enum.zip(types, agents))

    dsl
    |> add_new_attribute(:id, :uuid_v7,
      primary_key?: true,
      allow_nil?: false,
      writable?: true,
      public?: true
    )
    |> add_new_attribute(:type, :atom,
      allow_nil?: false,
      constraints: [one_of: types],
      public?: true
    )
    |> add_new_create_timestamp(:inserted_at, public?: true)
    |> add_new_update_timestamp(:updated_at, public?: true)
    |> add_new_calculation(
      :implementation,
      :union,
      {AshAi.Agents.Directory.Calculations.Implementation, agents_by_type: agents_by_type},
      constraints: [types: union_types],
      public?: true,
      allow_nil?: true
    )
  end
end
