# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Agents.Directory.Calculations.Implementation do
  @moduledoc """
  Polymorphic calculation that returns the actual agent record (Chat,
  Researcher, etc.) wrapped in `%Ash.Union{}` keyed by the agent's DSL-declared
  type. Loadable via `Ash.load!(directory_record, :implementation)`.

  Dispatches on the directory record's `type` discriminator using the
  `agents_by_type` map injected at compile time by the directory transformer.
  Directory.id is shared with the underlying agent's id, so the dispatched
  resource is fetched by the same id.
  """
  use Ash.Resource.Calculation
  require Ash.Query

  @impl true
  def calculate(records, opts, _context) do
    agents_by_type = Keyword.fetch!(opts, :agents_by_type)

    records
    |> Enum.group_by(& &1.type)
    |> Enum.flat_map(fn {type, dir_records} ->
      case Map.get(agents_by_type, type) do
        nil ->
          Enum.map(dir_records, &{&1.id, nil})

        module ->
          ids = Enum.map(dir_records, & &1.id)
          agents_by_id = load_agents(module, ids)

          Enum.map(dir_records, fn dir ->
            case Map.get(agents_by_id, dir.id) do
              nil -> {dir.id, nil}
              value -> {dir.id, %Ash.Union{type: type, value: value}}
            end
          end)
      end
    end)
    |> Map.new()
    |> then(fn lookup -> Enum.map(records, &Map.get(lookup, &1.id)) end)
  end

  defp load_agents(module, ids) do
    module
    |> Ash.Query.filter(id in ^ids)
    |> Ash.read!()
    |> Map.new(&{&1.id, &1})
  end
end
