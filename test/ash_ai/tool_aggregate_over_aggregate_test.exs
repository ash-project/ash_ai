# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.ToolAggregateOverAggregateTest do
  @moduledoc """
  An aggregate is offered as a field the `aggregate` result_type can fold, but it
  declares a type only to override the one its kind implies, so a plain `count`
  carries none.

  Reading the type straight off the field left `Ash.Query.Aggregate.kind_to_type/3`
  with `nil`, which it refuses for `avg` — and the refusal met a strict `{:ok, _, _}`
  match, so the caller got a `MatchError` reported as a generic error rather than
  the average it asked for.
  """
  use AshAi.RepoCase, async: false

  alias __MODULE__.{AggDomain, AggResource}

  defmodule AggResource do
    @moduledoc false
    use Ash.Resource,
      domain: AggDomain,
      data_layer: AshPostgres.DataLayer

    postgres do
      table("artists")
      repo(AshAi.TestRepo)
    end

    attributes do
      uuid_v7_primary_key(:id, writable?: true)

      attribute(:name, :string, public?: true)
    end

    relationships do
      has_many :namesakes, __MODULE__ do
        source_attribute :name
        destination_attribute :name
      end
    end

    aggregates do
      count :namesake_count, :namesakes do
        public? true
      end
    end

    actions do
      defaults([:read, :create])
      default_accept([:name])
    end
  end

  defmodule AggDomain do
    @moduledoc false
    use Ash.Domain, extensions: [AshAi]

    resources do
      resource(AggResource)
    end

    tools do
      tool(:read_agg, AggResource, :read)
    end
  end

  defp fold(kind) do
    {_tools, registry} =
      AshAi.build_tools_and_registry(
        actions: [{AggResource, [:read]}],
        tools: [:read_agg],
        strict: false
      )

    registry["read_agg"].(
      %{"result_type" => %{"aggregate" => kind, "field" => "namesake_count"}},
      %{actor: nil, tenant: nil, context: %{}, tool_callbacks: %{}}
    )
  end

  setup do
    for name <- ["blue", "blue", "blue", "red"] do
      AggResource
      |> Ash.Changeset.for_create(:create, %{name: name})
      |> Ash.create!(authorize?: false)
    end

    :ok
  end

  test "an aggregate's own type is resolved, so avg over it returns the average" do
    assert {:ok, _json, value} = fold("avg")

    assert value == 2.5
  end

  test "the kinds that tolerated an unresolved type keep working" do
    assert {:ok, _json, 3} = fold("max")
    assert {:ok, _json, 10} = fold("sum")
  end
end
