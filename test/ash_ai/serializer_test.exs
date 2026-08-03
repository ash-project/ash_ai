# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs.contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.SerializerTest do
  use ExUnit.Case, async: true

  defmodule EmbeddedItem do
    use Ash.Resource, data_layer: :embedded

    attributes do
      attribute :label, :string, public?: true, allow_nil?: false
    end

    actions do
      defaults [:create, :read]
      default_accept [:label]
    end
  end

  defmodule UnionResource do
    use Ash.Resource,
      domain: AshAi.SerializerTest.TestDomain,
      data_layer: Ash.DataLayer.Ets

    attributes do
      uuid_v7_primary_key(:id, writable?: true)
      attribute :name, :string, public?: true

      attribute :data, :union,
        public?: true,
        constraints: [
          types: [
            embedded: [type: EmbeddedItem, constraints: []]
          ]
        ]
    end

    actions do
      defaults [:read, :create]
      default_accept [:name, :data]
    end
  end

  defmodule PartialSelectResource do
    use Ash.Resource,
      domain: AshAi.SerializerTest.TestDomain,
      data_layer: Ash.DataLayer.Ets

    attributes do
      uuid_v7_primary_key(:id, writable?: true)
      attribute :name, :string, public?: true
      attribute :amount, :decimal, public?: true
    end

    actions do
      defaults [:create]
      default_accept [:name, :amount]

      read :read_name_only do
        prepare build(select: [:name])
      end
    end
  end

  defmodule AggregateResource do
    use Ash.Resource,
      domain: AshAi.SerializerTest.TestDomain,
      data_layer: Ash.DataLayer.Ets

    attributes do
      uuid_v7_primary_key(:id, writable?: true)
      attribute :amount, :decimal, public?: true
      attribute :category, :string, public?: true
    end

    actions do
      defaults [:read, create: [:amount, :category]]
    end
  end

  defmodule TestDomain do
    use Ash.Domain, extensions: [AshAi]

    resources do
      resource UnionResource
      resource PartialSelectResource
      resource AggregateResource
    end

    tools do
      tool :read_union_resources, UnionResource, :read
      tool :read_partial_select, PartialSelectResource, :read_name_only
      tool :read_aggregate_resources, AggregateResource, :read
    end
  end

  describe "Tools.execute with union-typed attributes" do
    test "serializes union containing embedded resource to JSON" do
      # Mirrors the real failure: a resource with a union attribute whose inner
      # value is a struct. Without the Ash.Union serializer clause, the struct
      # passes through unserialized and Jason.encode! inside Tools.execute
      # raises Protocol.UndefinedError.
      UnionResource
      |> Ash.Changeset.for_create(:create, %{
        name: "test",
        data: %Ash.Union{type: :embedded, value: %EmbeddedItem{label: "hello"}}
      })
      |> Ash.create!()

      [tool] =
        AshAi.exposed_tools(actions: [{UnionResource, :*}])

      assert {:ok, json, _result} = AshAi.Tools.execute(tool, %{}, %{})

      decoded = Jason.decode!(json)
      [item] = decoded
      assert item["data"]["type"] == "embedded"
      assert item["data"]["label"] == "hello"
      assert item["name"] == "test"
    end
  end

  describe "Tools.execute with partial select" do
    test "skips NotLoaded attributes when prepare build(select: ...) is used" do
      PartialSelectResource
      |> Ash.Changeset.for_create(:create, %{
        name: "widget",
        amount: Decimal.new("12.50")
      })
      |> Ash.create!()

      [tool] =
        AshAi.exposed_tools(actions: [{PartialSelectResource, [:read_name_only]}])

      assert {:ok, json, _result} = AshAi.Tools.execute(tool, %{}, %{})

      decoded = Jason.decode!(json)
      [item] = decoded
      assert item["name"] == "widget"
      refute Map.has_key?(item, "amount")
    end
  end

  describe "Tools.execute with decimal aggregates" do
    test "serializes the named aggregate result instead of the result map" do
      for amount <- ["12.50", "7.25"] do
        AggregateResource
        |> Ash.Changeset.for_create(:create, %{
          amount: Decimal.new(amount),
          category: "included"
        })
        |> Ash.create!()
      end

      AggregateResource
      |> Ash.Changeset.for_create(:create, %{
        amount: Decimal.new("100.00"),
        category: "excluded"
      })
      |> Ash.create!()

      [tool] = AshAi.exposed_tools(actions: [{AggregateResource, [:read]}])

      assert {:ok, json, _result} =
               AshAi.Tools.execute(
                 tool,
                 %{
                   "filter" => %{
                     "field" => "category",
                     "operator" => "eq",
                     "value" => "included"
                   },
                   "limit" => 1,
                   "offset" => 1,
                   "result_type" => %{
                     "aggregate" => "sum",
                     "field" => "amount"
                   }
                 },
                 %{}
               )

      assert Jason.decode!(json) == "19.75"
    end
  end
end
