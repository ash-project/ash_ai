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

  defmodule FieldPolicyResource do
    use Ash.Resource,
      domain: AshAi.SerializerTest.TestDomain,
      data_layer: Ash.DataLayer.Ets,
      authorizers: [Ash.Policy.Authorizer]

    attributes do
      uuid_v7_primary_key(:id, writable?: true)
      attribute :name, :string, public?: true
      attribute :secret, :string, public?: true
    end

    actions do
      defaults [:read, create: [:name, :secret]]
    end

    policies do
      policy always() do
        authorize_if always()
      end
    end

    field_policies do
      field_policy :secret do
        authorize_if actor_attribute_equals(:admin, true)
      end

      field_policy :* do
        authorize_if always()
      end
    end
  end

  defmodule NestedFieldPolicyResource do
    use Ash.Resource,
      domain: AshAi.SerializerTest.TestDomain,
      data_layer: Ash.DataLayer.Ets

    attributes do
      uuid_v7_primary_key(:id, writable?: true)
      attribute :name, :string, public?: true
    end

    relationships do
      belongs_to :user, AshAi.SerializerTest.FieldPolicyResource do
        public? true
        attribute_writable? true
      end
    end

    actions do
      defaults [:read, create: [:name, :user_id]]
    end
  end

  defmodule TestDomain do
    use Ash.Domain, extensions: [AshAi]

    resources do
      resource UnionResource
      resource PartialSelectResource
      resource AggregateResource
      resource FieldPolicyResource
      resource NestedFieldPolicyResource
    end

    tools do
      tool :read_union_resources, UnionResource, :read
      tool :read_partial_select, PartialSelectResource, :read_name_only
      tool :read_aggregate_resources, AggregateResource, :read
      tool :read_field_policy_resources, FieldPolicyResource, :read
      tool :read_nested_field_policy_resources, NestedFieldPolicyResource, :read, load: [:user]
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

  describe "Tools.execute with field policies" do
    setup context do
      name = "widget-#{:erlang.phash2(context.test)}"

      user =
        FieldPolicyResource
        |> Ash.Changeset.for_create(:create, %{name: name, secret: "hunter2"}, authorize?: false)
        |> Ash.create!(authorize?: false)

      NestedFieldPolicyResource
      |> Ash.Changeset.for_create(:create, %{name: name, user_id: user.id})
      |> Ash.create!()

      [tool] = AshAi.exposed_tools(actions: [{FieldPolicyResource, [:read]}])
      [nested_tool] = AshAi.exposed_tools(actions: [{NestedFieldPolicyResource, [:read]}])

      {:ok, tool: tool, nested_tool: nested_tool, name: name}
    end

    test "omits fields the actor may not see instead of failing the call", %{
      tool: tool,
      name: name
    } do
      assert {:ok, json, _result} =
               AshAi.Tools.execute(tool, %{}, %{actor: %{admin: false}})

      item = fetch_by_name(json, name)
      assert item["name"] == name
      refute Map.has_key?(item, "secret")
    end

    test "still serializes the field for an actor who may see it", %{tool: tool, name: name} do
      assert {:ok, json, _result} =
               AshAi.Tools.execute(tool, %{}, %{actor: %{admin: true}})

      assert fetch_by_name(json, name)["secret"] == "hunter2"
    end

    test "omits withheld fields on a loaded relationship", %{
      nested_tool: nested_tool,
      name: name
    } do
      assert {:ok, json, _result} =
               AshAi.Tools.execute(nested_tool, %{}, %{actor: %{admin: false}})

      user = fetch_user(json, name)
      assert user["name"] == name
      refute Map.has_key?(user, "secret")
    end

    test "still serializes a relationship field for an actor who may see it", %{
      nested_tool: nested_tool,
      name: name
    } do
      assert {:ok, json, _result} =
               AshAi.Tools.execute(nested_tool, %{}, %{actor: %{admin: true}})

      assert fetch_user(json, name)["secret"] == "hunter2"
    end
  end

  defp fetch_by_name(json, name) do
    json
    |> Jason.decode!()
    |> Enum.find(&(&1["name"] == name))
  end

  defp fetch_user(json, name) do
    record = fetch_by_name(json, name)
    refute is_nil(record), "no record named #{name} in #{json}"
    record["user"]
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
