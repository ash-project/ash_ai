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
      defaults [:create]
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

  defmodule TestDomain do
    use Ash.Domain, extensions: [AshAi]

    resources do
      resource UnionResource
    end

    tools do
      tool :read_union_resources, UnionResource, :read
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
end
