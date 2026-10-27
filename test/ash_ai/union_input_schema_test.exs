# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.UnionInputSchemaTest do
  use ExUnit.Case, async: true

  defmodule Empty do
    use Ash.Resource, data_layer: :embedded

    actions do
      defaults [:create, :update]
      default_accept :*
    end
  end

  defmodule CurrentRating do
    use Ash.Type.Enum, values: [:low, :high]
  end

  # Every value was retired
  defmodule ArchivedRating do
    use Ash.Type.Enum, values: []
  end

  test "fieldless union members have distinct, required discriminators" do
    schema =
      schema(
        first: [type: Empty, tag: :__type__, tag_value: "first"],
        second: [type: Empty, tag: :__type__, tag_value: "second"]
      )

    assert %{"anyOf" => branches} = schema
    tags = Enum.map(branches, &get_in(&1, ["properties", "__type__", "enum"]))
    assert Enum.sort(tags) == [["first"], ["second"]]
    assert Enum.all?(branches, &(&1["required"] == ["__type__"]))
  end

  test "uses the configured tag name and preserves its value" do
    for {value, type, encoded} <- [
          {:named, "string", "named"},
          {nil, "null", nil},
          {false, "boolean", false},
          {42, "number", 42}
        ] do
      schema = schema(variant: [type: Empty, tag: :kind, tag_value: value])
      assert schema["properties"]["kind"] == %{"type" => type, "enum" => [encoded]}
      assert schema["required"] == ["kind"]
    end
  end

  test "untagged unions are unchanged" do
    assert %{"anyOf" => branches} = schema(text: [type: :string], number: [type: :integer])
    assert Enum.sort(branches) == Enum.sort([%{"type" => "string"}, %{"type" => "integer"}])
  end

  describe "members that can never match" do
    test "empty enum members are dropped" do
      assert schema(archived: [type: ArchivedRating], current: [type: CurrentRating]) ==
               %{"type" => "string", "enum" => ["low", "high"]}
    end

    test "empty atom one_of members are dropped" do
      assert schema(retired: [type: :atom, constraints: [one_of: []]], text: [type: :string]) ==
               %{"type" => "string"}
    end

    test "a union of only empty enums still rejects every value" do
      assert schema(archived: [type: ArchivedRating]) == %{"type" => "string", "enum" => []}
    end

    test "empty enum members are dropped from unions nested in typed maps" do
      {:ok, constraints} =
        Ash.Type.init(:map,
          fields: [
            rating: [
              type: :union,
              allow_nil?: false,
              constraints: [
                types: [archived: [type: ArchivedRating], current: [type: CurrentRating]]
              ]
            ]
          ]
        )

      assert %{"properties" => %{"rating" => rating}} =
               encode(%{type: Ash.Type.Map, constraints: constraints})

      assert rating == %{"type" => "string", "enum" => ["low", "high"]}
    end
  end

  defp schema(types) do
    {:ok, constraints} = Ash.Type.init(:union, types: types)
    encode(%{type: Ash.Type.Union, constraints: constraints})
  end

  defp encode(attr) do
    attr
    |> AshAi.OpenApi.resource_write_attribute_type(Empty, :create)
    |> Jason.encode!()
    |> Jason.decode!()
  end
end
