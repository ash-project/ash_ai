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

  defp schema(types) do
    {:ok, constraints} = Ash.Type.init(:union, types: types)

    %{type: Ash.Type.Union, constraints: constraints}
    |> AshAi.OpenApi.resource_write_attribute_type(Empty, :create)
    |> Jason.encode!()
    |> Jason.decode!()
  end
end
