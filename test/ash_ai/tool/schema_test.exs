# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Tool.SchemaTest do
  use ExUnit.Case, async: true

  alias AshAi.Tool.Schema

  defp strict(properties, required \\ []) do
    Schema.make_strict_schema(%{
      "type" => "object",
      "properties" => properties,
      "required" => required
    })
  end

  describe "make_strict_schema/1" do
    test "an optional field is made nullable with a type list" do
      assert strict(%{"note" => %{"type" => "string"}})["properties"]["note"] ==
               %{"type" => ["string", "null"]}
    end

    # Anthropic's structured output refuses an enum whose `type` is a list, even with
    # null among its values; an `anyOf` with null is accepted by it and by OpenAI.
    test "an optional enum is made nullable with anyOf, keeping its description outside" do
      schema =
        strict(%{
          "meal" => %{
            "type" => "string",
            "enum" => ["breakfast", "lunch"],
            "description" => "Which meal"
          }
        })

      assert schema["properties"]["meal"] == %{
               "description" => "Which meal",
               "anyOf" => [
                 %{"type" => "null"},
                 %{"type" => "string", "enum" => ["breakfast", "lunch"]}
               ]
             }

      assert schema["required"] == ["meal"]
    end

    test "a required enum is left as it is" do
      meal = %{"type" => "string", "enum" => ["breakfast", "lunch"]}
      assert strict(%{"meal" => meal}, ["meal"])["properties"]["meal"] == meal
    end

    test "an enum that already allows null is left as it is" do
      meal = %{"enum" => ["breakfast", nil]}
      assert strict(%{"meal" => meal})["properties"]["meal"] == meal
    end
  end
end
