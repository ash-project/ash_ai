# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Type do
  @moduledoc """
  The behaviour for describing a custom `Ash.Type` to an LLM.

  By default, ash_ai has no JSON Schema for a custom type and describes it as
  `{}` (any value). A type can describe itself by implementing
  `c:ai_json_schema/1`, which takes the type's constraints and returns its
  JSON Schema. It is used wherever the type appears in a tool's input, a
  prompt-backed action's result, or inside an array, map, union, embedded
  resource or `Ash.Type.NewType`.

  A schema can reference named definitions with `"$ref": "#/$defs/<name>"`,
  which is how a recursive type refers to itself. Return those definitions,
  keyed by name, from `c:ai_json_schema_defs/1`. They are placed under the
  root schema's `$defs`, merged with the definitions of every other input.
  Two different definitions with the same name raise an error.

  ash_ai finds the types that contribute definitions by following each
  input's type through arrays, `Ash.Type.NewType`s, the fields of embedded
  resources, and `c:Ash.Type.referenced_types/1`. A custom type that wraps
  other types needs `referenced_types/1` for their definitions to be found.
  It stops at a type that implements `c:ai_json_schema/1`, since that schema
  replaces whatever its subtypes would describe.

      defmodule MyApp.Condition do
        use Ash.Type
        @behaviour AshAi.Type

        @impl AshAi.Type
        def ai_json_schema(_constraints), do: %{"$ref" => "#/$defs/Condition"}

        @impl AshAi.Type
        def ai_json_schema_defs(_constraints) do
          %{
            "Condition" => %{
              "anyOf" => [
                %{
                  "type" => "object",
                  "properties" => %{
                    "all" => %{"type" => "array", "items" => %{"$ref" => "#/$defs/Condition"}}
                  },
                  "required" => ["all"]
                },
                %{
                  "type" => "object",
                  "properties" => %{"key" => %{"type" => "string"}, "eq" => %{}},
                  "required" => ["key", "eq"]
                }
              ]
            }
          }
        end

        # ... the rest of the `Ash.Type` callbacks
      end

  The callbacks are named so that a type can also implement ash_json_api's
  `json_schema/1`.
  """

  @doc "The JSON Schema for a value of this type, given its constraints."
  @callback ai_json_schema(constraints :: Keyword.t()) :: map()

  @doc """
  The named definitions that `c:ai_json_schema/1` references, keyed by name.

  They are placed under the root schema's `$defs`.
  """
  @callback ai_json_schema_defs(constraints :: Keyword.t()) :: %{String.t() => map()}

  @optional_callbacks ai_json_schema: 1, ai_json_schema_defs: 1
end
