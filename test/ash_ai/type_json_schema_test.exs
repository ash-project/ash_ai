# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.TypeJsonSchemaTest do
  use ExUnit.Case, async: true

  alias __MODULE__.{Domain, Report}

  defmodule MapType do
    @moduledoc false
    # The `Ash.Type` callbacks shared by the test types: any map is valid.
    defmacro __using__(_) do
      quote do
        use Ash.Type
        @behaviour AshAi.Type

        @impl Ash.Type
        def storage_type(_), do: :map
        @impl Ash.Type
        def cast_input(nil, _), do: {:ok, nil}
        def cast_input(value, _) when is_map(value), do: {:ok, value}
        def cast_input(_, _), do: :error
        @impl Ash.Type
        def cast_stored(value, constraints), do: cast_input(value, constraints)
        @impl Ash.Type
        def dump_to_native(value, constraints), do: cast_input(value, constraints)
      end
    end
  end

  defmodule Point do
    @moduledoc false
    use MapType

    @impl AshAi.Type
    def ai_json_schema(_constraints) do
      %{
        "type" => "object",
        "properties" => %{"x" => %{"type" => "number"}, "y" => %{"type" => "number"}},
        "required" => ["x", "y"]
      }
    end
  end

  @condition %{
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
        "properties" => %{"key" => %{"type" => "string"}, "eq" => %{"type" => "string"}},
        "required" => ["key", "eq"]
      }
    ]
  }

  defmodule Condition do
    @moduledoc false
    use MapType

    @impl AshAi.Type
    def ai_json_schema(_constraints), do: %{"$ref" => "#/$defs/Condition"}

    @impl AshAi.Type
    def ai_json_schema_defs(_constraints) do
      %{"Condition" => AshAi.TypeJsonSchemaTest.condition()}
    end
  end

  # Defines `Condition` differently from `Condition` above.
  defmodule OtherCondition do
    @moduledoc false
    use MapType

    @impl AshAi.Type
    def ai_json_schema(_constraints), do: %{"$ref" => "#/$defs/Condition"}

    @impl AshAi.Type
    def ai_json_schema_defs(_constraints), do: %{"Condition" => %{"type" => "string"}}
  end

  defmodule Filter do
    @moduledoc false
    use Ash.Type.NewType, subtype_of: Condition
  end

  defmodule Rule do
    @moduledoc false
    use Ash.Resource, data_layer: :embedded

    attributes do
      attribute :condition, Condition, public?: true, allow_nil?: false
    end

    actions do
      defaults [:read, :destroy, create: :*, update: :*]
    end
  end

  defmodule Report do
    @moduledoc false
    use Ash.Resource, domain: Domain, data_layer: Ash.DataLayer.Ets, extensions: [AshAi]

    ets do
      private? true
    end

    attributes do
      uuid_v7_primary_key :id
    end

    actions do
      action :create_report, :boolean do
        argument :point, Point, allow_nil?: false
        argument :condition, Condition, allow_nil?: false
        argument :conditions, {:array, Condition}
        argument :filter, Filter
        argument :rule, Rule
        argument :either, :union, constraints: [types: [condition: [type: Condition]]]
        argument :wrapper, :map, constraints: [fields: [condition: [type: Condition]]]
        run fn _input, _context -> {:ok, true} end
      end

      action :place_point, :boolean do
        argument :point, Point, allow_nil?: false
        run fn _input, _context -> {:ok, true} end
      end

      action :conflicting, :boolean do
        argument :condition, Condition
        argument :other, OtherCondition
        run fn _input, _context -> {:ok, true} end
      end

      action :suggest_condition, Condition do
        run prompt("openai:gpt-4o",
              prompt: "Suggest a condition",
              req_llm: AshAi.TypeJsonSchemaTest.FakeReqLLM
            )
      end
    end
  end

  defmodule Domain do
    @moduledoc false
    use Ash.Domain, extensions: [AshAi]

    resources do
      resource Report
    end

    tools do
      tool :place_point, Report, :place_point
      tool :create_report, Report, :create_report
      tool :conflicting, Report, :conflicting
    end
  end

  defmodule FakeReqLLM do
    @moduledoc false
    def generate_object(_model, _context, schema, _opts \\ []) do
      send(self(), {:schema, schema})
      {:ok, %{object: %{"result" => %{"key" => "status", "eq" => "open"}}}}
    end
  end

  def condition, do: @condition

  defp tool(name) do
    [otp_app: :ash_ai, actions: [{Report, :*}]]
    |> AshAi.exposed_tools()
    |> Enum.find(&(&1.name == name))
  end

  defp input_schema(name, opts \\ [strict: false]) do
    AshAi.Tools.parameter_schema(tool(name), opts)
  end

  defp input_properties(schema), do: schema["properties"]["input"]["properties"]

  test "a type's own schema describes the input" do
    schema = input_schema(:create_report)

    assert input_properties(schema)["point"] == Point.ai_json_schema([])
  end

  test "a type without definitions adds no $defs" do
    schema = input_schema(:place_point)

    assert input_properties(schema)["point"] == Point.ai_json_schema([])
    refute Map.has_key?(schema, "$defs")
  end

  test "a recursive type's definitions are placed under the root $defs, once" do
    schema = input_schema(:create_report)
    properties = input_properties(schema)
    ref = %{"$ref" => "#/$defs/Condition"}

    assert schema["$defs"] == %{"Condition" => @condition}

    assert properties["condition"] == ref
    assert properties["conditions"] == %{"type" => "array", "items" => ref}
    assert properties["filter"] == ref
    assert properties["either"] == ref

    assert ref in properties["wrapper"]["properties"]["condition"]["anyOf"]

    assert properties["rule"]["properties"]["condition"] == ref

    refute schema |> Map.delete("$defs") |> inspect() =~ ~s("$defs" =>)
  end

  test "strict mode applies to the definitions" do
    schema = input_schema(:create_report, strict: true)

    assert %{"anyOf" => [all, comparison]} = schema["$defs"]["Condition"]
    assert all["additionalProperties"] == false
    assert comparison["additionalProperties"] == false
  end

  test "ReqLLM tools carry the definitions" do
    [otp_app: :ash_ai, actions: [{Report, [:create_report]}], tools: [:create_report]]
    |> AshAi.list_tools()
    |> Enum.find(&(&1.name == "create_report"))
    |> then(&assert(Map.keys(&1.parameter_schema["$defs"]) == ["Condition"]))
  end

  test "two different definitions with the same name raise" do
    assert_raise ArgumentError,
                 ~r/Two different JSON Schema definitions are named "Condition"/,
                 fn ->
                   input_schema(:conflicting)
                 end
  end

  test "a prompt-backed action's result schema carries the definitions" do
    Report
    |> Ash.ActionInput.for_action(:suggest_condition, %{})
    |> Ash.run_action!()

    assert_receive {:schema, schema}
    assert schema["properties"]["result"] == %{"$ref" => "#/$defs/Condition"}
    assert schema["$defs"] == %{"Condition" => @condition}
  end
end
