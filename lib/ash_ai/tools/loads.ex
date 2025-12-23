defmodule AshAi.Tools.Loads do
  @moduledoc """
  Utilities for working with dynamic loads in AshAi tools.

  ## Overview
  This module allows you to inject runtime values (like arguments provided by the LLM)
  into the `load` options of an AshAi tool. This is essential for explicitly passing arguments
  to calculations (e.g. date ranges, thresholds) because we can't assume that it is secure to
  display something externally just because it was loaded by an action we just called.

  ## ⚠️ Important: Action Arguments vs. Hidden Parameters

  When you use `from_input/1`, you are referencing a value provided by the LLM.
  However, you must decide how the LLM *knows* about this value.

  ### Option A: Action Arguments (Recommended)
  Define the argument on your Action.
  * **Pros:** The argument automatically appears in the JSON Schema sent to the LLM. Ash validates the type (e.g. ensures it is a valid Date).
  * **Usage:**
    ```elixir
    read :read_with_arguments do
      argument :date, :date do
        allow_nil? true
        description "The reference date for calculations"
      end
    end
    ```

  ### Option B: Hidden Parameters
  Do not define the argument on the Action; only mention it in the Tool's description.
  * **Pros:** Keeps your Ash Action definition "pure" if the argument is only for loading with tools.
  * **Cons:** The argument **does not appear** in the generated tool schema. You must rely on the LLM reading your text description to know it exists.
  * **Usage:**
    ```elixir
    tool :read_resources, ... do
      description "... can be calculated for a specific 'date' if provided ..."
    end
    ```

  Both options work because `AshAi.Tools` enforces inputs to be present in the action declaration before passing them to
  the Ash Action, preventing `NoSuchInput` errors.
  """

  # A unique token to signal that a key should be dropped from the structure to allow for optional arguments to be completely omitted from the Ash query rather than passing `nil` (which might be invalid for your calculation).
  @drop_token :__ash_ai_drop_key__

  defmodule InputReference do
    @moduledoc """
    Represents a placeholder that will be replaced by a tool input value at runtime.
    """
    defstruct [:key]

    @type t :: %__MODULE__{key: atom()}
  end

  @doc """
  Marks a reference to a tool input argument for use in load definitions.

  The reference will be resolved to the actual input value when the tool executes.
  If the input is missing, the containing element in the load structure will be
  **omitted entirely** (see `resolve_arguments/2` for details).

  ## Example

      load: [
        {:calculation_name, %{arg_name: AshAi.Tools.Loads.from_input(:input_key)}}
      ]
  """
  def from_input(key) when is_atom(key) do
    %InputReference{key: key}
  end

  @doc """
  Recursively traverses the load structure and replaces all `InputReference` structs
  with their corresponding values from the input.

  ## Dropping Missing Inputs
  If a referenced input is missing from the provided `input` map, the behavior
  depends on the structure containing the reference:

  * **Maps:** The key-value pair is removed entirely.
  * **Keyword Lists:** The `{key, value}` tuple is removed entirely.
  * **Lists:** The item is removed from the list.

  This allows optional arguments to be completely omitted from the Ash query
  rather than passing `nil` (which may be invalid in some calculations).

  ## ⚠️ Important: Handling Structs vs. Maps

  This function **does not** traverse into Structs (e.g. `%MyStruct{...}`).
  It treats them as opaque values.

  If your Calculation expects a Struct as an argument (e.g. an Embedded Resource),
  you must pass a **Map** in your load definition to use dynamic inputs.

  Ash will automatically cast this Map to the correct Struct based on your
  **Calculation Argument** definition.
  """
  def resolve_arguments(structure, input) do
    case traverse(structure, input) do
      @drop_token -> []
      result -> result
    end
  end

  defp traverse(%InputReference{key: key}, input) do
    case get_input_value(input, key) do
      {:ok, value} -> value
      :error -> @drop_token
    end
  end

  # Traversing a struct using Map logic strips its __struct__ tag, which corrupts common types like DateTime, Decimal, or Ash.Query. Meaning we have to treat it as opaque.
  defp traverse(%_{} = struct, _input), do: struct

  defp traverse(map, input) when is_map(map) do
    Map.new(map)
    |> Enum.reduce(%{}, fn {k, v}, acc ->
      case traverse(v, input) do
        # Drop this key from the map
        @drop_token -> acc
        resolved_value -> Map.put(acc, k, resolved_value)
      end
    end)
  end

  defp traverse(list, input) when is_list(list) do
    Enum.flat_map(list, fn item ->
      case traverse(item, input) do
        # Drop this item from the list
        @drop_token -> []
        resolved_value -> [resolved_value]
      end
    end)
  end

  defp traverse({key, value}, input) do
    case traverse(value, input) do
      @drop_token -> @drop_token
      resolved_val -> {traverse(key, input), resolved_val}
    end
  end

  defp traverse(tuple, input) when is_tuple(tuple) do
    tuple
    |> Tuple.to_list()
    |> Enum.map(fn item -> traverse(item, input) end)
    |> List.to_tuple()
  end

  defp traverse(value, _input), do: value

  defp get_input_value(input, key) do
    case Map.fetch(input, key) do
      {:ok, value} -> {:ok, value}
      :error -> Map.fetch(input, to_string(key))
    end
  end
end
