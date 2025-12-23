defmodule AshAi.Tools.Loads do
  @moduledoc """
  Utilities for working with dynamic loads in AshAi tools.
  """

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

  ## Example

      load: [
        {:calculation_name, %{arg_name: from_input(:input_key)}}
      ]
  """
  def from_input(key) when is_atom(key) do
    %InputReference{key: key}
  end

  @doc """
  Recursively traverses the load structure and replaces all `InputReference` structs
  with their corresponding values from the input.

  ## ⚠️ Important: Handling Structs vs. Maps

  This function **does not** traverse into Structs (e.g. `%MyStruct{...}`).
  It treats them as opaque values.

  ### Why?
  Elixir structs are Maps with a special `__struct__` key. If we attempted to
  traverse them using standard Map logic, we would inadvertently strip the
  `__struct__` tag or modify internal keys. This would corrupt standard types
  (like `DateTime`, `Decimal`, or `Ash.Query`) and break any code expecting
  a valid Struct.

  ### How to handle complex arguments
  If your Calculation expects a Struct as an argument (e.g. an Embedded Resource),
  you must pass a **Map** in your load definition to use dynamic inputs.

  Ash will automatically cast this Map to the correct Struct based on your
  **Calculation Argument** definition.

  ### Example

  Given a calculation defined as:
      argument :filter, MyFilterStruct

  **❌ Incorrect (Reference is ignored because it's inside a Struct):**
      %{filter: %MyFilterStruct{status: from_input(:status)}}

  **✅ Correct (Ash will cast this Map to %MyFilterStruct{}):**
      %{filter: %{status: from_input(:status)}}

  ## Usage Example

      iex> load = [user: {:score, %{threshold: from_input(:min_score)}}]
      iex> input = %{min_score: 10}
      iex> resolve_arguments(load, input)
      [user: {:score, %{threshold: 10}}]
  """
  def resolve_arguments(structure, input) do
    traverse(structure, input)
  end

  defp traverse(%InputReference{key: key}, input) do
    get_input_value(input, key)
  end

  # Traversing a struct using Map logic strips its __struct__ tag, which corrupts standard types like DateTime, Decimal, or Ash.Query.
  defp traverse(%_{} = struct, _input), do: struct

  defp traverse(map, input) when is_map(map) do
    Map.new(map, fn {k, v} -> {k, traverse(v, input)} end)
  end

  defp traverse(list, input) when is_list(list) do
    Enum.map(list, fn item -> traverse(item, input) end)
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
      {:ok, value} -> value
      :error -> Map.get(input, to_string(key))
    end
  end
end
