# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.Client.Headers do
  @moduledoc false
  # Request metadata headers for the Streamable HTTP transport: the Base64
  # sentinel encoding for `Mcp-Name` and `Mcp-Param-*` values, and the
  # `x-mcp-header` tool parameters mirrored into `Mcp-Param-*` headers.

  @token ~r/\A[!#$%&'*+\-.^_`|~0-9A-Za-z]+\z/
  @max_safe_integer 9_007_199_254_740_991

  @doc """
  Encodes a header value, using the `=?base64?...?=` sentinel when the value is
  not a plain ASCII header value.
  """
  @spec encode_value(String.t()) :: String.t()
  def encode_value(value) when is_binary(value) do
    if plain?(value) and not sentinel?(value) do
      value
    else
      "=?base64?" <> Base.encode64(value) <> "?="
    end
  end

  # RFC 9110 field values: visible ASCII, space, and horizontal tab, with no
  # surrounding whitespace, which would not survive as part of the value
  defp plain?(value) do
    String.match?(value, ~r/\A[\x20-\x7E\t]*\z/) and value == String.trim(value, " ") and
      value == String.trim(value, "\t")
  end

  defp sentinel?(value),
    do: String.starts_with?(value, "=?base64?") and String.ends_with?(value, "?=")

  @doc """
  The `{path, header_name}` pairs a tool's `inputSchema` designates with
  `x-mcp-header`.

  Returns `{:error, reason}` when any annotation violates the transport's
  constraints, in which case clients must not offer the tool.
  """
  @spec params(map() | nil) :: {:ok, [{[String.t()], String.t()}]} | {:error, String.t()}
  def params(nil), do: {:ok, []}

  def params(schema) when is_map(schema) do
    reachable = reachable_params(schema, [])

    with :ok <- all_reachable(schema, reachable),
         :ok <- validate_params(reachable) do
      {:ok, Enum.map(reachable, fn {path, name, _schema} -> {path, name} end)}
    end
  end

  def params(_schema), do: {:error, "inputSchema must be an object"}

  # Annotated properties reachable from the root through `properties` keys only
  defp reachable_params(schema, path) do
    case schema do
      %{"properties" => properties} when is_map(properties) ->
        properties
        |> Enum.sort_by(&elem(&1, 0))
        |> Enum.flat_map(fn
          {key, property} when is_map(property) ->
            own =
              case Map.fetch(property, "x-mcp-header") do
                {:ok, name} -> [{path ++ [key], name, property}]
                :error -> []
              end

            own ++ reachable_params(property, path ++ [key])

          _other ->
            []
        end)

      _ ->
        []
    end
  end

  # An annotation anywhere else (under `items`, a composition keyword, `$defs`,
  # ...) makes the tool definition invalid
  defp all_reachable(schema, reachable) do
    if count_annotations(schema, false) == length(reachable) do
      :ok
    else
      {:error, "x-mcp-header is only allowed on properties reachable through `properties`"}
    end
  end

  # Keys of a `properties` map are property names, not keywords, so a property
  # that happens to be named `x-mcp-header` is not an annotation
  defp count_annotations(map, true) when is_map(map) do
    map |> Map.values() |> Enum.map(&count_annotations(&1, false)) |> Enum.sum()
  end

  defp count_annotations(map, false) when is_map(map) do
    own = if Map.has_key?(map, "x-mcp-header"), do: 1, else: 0

    nested =
      map
      |> Enum.map(fn
        {"properties", properties} -> count_annotations(properties, true)
        {_key, value} -> count_annotations(value, false)
      end)
      |> Enum.sum()

    own + nested
  end

  defp count_annotations(list, _in_properties?) when is_list(list) do
    list |> Enum.map(&count_annotations(&1, false)) |> Enum.sum()
  end

  defp count_annotations(_value, _in_properties?), do: 0

  defp validate_params(params) do
    params
    |> Enum.reduce_while({:ok, MapSet.new()}, fn {path, name, property}, {:ok, seen} ->
      downcased = if is_binary(name), do: String.downcase(name)

      cond do
        not is_binary(name) or not String.match?(name, @token) ->
          {:halt, {:error, "x-mcp-header at #{Enum.join(path, ".")} is not a valid header name"}}

        MapSet.member?(seen, downcased) ->
          {:halt, {:error, "x-mcp-header #{inspect(name)} is not unique"}}

        property["type"] not in ["string", "integer", "boolean"] ->
          {:halt,
           {:error,
            "x-mcp-header at #{Enum.join(path, ".")} must be on a string, integer, or boolean property"}}

        true ->
          {:cont, {:ok, MapSet.put(seen, downcased)}}
      end
    end)
    |> case do
      {:ok, _seen} -> :ok
      error -> error
    end
  end

  @doc """
  The `Mcp-Param-*` headers for calling a tool with `arguments`.

  Parameters without a value are omitted, as the transport requires.
  """
  @spec param_headers([{[String.t()], String.t()}], map()) :: [{String.t(), String.t()}]
  def param_headers(params, arguments) when is_map(arguments) do
    Enum.flat_map(params, fn {path, name} ->
      case header_value(get_path(arguments, path)) do
        nil -> []
        value -> [{"mcp-param-" <> String.downcase(name), encode_value(value)}]
      end
    end)
  end

  def param_headers(_params, _arguments), do: []

  defp get_path(value, []), do: value
  defp get_path(map, [key | rest]) when is_map(map), do: get_path(Map.get(map, key), rest)
  defp get_path(_value, _path), do: nil

  defp header_value(value) when is_binary(value), do: value
  defp header_value(value) when is_boolean(value), do: to_string(value)

  defp header_value(value) when is_integer(value) and abs(value) <= @max_safe_integer,
    do: Integer.to_string(value)

  # Models sometimes send integers as whole floats; the server compares numerically
  defp header_value(value) when is_float(value) and value == trunc(value),
    do: header_value(trunc(value))

  defp header_value(_value), do: nil
end
