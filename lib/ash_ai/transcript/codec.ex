# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Transcript.Codec do
  @moduledoc """
  Encodes Elixir terms as JSON-safe values and back, without losing atoms,
  tuples, binaries, or ReqLLM structs.

  Provider metadata on ReqLLM messages uses atom keys and values (for example
  `%{provider: :anthropic, signature: "..."}`) that a JSON round trip would turn
  into strings, which the provider encoders would then ignore. Values that JSON
  can't represent are wrapped in a single-key object:

  - atoms: `%{"$atom" => "anthropic"}`
  - maps with atom keys: `%{"$atoms" => %{"provider" => ...}}`
  - other maps with non-string keys: `%{"$map" => [[key, value], ...]}`
  - tuples: `%{"$tuple" => [...]}`
  - non-UTF-8 binaries: `%{"$binary" => base64}`
  - ReqLLM structs: `%{"$struct" => "ReqLLM.Message", "fields" => ...}`

  Decoding only creates existing atoms and only rebuilds the ReqLLM structs
  listed here; any other value decodes to plain data.
  """

  @structs %{
    "ReqLLM.Message" => ReqLLM.Message,
    "ReqLLM.Message.ContentPart" => ReqLLM.Message.ContentPart,
    "ReqLLM.Message.ReasoningDetails" => ReqLLM.Message.ReasoningDetails,
    "ReqLLM.ToolCall" => ReqLLM.ToolCall,
    "ReqLLM.ToolResult" => ReqLLM.ToolResult
  }

  @struct_names Map.new(@structs, fn {name, module} -> {module, name} end)

  @tags ["$atom", "$atoms", "$map", "$tuple", "$binary", "$struct"]

  @doc "Encodes a term as a JSON-safe value."
  @spec encode(term()) :: term()
  def encode(value) when is_nil(value) or is_boolean(value) or is_number(value), do: value

  def encode(value) when is_binary(value) do
    if String.valid?(value), do: value, else: %{"$binary" => Base.encode64(value)}
  end

  def encode(value) when is_atom(value), do: %{"$atom" => Atom.to_string(value)}
  def encode(value) when is_list(value), do: Enum.map(value, &encode/1)

  def encode(value) when is_tuple(value),
    do: %{"$tuple" => value |> Tuple.to_list() |> Enum.map(&encode/1)}

  def encode(%DateTime{} = value), do: DateTime.to_iso8601(value)

  def encode(%module{} = value) do
    fields = value |> Map.from_struct() |> encode()

    case Map.fetch(@struct_names, module) do
      {:ok, name} -> %{"$struct" => name, "fields" => fields}
      :error -> fields
    end
  end

  def encode(value) when is_map(value) do
    keys = Map.keys(value)

    cond do
      Enum.all?(keys, &(is_binary(&1) and &1 not in @tags)) ->
        Map.new(value, fn {key, val} -> {key, encode(val)} end)

      Enum.all?(keys, &(is_atom(&1) and not is_nil(&1) and not is_boolean(&1))) ->
        %{"$atoms" => Map.new(value, fn {key, val} -> {Atom.to_string(key), encode(val)} end)}

      true ->
        %{"$map" => Enum.map(value, fn {key, val} -> [encode(key), encode(val)] end)}
    end
  end

  @doc "Decodes a value produced by `encode/1`."
  @spec decode(term()) :: term()
  def decode(%{"$atom" => name}) when is_binary(name), do: to_atom(name)

  def decode(%{"$atoms" => map}) when is_map(map),
    do: Map.new(map, fn {key, val} -> {to_atom(key), decode(val)} end)

  def decode(%{"$map" => pairs}) when is_list(pairs),
    do: Map.new(pairs, fn [key, val] -> {decode(key), decode(val)} end)

  def decode(%{"$tuple" => items}) when is_list(items),
    do: items |> Enum.map(&decode/1) |> List.to_tuple()

  def decode(%{"$binary" => data}) when is_binary(data), do: Base.decode64!(data)

  def decode(%{"$struct" => name, "fields" => fields}) do
    fields = decode(fields)

    case Map.fetch(@structs, name) do
      {:ok, module} -> struct(module, fields)
      :error -> fields
    end
  end

  def decode(value) when is_map(value), do: Map.new(value, fn {k, v} -> {k, decode(v)} end)
  def decode(value) when is_list(value), do: Enum.map(value, &decode/1)
  def decode(value), do: value

  # Unknown atoms stay strings rather than growing the atom table from stored data.
  defp to_atom(name) do
    String.to_existing_atom(name)
  rescue
    ArgumentError -> name
  end
end
