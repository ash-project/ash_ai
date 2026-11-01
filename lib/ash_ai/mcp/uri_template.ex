# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.UriTemplate do
  @moduledoc false
  # The subset of RFC 6570 URI templates that `mcp_resource` URIs accept,
  # parsed at compile time and matched against `resources/read` URIs:
  #
  #   * `{var}` - simple expansion: one or more characters, none of `/`, `?` or `#`
  #   * `{+var}` - reserved expansion: one or more characters, none of `?` or
  #     `#`, so it can span path segments
  #   * `{?a,b}` - form-style query: ends the template, and each variable is
  #     optional. A query naming any other key, or one key twice, doesn't match.
  #
  # Matched values are percent-decoded. Other operators, prefix and explode
  # modifiers, and several variables in one simple or reserved expression are
  # rejected rather than matched loosely. Two variables with no literal text
  # between them are rejected too, since no split of the URI between them is
  # more right than another.

  defstruct [:source, parts: [], query: nil]

  @type part :: {:literal, String.t()} | {:simple, String.t()} | {:reserved, String.t()}
  @type t :: %__MODULE__{source: String.t(), parts: [part()], query: [String.t()] | nil}

  @doc "Whether `uri` contains template expressions (or a stray brace)."
  @spec template?(String.t()) :: boolean()
  def template?(uri), do: String.contains?(uri, ["{", "}"])

  @spec parse(String.t()) :: {:ok, t()} | {:error, String.t()}
  def parse(source) when is_binary(source) do
    with {:ok, tokens} <- tokenize(source, "", []),
         {:ok, parts, query} <- split_query(tokens),
         :ok <- check_query_literals(parts, query),
         :ok <- check_adjacent(parts),
         :ok <- check_unique(variables(parts, query)) do
      {:ok, %__MODULE__{source: source, parts: parts, query: query}}
    end
  end

  @doc "The template's variable names, in order."
  @spec variables(t()) :: [String.t()]
  def variables(%__MODULE__{parts: parts, query: query}), do: variables(parts, query)

  defp variables(parts, query) do
    for({kind, name} <- parts, kind != :literal, do: name) ++ (query || [])
  end

  @doc """
  The variables `uri` assigns, or `:error` when it doesn't match. Query
  variables the URI leaves out are absent from the map.
  """
  @spec match(t(), String.t()) :: {:ok, %{String.t() => String.t()}} | :error
  def match(%__MODULE__{parts: parts, query: nil}, uri) when is_binary(uri),
    do: match_parts(parts, uri, %{})

  def match(%__MODULE__{parts: parts, query: names}, uri) when is_binary(uri) do
    {head, query} =
      case :binary.split(uri, "?") do
        [head, query] -> {head, query}
        [head] -> {head, ""}
      end

    with {:ok, variables} <- match_parts(parts, head, %{}),
         {:ok, query_variables} <- match_query(query, names) do
      {:ok, Map.merge(variables, query_variables)}
    end
  end

  # Parsing

  defp tokenize("", literal, acc), do: {:ok, Enum.reverse(push_literal(acc, literal))}

  defp tokenize("{" <> rest, literal, acc) do
    case :binary.split(rest, "}") do
      [expression, rest] ->
        with {:ok, token} <- expression(expression) do
          tokenize(rest, "", [token | push_literal(acc, literal)])
        end

      [_unclosed] ->
        {:error, "`{` is never closed"}
    end
  end

  defp tokenize("}" <> _rest, _literal, _acc), do: {:error, "`}` has no matching `{`"}

  defp tokenize(<<byte, rest::binary>>, literal, acc),
    do: tokenize(rest, <<literal::binary, byte>>, acc)

  defp push_literal(acc, ""), do: acc
  defp push_literal(acc, literal), do: [{:literal, literal} | acc]

  defp expression("+" <> names), do: single(:reserved, "+", names)

  defp expression("?" <> names) do
    with {:ok, names} <- names("?", names), do: {:ok, {:query, names}}
  end

  defp expression(<<operator, _rest::binary>> = expression) when operator in ~c"#./;&=,!@|" do
    {:error,
     "`{#{expression}}` uses the `#{<<operator>>}` operator, which isn't supported. " <>
       "Use `{var}`, `{+var}` or a trailing `{?var,...}`"}
  end

  defp expression(names), do: single(:simple, "", names)

  defp single(kind, operator, names) do
    case names(operator, names) do
      {:ok, [name]} ->
        {:ok, {kind, name}}

      {:ok, _names} ->
        {:error,
         "`{#{operator}#{names}}` names several variables, which only a trailing `{?...}` may do"}

      error ->
        error
    end
  end

  defp names(operator, ""), do: {:error, "`{#{operator}}` names no variable"}

  defp names(operator, names) do
    names
    |> String.split(",")
    |> Enum.reduce_while({:ok, []}, fn name, {:ok, acc} ->
      cond do
        String.ends_with?(name, "*") or String.contains?(name, ":") ->
          {:halt,
           {:error,
            "`{#{operator}#{names}}` uses a modifier (`*` or `:n`), which isn't supported"}}

        varname?(name) ->
          {:cont, {:ok, [name | acc]}}

        true ->
          {:halt,
           {:error,
            "`{#{operator}#{names}}` has the invalid variable name #{inspect(name)}; " <>
              "use letters, digits and underscores"}}
      end
    end)
    |> case do
      {:ok, names} -> {:ok, Enum.reverse(names)}
      error -> error
    end
  end

  defp varname?(""), do: false

  defp varname?(name) do
    for <<byte <- name>>, reduce: true do
      acc -> acc and (byte in ?a..?z or byte in ?A..?Z or byte in ?0..?9 or byte == ?_)
    end
  end

  defp split_query(tokens) do
    case Enum.split_while(tokens, &(elem(&1, 0) != :query)) do
      {parts, []} -> {:ok, parts, nil}
      {parts, [{:query, names}]} -> {:ok, parts, names}
      {_parts, _rest} -> {:error, "`{?...}` must end the template"}
    end
  end

  # The query is split off at the URI's first `?`, so the text before it
  # can't contain one
  defp check_query_literals(_parts, nil), do: :ok

  defp check_query_literals(parts, _query) do
    if Enum.any?(parts, fn {kind, text} -> kind == :literal and String.contains?(text, "?") end),
      do: {:error, "a template ending in `{?...}` can't also contain a literal `?`"},
      else: :ok
  end

  defp check_adjacent(parts) do
    parts
    |> Enum.chunk_every(2, 1, :discard)
    |> Enum.find(fn [{left, _}, {right, _}] -> left != :literal and right != :literal end)
    |> case do
      nil ->
        :ok

      [{_, left}, {_, right}] ->
        {:error, "`#{left}` and `#{right}` need literal text between them to be told apart"}
    end
  end

  defp check_unique(names) do
    case names -- Enum.uniq(names) do
      [] -> :ok
      [name | _] -> {:error, "the variable `#{name}` appears more than once"}
    end
  end

  # Matching

  defp match_parts([], "", variables), do: {:ok, variables}
  defp match_parts([], _rest, _variables), do: :error

  defp match_parts([{:literal, literal} | parts], uri, variables) do
    size = byte_size(literal)

    case uri do
      <<^literal::binary-size(^size), rest::binary>> -> match_parts(parts, rest, variables)
      _ -> :error
    end
  end

  # Tries each place the variable could end, shortest first: the next literal
  # can also occur inside the value, as `.` does in `{+path}.json`
  defp match_parts([{kind, name} | parts], uri, variables) do
    limit = value_limit(kind, uri)

    parts
    |> value_lengths(uri, limit)
    |> Enum.find_value(:error, fn length ->
      <<value::binary-size(^length), rest::binary>> = uri

      with {:ok, value} <- decode(value),
           {:ok, variables} <- match_parts(parts, rest, Map.put(variables, name, value)) do
        {:ok, variables}
      else
        _ -> nil
      end
    end)
  end

  # The length of the longest value the variable could take: up to the first
  # character it can't contain
  defp value_limit(kind, uri) do
    stops = if kind == :simple, do: ["/", "?", "#"], else: ["?", "#"]

    case :binary.match(uri, stops) do
      {position, _length} -> position
      :nomatch -> byte_size(uri)
    end
  end

  defp value_lengths([], uri, limit),
    do: if(limit == byte_size(uri) and limit > 0, do: [limit], else: [])

  defp value_lengths([{:literal, literal} | _parts], uri, limit) do
    size = byte_size(literal)

    for length <- 1..limit//1,
        length + size <= byte_size(uri),
        binary_part(uri, length, size) == literal,
        do: length
  end

  defp match_query("", _names), do: {:ok, %{}}

  defp match_query(query, names) do
    query
    |> String.split("&")
    |> Enum.reduce_while({:ok, %{}}, fn pair, {:ok, acc} ->
      {key, value} =
        case :binary.split(pair, "=") do
          [key, value] -> {key, value}
          [key] -> {key, ""}
        end

      with {:ok, key} <- decode(key),
           true <- key in names and not is_map_key(acc, key),
           {:ok, value} <- decode(value) do
        {:cont, {:ok, Map.put(acc, key, value)}}
      else
        _ -> {:halt, :error}
      end
    end)
  end

  # `URI.decode/1` passes a `%` without two hex digits through unchanged, but
  # an expanded template never contains one
  defp decode(value) do
    with true <- percent_encoded?(value),
         decoded = URI.decode(value),
         true <- String.valid?(decoded) do
      {:ok, decoded}
    else
      false -> :error
    end
  end

  defguardp is_hex(byte) when byte in ?0..?9 or byte in ?a..?f or byte in ?A..?F

  defp percent_encoded?(<<>>), do: true

  defp percent_encoded?(<<?%, a, b, rest::binary>>) when is_hex(a) and is_hex(b),
    do: percent_encoded?(rest)

  defp percent_encoded?(<<?%, _rest::binary>>), do: false
  defp percent_encoded?(<<_byte, rest::binary>>), do: percent_encoded?(rest)
end
