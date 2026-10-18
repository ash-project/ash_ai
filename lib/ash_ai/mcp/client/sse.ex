# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.Client.SSE do
  @moduledoc false
  # An incremental Server-Sent Events parser for MCP response streams.
  #
  # `parse/2` takes the remainder from the previous call and the new chunk, and
  # returns the complete events plus the new remainder, so chunks can arrive
  # split anywhere, including inside a CRLF line ending. Only the new chunk is
  # normalized and searched for the end of an event, so an event arriving in
  # many small chunks costs time in proportion to its size.

  @type event :: %{event: String.t() | nil, data: String.t(), id: String.t() | nil}

  @doc """
  Parses the complete events in `rest` (the remainder from the previous call,
  or `""`) followed by `data`.

  Returns `{events, rest}`, where `rest` holds an incomplete trailing event to
  pass to the next call.
  """
  @spec parse(binary(), binary()) :: {[event()], binary()}
  def parse(rest, data) do
    # The remainder is already normalized, except for a trailing CR that may be
    # the first half of a CRLF split across chunks. It rejoins the new chunk.
    {rest, chunk} =
      if String.ends_with?(rest, "\r"),
        do: {binary_part(rest, 0, byte_size(rest) - 1), "\r" <> data},
        else: {rest, data}

    {chunk, held} =
      if String.ends_with?(chunk, "\r"),
        do: {binary_part(chunk, 0, byte_size(chunk) - 1), "\r"},
        else: {chunk, ""}

    normalized =
      chunk
      |> String.replace("\r\n", "\n")
      |> String.replace("\r", "\n")

    buffer = rest <> normalized

    # An event can only end within the new bytes or at the byte before them
    start = max(byte_size(rest) - 1, 0)

    case :binary.match(buffer, "\n\n", scope: {start, byte_size(buffer) - start}) do
      :nomatch ->
        {[], buffer <> held}

      _found ->
        {complete, [rest]} = buffer |> String.split("\n\n") |> Enum.split(-1)

        events =
          complete
          |> Enum.map(&parse_block/1)
          |> Enum.reject(&is_nil/1)

        {events, rest <> held}
    end
  end

  defp parse_block(block) do
    {event, data, id} =
      block
      |> String.split("\n")
      |> Enum.reduce({nil, [], nil}, fn line, {event, data, id} = acc ->
        case parse_line(line) do
          {"event", value} -> {value, data, id}
          {"data", value} -> {event, [value | data], id}
          {"id", value} -> {event, data, value}
          _comment_or_unknown -> acc
        end
      end)

    # An event without data lines dispatches nothing
    if data == [] do
      nil
    else
      %{event: event, data: data |> Enum.reverse() |> Enum.join("\n"), id: id}
    end
  end

  defp parse_line(""), do: nil
  defp parse_line(":" <> _comment), do: nil

  defp parse_line(line) do
    case String.split(line, ":", parts: 2) do
      [field, " " <> value] -> {field, value}
      [field, value] -> {field, value}
      [field] -> {field, ""}
    end
  end
end
