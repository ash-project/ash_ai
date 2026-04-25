# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Tool.Errors do
  @moduledoc """
  Formats Ash errors into human-readable text for tool responses.

  As the MCP specification dated 2025-06-18, tool execution errors should be
  returned as successful responses with `isError: true` and error details in
  the content array
  """

  require Logger

  @doc """
  Formats an Ash error into a mcp protocol compatible structure for tool error responses.
  """
  def format(error) do
    error
    |> Ash.Error.to_error_class()
    |> Map.get(:errors, [])
    |> Enum.map_join("\n", &format_single_error/1)
    |> case do
      "" -> "Tool execution failed"
      text -> text
    end
  end

  defp format_single_error(%{fields: fields} = error) when is_list(fields) and fields != [] do
    Enum.map_join(fields, "\n", fn field ->
      error |> Map.put(:fields, nil) |> Map.put(:field, field) |> format_single_error()
    end)
  end

  defp format_single_error(error) do
    msg =
      if AshAi.ToToolError.impl_for(error) do
        AshAi.ToToolError.to_tool_error(error)
      else
        Logger.warning("AshAi.ToToolError not implemented for #{inspect(error.__struct__)}")

        "unexpected error occurred"
      end

    case {Map.get(error, :path, []), Map.get(error, :field)} do
      {_, nil} -> msg
      {[], field} -> "#{field}: #{msg}"
      {path, field} -> "#{Enum.join(path ++ [field], ".")}: #{msg}"
    end
  end
end
