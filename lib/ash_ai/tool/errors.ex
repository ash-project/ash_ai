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

  @doc """
  Formats an Ash error into a mcp protocol compatible structure for tool error responses.
  """
  def format(error) do
    error
    |> Ash.Error.to_error_class()
    |> Map.get(:errors, [])
    |> Enum.map_join("\n", fn error ->
      msg = Exception.message(%{error | bread_crumbs: []})

      if Map.get(error, :field) do
        "#{error.field}: #{msg}"
      else
        msg
      end
    end)
    |> case do
      "" -> "Tool execution failed"
      text -> text
    end
  end
end
