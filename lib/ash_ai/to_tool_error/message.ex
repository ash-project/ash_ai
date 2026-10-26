# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.ToToolError.Message do
  @moduledoc false

  @spec interpolate(map()) :: String.t() | nil
  def interpolate(%{message: message} = error) when is_binary(message) do
    error
    |> Map.get(:vars)
    |> List.wrap()
    |> Enum.reduce(message, fn {key, value}, acc ->
      String.replace(acc, "%{#{key}}", format_value(value))
    end)
  end

  def interpolate(error), do: Map.get(error, :message)

  defp format_value(value) when is_list(value), do: Enum.map_join(value, ", ", &format_value/1)
  defp format_value(%Regex{} = value), do: Regex.source(value)

  defp format_value(value) do
    if String.Chars.impl_for(value), do: to_string(value), else: inspect(value)
  end
end
