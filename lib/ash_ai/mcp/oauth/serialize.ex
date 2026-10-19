# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.OAuth.Serialize do
  @moduledoc false

  def datetime(nil), do: nil
  def datetime(%DateTime{} = datetime), do: DateTime.to_iso8601(datetime)

  def parse_datetime(nil), do: nil
  def parse_datetime(%DateTime{} = datetime), do: datetime

  def parse_datetime(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, datetime, _offset} -> datetime
      _ -> nil
    end
  end
end
