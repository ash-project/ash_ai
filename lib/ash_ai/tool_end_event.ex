# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.ToolEndEvent do
  @moduledoc """
  Event data passed to the `on_tool_end` callback passed to `AshAi.setup_ash_ai/2`.

  Contains the tool name and execution result.
  """
  @type t :: %__MODULE__{
          tool_name: String.t(),
          result: {:ok, String.t(), any()} | {:error, String.t()}
        }

  defstruct [:tool_name, :result]
end
