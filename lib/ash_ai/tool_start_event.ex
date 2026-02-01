# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.ToolStartEvent do
  @moduledoc """
  Event data passed to the `on_tool_start` callback passed to `AshAi.setup_ash_ai/2`.

  Contains information about the tool execution that is about to begin.
  """
  @type t :: %__MODULE__{
          tool_name: String.t(),
          action: atom(),
          resource: module(),
          arguments: map(),
          actor: any() | nil,
          tenant: any() | nil
        }

  defstruct [:tool_name, :action, :resource, :arguments, :actor, :tenant]
end
