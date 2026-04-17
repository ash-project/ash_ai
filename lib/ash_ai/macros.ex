# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Macros do
  @moduledoc false

  @doc """
  Resource-level shorthand for AshAi tools.

  Allows defining tools inside an `Ash.Resource` as:

      tools do
        tool :list_posts, :read
      end

  This expands to the standard 3-argument tool form using the current module
  as the tool resource.
  """
  defmacro tool(name, action) do
    caller_module = __CALLER__.module

    quote do
      require AshAi.Tools.Tool
      AshAi.Tools.Tool.tool(unquote(name), unquote(caller_module), unquote(action))
    end
  end
end
