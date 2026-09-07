# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Dependencies do
  @moduledoc false

  # `req_llm` is optional. It is only required for features that talk to an
  # LLM; serving tools over MCP works without it.

  @spec require_req_llm!(String.t()) :: no_return()
  def require_req_llm!(feature) do
    raise RuntimeError, """
    #{feature} requires the `req_llm` dependency, which is optional in `ash_ai`.

    Add it to your `mix.exs`:

        {:req_llm, "~> 1.18"}

    then run:

        mix deps.get
        mix deps.compile ash_ai --force
    """
  end
end
