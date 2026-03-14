# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Actions.Prompt.FlowState do
  @moduledoc """
  Internal ReqLLM-native flow state for prompt actions.

  This state is the canonical representation used by prompt action execution and
  powers `transform_flow` customizations.
  """

  defstruct [
    :model,
    :req_llm,
    req_llm_opts: [],
    messages: [],
    tool_selection: false,
    extra_tools: [],
    max_iterations: :infinity,
    strict: true,
    verbose?: false,
    on_tool_start: nil,
    on_tool_end: nil,
    actor: nil,
    tenant: nil,
    source_context: %{}
  ]

  @type t :: %__MODULE__{
          model: term(),
          req_llm: module(),
          req_llm_opts: Keyword.t(),
          messages: list(),
          tool_selection: false | true | [atom()],
          extra_tools: list(),
          max_iterations: :infinity | pos_integer(),
          strict: boolean(),
          verbose?: boolean(),
          on_tool_start: (term() -> term()) | nil,
          on_tool_end: (term() -> term()) | nil,
          actor: term(),
          tenant: term(),
          source_context: map()
        }
end
