# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Actions.Prompt.LegacyChainCompat do
  @moduledoc """
  Compatibility shim for legacy `modify_chain` callbacks.

  This is not a LangChain chain. It is a wrapper around ReqLLM prompt flow data
  that preserves the old callback shape: `fn chain_like, context -> chain_like end`.
  """

  alias AshAi.Actions.Prompt.FlowState

  defstruct [
    :llm,
    :messages,
    :tools,
    :extra_tools,
    :verbose,
    :custom_context,
    :req_llm_opts,
    :max_iterations,
    :strict,
    :on_tool_start,
    :on_tool_end,
    :flow_state
  ]

  @type t :: %__MODULE__{
          llm: term(),
          messages: list(),
          tools: false | true | [atom()],
          extra_tools: list(),
          verbose: boolean(),
          custom_context: map(),
          req_llm_opts: Keyword.t(),
          max_iterations: :infinity | pos_integer(),
          strict: boolean(),
          on_tool_start: (term() -> term()) | nil,
          on_tool_end: (term() -> term()) | nil,
          flow_state: FlowState.t()
        }

  @spec from_flow_state(FlowState.t()) :: t()
  def from_flow_state(%FlowState{} = flow_state) do
    %__MODULE__{
      llm: flow_state.model,
      messages: flow_state.messages,
      tools: flow_state.tool_selection,
      extra_tools: flow_state.extra_tools || [],
      verbose: flow_state.verbose?,
      custom_context: flow_state.source_context || %{},
      req_llm_opts: flow_state.req_llm_opts || [],
      max_iterations: flow_state.max_iterations,
      strict: flow_state.strict,
      on_tool_start: flow_state.on_tool_start,
      on_tool_end: flow_state.on_tool_end,
      flow_state: flow_state
    }
  end

  @spec to_flow_state(t()) :: FlowState.t()
  def to_flow_state(%__MODULE__{flow_state: %FlowState{} = flow_state} = compat) do
    %FlowState{
      flow_state
      | model: compat.llm,
        messages: compat.messages || [],
        tool_selection: compat.tools,
        extra_tools: compat.extra_tools || [],
        verbose?: compat.verbose || false,
        source_context: compat.custom_context || %{},
        req_llm_opts: compat.req_llm_opts || [],
        max_iterations: compat.max_iterations,
        strict: compat.strict,
        on_tool_start: compat.on_tool_start,
        on_tool_end: compat.on_tool_end
    }
  end

  @doc "Sets the model (`llm` in legacy naming)."
  @spec put_model(t(), term()) :: t()
  def put_model(%__MODULE__{} = compat, model), do: %{compat | llm: model}

  @doc "Replaces ReqLLM options."
  @spec put_req_llm_opts(t(), Keyword.t()) :: t()
  def put_req_llm_opts(%__MODULE__{} = compat, req_llm_opts) when is_list(req_llm_opts) do
    %{compat | req_llm_opts: req_llm_opts}
  end

  @doc "Replaces prompt messages."
  @spec set_messages(t(), list()) :: t()
  def set_messages(%__MODULE__{} = compat, messages) when is_list(messages) do
    %{compat | messages: messages}
  end

  @doc "Appends a single message."
  @spec append_message(t(), term()) :: t()
  def append_message(%__MODULE__{} = compat, message) do
    %{compat | messages: (compat.messages || []) ++ [message]}
  end

  @doc "Replaces tool selection (`false`, `true`, or list of tool names)."
  @spec set_tools(t(), false | true | [atom()]) :: t()
  def set_tools(%__MODULE__{} = compat, tools)
      when is_boolean(tools) or is_list(tools) do
    %{compat | tools: tools}
  end

  @doc "Appends tool names when tool selection is explicit list mode."
  @spec append_tools(t(), [atom()]) :: t()
  def append_tools(%__MODULE__{} = compat, tool_names) when is_list(tool_names) do
    tools =
      case compat.tools do
        false ->
          tool_names

        nil ->
          tool_names

        true ->
          true

        current when is_list(current) ->
          (current ++ tool_names)
          |> Enum.uniq()
      end

    %{compat | tools: tools}
  end

  @doc "Replaces additional ReqLLM tools."
  @spec set_extra_tools(t(), list()) :: t()
  def set_extra_tools(%__MODULE__{} = compat, extra_tools) when is_list(extra_tools) do
    %{compat | extra_tools: extra_tools}
  end

  @doc "Appends additional ReqLLM tools."
  @spec append_extra_tools(t(), list()) :: t()
  def append_extra_tools(%__MODULE__{} = compat, extra_tools) when is_list(extra_tools) do
    %{compat | extra_tools: (compat.extra_tools || []) ++ extra_tools}
  end

  @doc "Sets tool lifecycle callbacks."
  @spec set_tool_callbacks(
          t(),
          on_tool_start: (term() -> term()) | nil,
          on_tool_end: (term() -> term()) | nil
        ) :: t()
  def set_tool_callbacks(%__MODULE__{} = compat, callbacks) do
    compat
    |> put_if_present(:on_tool_start, callbacks[:on_tool_start])
    |> put_if_present(:on_tool_end, callbacks[:on_tool_end])
  end

  defp put_if_present(compat, _key, nil), do: compat
  defp put_if_present(compat, key, value), do: Map.put(compat, key, value)
end
