# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

if Code.ensure_loaded?(ReqLLM) do
  defmodule AshAi.ToolSearch do
    @moduledoc """
    Deferred tool loading for `AshAi.ToolLoop`, using the provider's own tool
    search.

    With `tool_search` enabled, deferred tools are sent marked `defer_loading`
    along with the provider's hosted search tool (Anthropic's
    `tool_search_tool_bm25`, or OpenAI's `tool_search` on the Responses API,
    gpt-5.4 and later). The provider keeps deferred tools out of the model's
    context until the model searches for them, and out of the cached prompt
    prefix, so loading one doesn't invalidate the cache.

    The provider's built-in search is the only strategy for now. With any other
    provider, tool search is skipped and every tool is sent normally. Other
    strategies may be added later.

    ## Options

    - `:defer` - which tools to defer: `:all` (default), a list of tool names,
      or a function that takes a `ReqLLM.Tool` and returns a boolean.
    - `:always_load` - tool names that are never deferred.
    """

    @providers [:anthropic, :openai]

    defstruct [:provider, :base_tools, :deferred]

    @schema [
      defer: [type: {:or, [{:in, [:all]}, {:list, :string}, {:fun, 1}]}, default: :all],
      always_load: [type: {:list, :string}, default: []]
    ]

    @doc """
    Prepares tool search for a loop.

    Returns `nil` when tool search is disabled, the model's provider has no
    built-in search, or nothing is deferred.
    """
    def new(_tools, config, _model) when config in [nil, false], do: nil

    def new(tools, config, model) do
      config = Spark.Options.validate!(if(config == true, do: [], else: config), @schema)
      {deferred, base} = Enum.split_with(tools, &deferred?(&1, config))

      if deferred != [] and model.provider in @providers do
        %__MODULE__{provider: model.provider, base_tools: base, deferred: deferred}
      end
    end

    @doc """
    The tools to send on each request.
    """
    def request_tools(nil, tools), do: tools

    def request_tools(%__MODULE__{provider: :openai} = search, _tools) do
      search.base_tools ++
        Enum.map(search.deferred, &defer(&1, :openai)) ++ [%{"type" => "tool_search"}]
    end

    def request_tools(%__MODULE__{} = search, _tools) do
      search.base_tools ++ Enum.map(search.deferred, &defer(&1, search.provider))
    end

    @doc """
    ReqLLM options for each request: adds Anthropic's hosted search tool.
    """
    def request_opts(%__MODULE__{provider: :anthropic}, req_llm_opts) do
      Keyword.update(
        req_llm_opts,
        :provider_options,
        [tool_search: %{variant: :bm25}],
        &put_option(&1, :tool_search, %{variant: :bm25})
      )
    end

    def request_opts(_search, req_llm_opts), do: req_llm_opts

    defp deferred?(tool, config) do
      tool.name not in config[:always_load] and
        case config[:defer] do
          :all -> true
          names when is_list(names) -> tool.name in names
          fun when is_function(fun, 1) -> fun.(tool)
        end
    end

    defp defer(tool, provider) do
      %{tool | provider_options: put_option(tool.provider_options, provider, defer_loading: true)}
    end

    defp put_option(options, key, value) when is_list(options) do
      Keyword.update(options, key, value, &merge_option(&1, value))
    end

    defp put_option(options, key, value) when is_map(options) do
      Map.update(options, key, value, &merge_option(&1, value))
    end

    defp put_option(_options, key, value), do: [{key, value}]

    defp merge_option(existing, value) when is_list(existing) and is_list(value),
      do: Keyword.merge(existing, value)

    defp merge_option(existing, value) when is_map(existing) and is_list(value),
      do: Map.merge(existing, Map.new(value))

    defp merge_option(_existing, value), do: value
  end
end
