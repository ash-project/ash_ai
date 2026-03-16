# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Tools do
  @moduledoc """
  High-level API for discovering and building tools from Ash domains.

  This module provides the main interface for working with AshAi tools.
  It builds ReqLLM tools/registries and executes tool calls with consistent
  JSON:API error formatting.

  ## Architecture

  The tool functionality is organized into several specialized modules:
  - `AshAi.Tool.Schema` - Generates JSON schemas for tool parameters
  - `AshAi.Tool.Execution` - Executes Ash actions from tool calls
  - `AshAi.Tool.Errors` - Formats errors as JSON:API responses
  - `AshAi.Tool.Builder` - Creates ReqLLM.Tool structs and callbacks
  """

  alias AshAi.{Tool, ToolEndEvent, ToolStartEvent}
  alias AshAi.Tool.{Builder, Execution, Schema}

  @doc """
  Returns the JSON Schema parameter schema for a tool definition.

  Delegates to `AshAi.Tool.Schema.for_tool/1`.
  """
  def parameter_schema(%Tool{} = tool, opts \\ []) do
    strict? = Keyword.get(opts, :strict, true)
    Schema.for_tool(tool, strict?: strict?)
  end

  @doc """
  Executes a tool with the given arguments and context.

  Delegates to `AshAi.Tool.Execution.run/3`.

  Returns `{:ok, json_result, raw_result}` on success or `{:error, json_error}` on failure.
  """
  def execute(%Tool{} = tool, arguments, context) do
    Execution.run(tool, arguments, context)
  end

  @doc """
  Builds a ReqLLM.Tool and callback from a tool definition.

  Delegates to `AshAi.Tool.Builder.build/2`.

  Returns `{ReqLLM.Tool, callback_fn}` tuple.
  """
  def build(%Tool{} = tool, opts \\ []) do
    Builder.build(tool, opts)
  end

  @doc """
  Builds tools and a registry from options.

  Returns `{[ReqLLM.Tool], %{name => callback}}` tuple.
  """
  def build_tools_and_registry(opts) do
    opts = if is_list(opts), do: AshAi.Options.validate!(opts), else: opts

    ash_tool_tuples =
      opts
      |> AshAi.exposed_tools()
      |> Enum.map(&Builder.build(&1, strict: opts.strict))

    extra_tool_tuples = build_extra_tools(opts.extra_tools || [])
    tool_tuples = ensure_unique_tool_names!(ash_tool_tuples ++ extra_tool_tuples)

    {tools, callbacks} =
      case tool_tuples do
        [] -> {[], []}
        tuples -> Enum.unzip(tuples)
      end

    registry =
      Enum.zip(tools, callbacks)
      |> Enum.into(%{}, fn {tool, callback} -> {tool.name, callback} end)

    {tools, registry}
  end

  @doc """
  Returns a list of ReqLLM.Tool structs for the given options.
  """
  def list(opts) do
    opts
    |> build_tools_and_registry()
    |> elem(0)
  end

  @doc """
  Returns a registry map of tool names to callbacks.
  """
  def registry(opts) do
    opts
    |> build_tools_and_registry()
    |> elem(1)
  end

  defp build_extra_tools(extra_tools) when is_list(extra_tools) do
    Enum.map(extra_tools, &normalize_extra_tool/1)
  end

  defp normalize_extra_tool(%ReqLLM.Tool{} = tool) do
    {tool, build_extra_tool_callback(tool, nil)}
  end

  defp normalize_extra_tool({%ReqLLM.Tool{} = tool, callback}) when is_function(callback, 2) do
    {tool, build_extra_tool_callback(tool, callback)}
  end

  defp normalize_extra_tool(other) do
    raise ArgumentError,
          "Invalid extra tool: #{inspect(other)}. Expected %ReqLLM.Tool{} or {%ReqLLM.Tool{}, callback}"
  end

  defp build_extra_tool_callback(%ReqLLM.Tool{} = tool, callback_override) do
    fn arguments, context ->
      callbacks = context[:tool_callbacks] || %{}
      tool_name = tool.name

      if on_start = callbacks[:on_tool_start] do
        on_start.(%ToolStartEvent{
          tool_name: tool_name,
          action: nil,
          resource: nil,
          arguments: arguments,
          actor: context[:actor],
          tenant: context[:tenant]
        })
      end

      result =
        tool
        |> maybe_override_callback(callback_override, context)
        |> ReqLLM.Tool.execute(arguments || %{})
        |> normalize_extra_tool_result()

      if on_end = callbacks[:on_tool_end] do
        on_end.(%ToolEndEvent{
          tool_name: tool_name,
          result: result
        })
      end

      result
    end
  end

  defp maybe_override_callback(tool, nil, _context), do: tool

  defp maybe_override_callback(tool, callback, context) when is_function(callback, 2) do
    %{tool | callback: fn arguments -> callback.(arguments, context) end}
  end

  defp normalize_extra_tool_result({:ok, content}), do: {:ok, content, content}

  defp normalize_extra_tool_result({:error, content}) do
    {:error, normalize_extra_tool_error(content)}
  end

  defp ensure_unique_tool_names!(tool_tuples) do
    duplicates =
      tool_tuples
      |> Enum.map(fn {tool, _callback} -> tool.name end)
      |> Enum.frequencies()
      |> Enum.filter(fn {_name, count} -> count > 1 end)
      |> Enum.map(&elem(&1, 0))

    if duplicates == [] do
      tool_tuples
    else
      raise ArgumentError, "Duplicate tool names: #{Enum.join(Enum.sort(duplicates), ", ")}"
    end
  end

  defp normalize_extra_tool_error(%ReqLLM.ToolResult{} = result), do: result

  defp normalize_extra_tool_error(content) when is_binary(content) or is_list(content),
    do: content

  defp normalize_extra_tool_error(content) when is_map(content) and not is_struct(content) do
    content
  end

  defp normalize_extra_tool_error(content) do
    Jason.encode!(%{error: Exception.message(content)})
  rescue
    _ -> Jason.encode!(%{error: inspect(content)})
  end
end
