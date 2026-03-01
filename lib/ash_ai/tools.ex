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

  alias AshAi.Tool
  alias AshAi.Tool.{Builder, Schema, Execution}

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

    tool_tuples =
      opts
      |> AshAi.exposed_tools()
      |> Enum.map(&Builder.build(&1, strict: opts.strict))

    {tools, callbacks} = Enum.unzip(tool_tuples)

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
end
