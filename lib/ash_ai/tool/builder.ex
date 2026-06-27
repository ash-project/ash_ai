# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Tool.Builder do
  @moduledoc """
  Builds ReqLLM.Tool structs and callbacks from AshAi.Tool DSL entities.

  This module is responsible for converting AshAi tool definitions into
  the format expected by ReqLLM, including generating the parameter schema
  and creating the callback function that executes the tool.
  """

  alias AshAi.Tool.Execution
  alias AshAi.Tool.Schema
  alias AshAi.ToolEndEvent
  alias AshAi.ToolStartEvent

  @doc """
  Builds a ReqLLM.Tool struct and callback function from an AshAi.Tool definition.

  Returns a tuple of `{ReqLLM.Tool, callback_fn}` where:
  - `ReqLLM.Tool` contains the tool schema for the LLM
  - `callback_fn` is a function/2 that takes (arguments, context) and executes the Ash action

  ## Example

      {tool, callback} = AshAi.Tool.Builder.build(tool_def)
      result = callback.(%{"input" => %{"name" => "foo"}}, %{actor: current_user})
  """
  def build(%AshAi.Tool{} = tool_def, opts \\ []) do
    name = to_string(tool_def.name)
    strict? = Keyword.get(opts, :strict, true)

    base_description =
      String.trim(
        tool_def.description || tool_def.action.description ||
          "Call the #{tool_def.action.name} tool"
      )

    parameter_schema = Schema.for_tool(tool_def, strict?: strict?)
    description = append_input_shape_hint(base_description, parameter_schema)

    callback_fn = build_callback(tool_def)

    tool =
      ReqLLM.Tool.new!(
        name: name,
        description: description,
        parameter_schema: parameter_schema,
        callback: fn _args -> {:ok, "stub - should not be called"} end
      )

    {tool, callback_fn}
  end

  # Append a one-line reminder of the call shape so models that occasionally
  # drop the `input` wrapper see it spelled out alongside the description.
  defp append_input_shape_hint(description, %{"properties" => %{"input" => input}})
       when is_map(input) do
    case Map.get(input, "properties") do
      props when is_map(props) and map_size(props) > 0 ->
        keys = props |> Map.keys() |> Enum.sort()
        param_list = keys |> Enum.map(&"`#{&1}`") |> Enum.join(", ")
        first = hd(keys)

        description <>
          "\n\nCall shape: nest all parameters (#{param_list}) under an `input` object — " <>
          "e.g. `{\"input\": {\"#{first}\": ...}}`. Do not pass parameters at the top level."

      _ ->
        description
    end
  end

  defp append_input_shape_hint(description, _schema), do: description

  defp build_callback(tool_def) do
    fn arguments, context ->
      tool_name = to_string(tool_def.name)
      callbacks = context[:tool_callbacks] || %{}

      if on_start = callbacks[:on_tool_start] do
        on_start.(%ToolStartEvent{
          tool_name: tool_name,
          action: tool_def.action.name,
          resource: tool_def.resource,
          arguments: arguments,
          actor: context[:actor],
          tenant: context[:tenant]
        })
      end

      result = Execution.run(tool_def, arguments, context)

      if on_end = callbacks[:on_tool_end] do
        on_end.(%ToolEndEvent{
          tool_name: tool_name,
          result: result
        })
      end

      result
    end
  end
end
