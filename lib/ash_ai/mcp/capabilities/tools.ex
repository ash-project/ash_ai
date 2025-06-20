defmodule AshAi.Mcp.Capabilities.Tools do
  @moduledoc """
  MCP Tools capability implementation.

  This module handles the tools capability for the MCP server,
  allowing clients to list and call tools exposed through AshAi.
  """

  @behaviour AshAi.Mcp.Capability

  require Logger

  @impl AshAi.Mcp.Capability
  def capability_name, do: "tools"

  @impl AshAi.Mcp.Capability
  def capability_config do
    %{
      "listChanged" => false
    }
  end

  @impl AshAi.Mcp.Capability
  def list_items(_session_id, opts) do
    tools = get_tools(opts)

    tool_list =
      Enum.map(tools, fn function ->
        %{
          "name" => function.name,
          "description" => function.description,
          "inputSchema" => function.parameters_schema
        }
      end)

    {:ok, tool_list}
  end

  @impl AshAi.Mcp.Capability
  def handle_method("tools/list", _params, session_id, opts) do
    {:ok, tools} = list_items(session_id, opts)
    {:ok, %{"tools" => tools}}
  end

  def handle_method("tools/call", params, session_id, opts) do
    tool_name = params["name"]
    tool_args = params["arguments"] || %{}

    opts =
      opts
      |> Keyword.update(
        :context,
        %{mcp_session_id: session_id},
        &Map.put(&1, :mcp_session_id, session_id)
      )
      |> Keyword.put(:filter, fn tool -> tool.mcp == :tool end)

    case find_tool(tool_name, opts) do
      nil ->
        {:error, {:tool_not_found, tool_name}}

      tool ->
        context =
          opts
          |> Keyword.take([:actor, :tenant, :context])
          |> Map.new()
          |> Map.update(
            :context,
            %{otp_app: opts[:otp_app]},
            &Map.put(&1, :otp_app, opts[:otp_app])
          )

        case tool.function.(tool_args, context) do
          {:ok, result, _} ->
            {:ok,
             %{
               "isError" => false,
               "content" => [%{"type" => "text", "text" => result}]
             }}

          {:error, error} ->
            Logger.warning("Tool execution failed: #{inspect(error)}")
            {:error, {:tool_execution_failed, error}}
        end
    end
  end

  def handle_method(_method, _params, _session_id, _opts) do
    :not_handled
  end

  # Private functions

  defp get_tools(opts) do
    opts =
      if opts[:tools] == :ash_dev_tools do
        opts
        |> Keyword.put(:actions, [{AshAi.DevTools.Tools, :*}])
        |> Keyword.put(:tools, [
          :list_ash_resources,
          :list_generators,
          :get_usage_rules,
          :list_packages_with_rules
        ])
      else
        opts
      end

    opts
    |> Keyword.take([:otp_app, :tools, :actor, :context, :tenant, :actions])
    |> Keyword.update(
      :context,
      %{otp_app: opts[:otp_app]},
      &Map.put(&1, :otp_app, opts[:otp_app])
    )
    |> AshAi.functions()
  end

  defp find_tool(tool_name, opts) do
    get_tools(opts)
    |> Enum.find(&(&1.name == tool_name))
  end
end
