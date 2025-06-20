defmodule AshAi.Mcp.Capabilities.Prompts do
  @moduledoc """
  MCP Prompts capability implementation.

  This module handles the prompts capability for the MCP server,
  allowing clients to discover and use prompt templates from AshAi.
  """

  @behaviour AshAi.Mcp.Capability

  require Logger
  alias AshAi.Mcp.PromptTemplate

  @impl AshAi.Mcp.Capability
  def capability_name, do: "prompts"

  @impl AshAi.Mcp.Capability
  def capability_config do
    %{
      "listChanged" => false
    }
  end

  @impl AshAi.Mcp.Capability
  def list_items(_session_id, opts) do
    case PromptTemplate.discover_prompts(opts) do
      {:ok, prompts} ->
        prompt_list = Enum.map(prompts, &PromptTemplate.to_mcp_prompt/1)
        {:ok, prompt_list}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @impl AshAi.Mcp.Capability
  def handle_method("prompts/list", _params, session_id, opts) do
    case list_items(session_id, opts) do
      {:ok, prompts} ->
        {:ok, %{"prompts" => prompts}}

      {:error, :otp_app_required} ->
        {:error, {:missing_configuration, "otp_app is required for prompt discovery"}}

      {:error, {:discovery_failed, error}} ->
        Logger.warning("Prompt discovery failed: #{inspect(error)}")
        {:error, {:discovery_failed, "Failed to discover prompts"}}
    end
  end

  def handle_method("prompts/get", params, _session_id, opts) do
    name = params["name"]
    arguments = params["arguments"] || %{}

    if is_nil(name) do
      {:error, {:missing_parameter, "name parameter is required"}}
    else
      case PromptTemplate.get_prompt(name, arguments, opts) do
        {:ok, rendered_prompt} ->
          {:ok, rendered_prompt}

        {:error, :prompt_not_found} ->
          {:error, {:prompt_not_found, "Prompt '#{name}' not found"}}

        {:error, {:render_failed, error}} ->
          Logger.warning("Prompt rendering failed for '#{name}': #{inspect(error)}")
          {:error, {:render_failed, "Failed to render prompt"}}

        {:error, error} ->
          Logger.warning("Prompt get failed for '#{name}': #{inspect(error)}")
          {:error, {:prompt_get_failed, "Failed to get prompt"}}
      end
    end
  end

  def handle_method(_method, _params, _session_id, _opts) do
    :not_handled
  end
end
