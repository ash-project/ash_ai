defmodule AshAi.Mcp.Registry do
  @moduledoc """
  Registry for MCP capabilities.

  This module manages the registration and discovery of MCP capabilities
  such as tools, resources, and prompts. It uses ETS for fast lookups
  and supports dynamic capability registration.

  This module now delegates to AshMcp.Registry for core functionality.
  """

  @deprecated "Use AshMcp.Registry instead"

  require Logger

  @doc """
  Starts the registry process.
  """
  def start_link(opts \\ []) do
    if Code.ensure_loaded?(AshMcp.Registry) do
      AshMcp.Registry.start_link(opts)
    else
      {:error, :ash_mcp_not_available}
    end
  end

  @doc """
  Registers a capability module.
  """
  def register_capability(name, module, opts \\ []) when is_atom(module) do
    if Code.ensure_loaded?(AshMcp.Registry) do
      AshMcp.Registry.register_capability(name, module, opts)
    else
      {:error, :ash_mcp_not_available}
    end
  end

  @doc """
  Unregisters a capability.
  """
  def unregister_capability(name) do
    if Code.ensure_loaded?(AshMcp.Registry) do
      AshMcp.Registry.unregister_capability(name)
    else
      {:error, :ash_mcp_not_available}
    end
  end

  @doc """
  Lists all registered capabilities.
  """
  def list_capabilities do
    if Code.ensure_loaded?(AshMcp.Registry) do
      AshMcp.Registry.list_capabilities()
    else
      []
    end
  end

  @doc """
  Gets capability information by name.
  """
  def get_capability(name) do
    if Code.ensure_loaded?(AshMcp.Registry) do
      AshMcp.Registry.get_capability(name)
    else
      {:error, :ash_mcp_not_available}
    end
  end

  @doc """
  Builds the capabilities configuration for MCP initialize response.
  """
  def build_capabilities_config(session_id, opts \\ []) do
    if Code.ensure_loaded?(AshMcp.Registry) do
      AshMcp.Registry.build_capabilities_config(session_id, opts)
    else
      %{}
    end
  end

  @doc """
  Handles a method call by dispatching to the appropriate capability.
  """
  def handle_method(method, params, session_id, opts \\ []) do
    if Code.ensure_loaded?(AshMcp.Registry) do
      AshMcp.Registry.handle_method(method, params, session_id, opts)
    else
      :not_handled
    end
  end

  @doc """
  Register default capabilities with AshMcp.Registry.
  """
  def register_default_capabilities do
    if Code.ensure_loaded?(AshMcp.Registry) do
      # Register Ash-specific capabilities
      AshMcp.Registry.register_capability(:ash_tools, AshAi.Mcp.Tools, [])
      AshMcp.Registry.register_capability(:ash_resources, AshAi.Mcp.Resources, [])

      # Register old capabilities for backward compatibility
      if Code.ensure_loaded?(AshAi.Mcp.Capabilities.Prompts) do
        AshMcp.Registry.register_capability(:prompts, AshAi.Mcp.Capabilities.Prompts, [])
      end

      if Code.ensure_loaded?(AshAi.Mcp.Capabilities.Sampling) do
        AshMcp.Registry.register_capability(:sampling, AshAi.Mcp.Capabilities.Sampling, [])
      end
    end
  end
end
