defmodule AshAi.Mcp do
  @moduledoc """
  Integration module for Model Context Protocol (MCP) in AshAi.

  This module provides a clean interface to the AshMcp library with
  Ash-specific capabilities and integrations.

  ## Usage

  In your Phoenix router:

      scope "/mcp" do
        pipe_through :api
        forward "/", AshAi.Mcp.Router,
          otp_app: :my_app,
          tools: [:my_tool],
          auth_enabled?: true
      end

  Or for development:

      scope "/dev" do
        plug AshAi.Mcp.Dev,
          otp_app: :my_app,
          tools: :ash_dev_tools
      end
  """

  @doc """
  Register an Ash domain's tools as MCP capabilities.

  This automatically registers all tools defined in the domain
  with the MCP server.
  """
  def register_domain_tools(domain) when is_atom(domain) do
    if Code.ensure_loaded?(domain) and function_exported?(domain, :__ash_ai_tools__, 0) do
      tools = domain.__ash_ai_tools__()

      # Register the domain as a tools capability
      if Code.ensure_loaded?(AshMcp) do
        AshMcp.register_capability(domain, AshAi.Mcp.DomainTools, domain: domain, tools: tools)
      end
    end
  end

  @doc """
  Get all tools from registered Ash domains.
  """
  def get_ash_tools(opts \\ []) do
    if Code.ensure_loaded?(AshAi) do
      AshAi.functions(opts)
    else
      []
    end
  end

  @doc """
  Create an MCP server configuration for Ash applications.
  """
  def ash_mcp_config(opts) do
    base_capabilities = [
      AshAi.Mcp.Tools,
      AshAi.Mcp.Resources
    ]

    additional_capabilities = opts[:capabilities] || []

    opts
    |> Keyword.put(:capabilities, base_capabilities ++ additional_capabilities)
    |> Keyword.put_new(:server_name, "AshAi MCP Server")
    |> Keyword.put_new(:server_version, Application.spec(:ash_ai, :vsn) |> to_string())
  end
end
