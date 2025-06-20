defmodule AshMcp do
  @moduledoc """
  A Model Context Protocol (MCP) server implementation for Elixir applications.

  AshMcp provides a framework for building MCP servers with support for:
  - Tools capability for exposing functions to AI agents
  - Resources capability for providing structured data access
  - Prompts capability for reusable prompt templates
  - Sampling capability for AI model configuration
  - OAuth authentication integration
  - Session management

  ## Basic Usage

  To create an MCP server, you define capability modules and configure a router:

      # Define a tools capability
      defmodule MyApp.McpTools do
        @behaviour AshMcp.Capability

        def capability_name, do: "tools"
        def capability_config, do: %{"listChanged" => false}

        def list_items(_session_id, _opts) do
          {:ok, [%{"name" => "my_tool", "description" => "Does something"}]}
        end

        def handle_method("tools/call", params, _session_id, _opts) do
          # Handle tool execution
          {:ok, %{"result" => "success"}}
        end
      end

      # In your Phoenix router
      scope "/mcp" do
        forward "/", AshMcp.Router,
          capabilities: [MyApp.McpTools],
          otp_app: :my_app
      end

  ## With Authentication

      scope "/mcp" do
        forward "/", AshMcp.Router,
          capabilities: [MyApp.McpTools],
          otp_app: :my_app,
          auth_enabled?: true,
          auth_strategies: [:github, :google]
      end
  """

  @doc """
  Register a capability module with the MCP registry.

  This is typically called during application startup to make capabilities
  available to the MCP server.
  """
  defdelegate register_capability(name, module, opts \\ []), to: AshMcp.Registry

  @doc """
  Get all registered capabilities.
  """
  defdelegate get_capabilities(), to: AshMcp.Registry

  @doc """
  Build capabilities configuration for MCP initialization response.
  """
  defdelegate build_capabilities_config(session_id, opts \\ []), to: AshMcp.Registry

  @doc """
  Create a new MCP session.
  """
  defdelegate create_session(session_id, opts \\ []), to: AshMcp.Session

  @doc """
  Get an existing MCP session.
  """
  defdelegate get_session(session_id), to: AshMcp.Session

  @doc """
  Terminate an MCP session.
  """
  defdelegate terminate_session(session_id), to: AshMcp.Session
end
