defmodule AshMcp.Capability do
  @moduledoc """
  Behaviour for implementing MCP capabilities.

  Capabilities are the primary way to extend MCP servers with functionality.
  Each capability handles specific MCP methods and provides a list of items
  (tools, resources, prompts, etc.) that the capability exposes.

  ## Example

      defmodule MyApp.ToolsCapability do
        @behaviour AshMcp.Capability

        @impl AshMcp.Capability
        def capability_name, do: "tools"

        @impl AshMcp.Capability
        def capability_config do
          %{"listChanged" => false}
        end

        @impl AshMcp.Capability
        def list_items(_session_id, opts) do
          tools = get_tools_from_somewhere(opts)
          {:ok, tools}
        end

        @impl AshMcp.Capability
        def handle_method("tools/call", params, session_id, opts) do
          # Handle tool execution
          {:ok, %{"result" => "Tool executed successfully"}}
        end

        def handle_method(_method, _params, _session_id, _opts) do
          :not_handled
        end
      end
  """

  @doc """
  Returns the name of the capability (e.g., "tools", "resources", "prompts").
  """
  @callback capability_name() :: String.t()

  @doc """
  Returns the configuration for this capability that will be sent
  during MCP initialization.
  """
  @callback capability_config() :: map()

  @doc """
  Returns a list of items that this capability exposes.

  For tools capability, this would be a list of available tools.
  For resources capability, this would be a list of available resources.
  """
  @callback list_items(session_id :: String.t(), opts :: Keyword.t()) ::
              {:ok, list()} | {:error, term()}

  @doc """
  Handles MCP method calls for this capability.

  Should return `:not_handled` if the method is not supported by this capability.
  """
  @callback handle_method(
              method :: String.t(),
              params :: map(),
              session_id :: String.t(),
              opts :: Keyword.t()
            ) :: {:ok, map()} | {:error, term()} | :not_handled
end
