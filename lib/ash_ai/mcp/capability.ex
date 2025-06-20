defmodule AshAi.Mcp.Capability do
  @moduledoc """
  Behavior for MCP capabilities.

  MCP capabilities define different types of functionality that can be exposed
  through the Model Context Protocol, such as tools, resources, and prompts.
  """

  @doc """
  Returns the capability name (e.g., "tools", "resources", "prompts")
  """
  @callback capability_name() :: String.t()

  @doc """
  Returns the capability configuration that will be included in the MCP
  initialize response under the "capabilities" key.
  """
  @callback capability_config() :: map()

  @doc """
  Lists all items for this capability.
  """
  @callback list_items(session_id :: String.t(), opts :: keyword()) ::
              {:ok, list()} | {:error, term()}

  @doc """
  Handles method calls for this capability.
  Returns {:ok, response} for successful operations, {:error, error} for failures,
  or :not_handled if this capability doesn't handle the given method.
  """
  @callback handle_method(
              method :: String.t(),
              params :: map(),
              session_id :: String.t(),
              opts :: keyword()
            ) ::
              {:ok, map()} | {:error, term()} | :not_handled

  @optional_callbacks [list_items: 2, handle_method: 4]
end
