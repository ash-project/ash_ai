defmodule AshAi.Mcp do
  @moduledoc """
  Model Context Protocol (MCP) implementation for Ash Framework.

  This module implements a [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server
  that integrates with Ash Framework, following the MCP [Streamable HTTP Transport](https://modelcontextprotocol.io/specification/2025-03-26/basic/transports#streamable-http) specification.

  ## Overview

  This MCP implementation provides:

  * A fully compliant MCP server with JSON-RPC message processing
  * Session management with unique session IDs
  * Support for both JSON and Server-Sent Events (SSE) responses
  * Batch request handling
  * A foundation for integrating Ash resources with MCP clients
  * Integration with AshAi tools for AI-assisted operations

  ## Current Features

  * `initialize` and `shutdown` method handlers
  * Session management via GenServer processes
  * Support for streaming responses
  * Plug-compatible router for easy integration
  * Tool support for AshAi functions

  ## Future Enhancements

  * OAuth integration with AshAuthentication
  * Resource-specific method handlers
  * Advanced streaming capabilities

  ## Integration

  ### With Phoenix

  ```elixir
  # In your Phoenix router
  forward "/mcp", AshAi.Mcp.router()

  # With tools enabled
  forward "/mcp", AshAi.Mcp.Router, tools: [:tool1, :tool2]
  ```

  ### With Any Plug-Based Application

  The MCP router is a standard Plug, so it can be integrated into any Plug-based application.
  You are responsible for hosting the Plug however you prefer.

  ## Client-Server Communication Example

  ```javascript
  // Post to the MCP endpoint
  const response = await fetch('http://your-host/mcp', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json, text/event-stream'
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        client: {
          name: 'My MCP Client',
          version: '1.0.0'
        }
      }
    })
  });

  const sessionId = response.headers.get('mcp-session-id');
  const result = await response.json();

  // Use sessionId for subsequent requests
  ```
  """

  use Supervisor

  def start_link(state) do
    Supervisor.start_link(__MODULE__, state, name: __MODULE__)
  end

  @impl true
  def init(_state) do
    children = [
      # Registry for session tracking
      {Registry, name: __MODULE__.Registry, keys: :unique},

      # Dynamic supervisor for session processes
      {DynamicSupervisor, name: __MODULE__.SessionSupervisor, strategy: :one_for_one}
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end
end
