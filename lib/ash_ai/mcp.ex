# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp do
  @moduledoc """
  Model Context Protocol (MCP) implementation for Ash Framework.

  This module implements a [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server
  that integrates with Ash Framework over the MCP [Streamable HTTP Transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http).

  The server supports multiple protocol revisions in tandem on the same
  endpoint: `2026-07-28` (stateless, per-request `_meta`, `server/discover`,
  mirrored `Mcp-Method`/`Mcp-Name` headers) as well as `2025-06-18` and
  `2025-03-26` (the `initialize` handshake, `Mcp-Session-Id`). See
  `AshAi.Mcp.Server` for how the revision is selected per request.

  ## Overview

  This MCP implementation provides:

  * A fully compliant MCP server with JSON-RPC message processing
  * Support for protocol version `2026-07-28` and older versions in tandem
  * Support for both JSON and Server-Sent Events (SSE) responses
  * Batch request handling (protocol version `2025-03-26`)
  * A foundation for integrating Ash resources with MCP clients
  * Integration with AshAi tools for AI-assisted operations

  ## Current Features

  * Stateless `2026-07-28` requests, `server/discover`, and
    `subscriptions/listen`
  * `initialize` and `shutdown` method handlers for initialize-based
    protocol revisions, with session IDs
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
  forward "/mcp", AshAi.Mcp.Router

  # With tools enabled
  forward "/mcp", AshAi.Mcp.Router, tools: [:tool1, :tool2]
  ```

  ### With Any Plug-Based Application

  The MCP router is a standard Plug, so it can be integrated into any Plug-based application.
  You are responsible for hosting the Plug however you prefer.
  """
end
