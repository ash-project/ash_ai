# AshMcp

A Model Context Protocol (MCP) server implementation for Elixir applications.

AshMcp provides a framework for building MCP servers with support for tools, resources, prompts, and sampling capabilities. It includes optional integration with the Ash framework for enhanced functionality.

## Features

- **Core MCP Protocol**: Full JSON-RPC 2.0 implementation following MCP specification
- **Capability System**: Extensible architecture for adding new MCP capabilities
- **Session Management**: Built-in session handling with automatic cleanup
- **Phoenix Integration**: Router and Plug support for easy Phoenix integration
- **Ash Integration**: Optional tight integration with Ash framework (when available)
- **Authentication Ready**: Framework for adding OAuth and other auth strategies

## Installation

Add `ash_mcp` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:ash_mcp, "~> 0.1.0"}
  ]
end
```

## Basic Usage

### 1. Define a Capability

```elixir
defmodule MyApp.ToolsCapability do
  @behaviour AshMcp.Capability

  @impl AshMcp.Capability
  def capability_name, do: "tools"

  @impl AshMcp.Capability
  def capability_config do
    %{"listChanged" => false}
  end

  @impl AshMcp.Capability
  def list_items(_session_id, _opts) do
    tools = [
      %{
        "name" => "hello_world",
        "description" => "Says hello to the world",
        "inputSchema" => %{
          "type" => "object",
          "properties" => %{
            "name" => %{"type" => "string", "description" => "Name to greet"}
          }
        }
      }
    ]
    {:ok, tools}
  end

  @impl AshMcp.Capability
  def handle_method("tools/call", params, _session_id, _opts) do
    case params do
      %{"name" => "hello_world", "arguments" => %{"name" => name}} ->
        {:ok, %{
          "isError" => false,
          "content" => [%{"type" => "text", "text" => "Hello, #{name}!"}]
        }}
      _ ->
        {:error, :invalid_tool_call}
    end
  end

  def handle_method(_method, _params, _session_id, _opts) do
    :not_handled
  end
end
```

### 2. Add to Phoenix Router

```elixir
# In your Phoenix router
scope "/mcp" do
  forward "/", AshMcp.Router,
    capabilities: [MyApp.ToolsCapability],
    otp_app: :my_app
end
```

### 3. Register Capabilities (Alternative)

You can also register capabilities at runtime:

```elixir
# In your application start/2
AshMcp.register_capability(:tools, MyApp.ToolsCapability)
```

## Ash Integration

When using with Ash framework applications, you can use the built-in Ash capabilities:

```elixir
# In your router
scope "/mcp" do
  forward "/", AshMcp.Router,
    capabilities: [AshMcp.AshTools],  # Uses AshAi integration
    otp_app: :my_app,
    tools: [:availability_check]  # Specific tools to expose
end
```

This automatically exposes Ash actions defined as tools in your domains.

## Configuration

The MCP server can be configured with various options:

```elixir
forward "/", AshMcp.Router,
  capabilities: [MyApp.ToolsCapability],
  otp_app: :my_app,
  server_name: "My MCP Server",
  server_version: "1.0.0",
  protocol_version: "2025-03-26",
  session_timeout: :timer.hours(2),
  max_sessions: 1000
```

## Sessions

AshMcp automatically manages sessions for each MCP client connection:

```elixir
# Create a session
{:ok, session} = AshMcp.create_session("session-id")

# Get session info
{:ok, session} = AshMcp.get_session("session-id")

# Terminate session
:ok = AshMcp.terminate_session("session-id")
```

## Creating Custom Capabilities

Implement the `AshMcp.Capability` behaviour:

```elixir
defmodule MyApp.CustomCapability do
  @behaviour AshMcp.Capability

  def capability_name, do: "my_capability"
  def capability_config, do: %{}
  def list_items(_session_id, _opts), do: {:ok, []}
  def handle_method(_method, _params, _session_id, _opts), do: :not_handled
end
```

## License

MIT License - see [LICENSE](LICENSE) for details. 