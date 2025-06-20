# Model Context Protocol (MCP) Server Tutorial

This tutorial will guide you through setting up and using AshAi's Model Context Protocol (MCP) server implementation. MCP allows AI agents to access external tools, resources, and capabilities in a standardized way.

## Table of Contents

1. [What is MCP?](#what-is-mcp)
2. [Quick Start](#quick-start)
3. [Basic Configuration](#basic-configuration)
4. [Exposing Tools](#exposing-tools)
5. [Resource Capabilities](#resource-capabilities)
6. [Prompt Templates](#prompt-templates)
7. [Authentication Setup](#authentication-setup)
8. [Advanced Configuration](#advanced-configuration)
9. [Client Integration](#client-integration)
10. [Troubleshooting](#troubleshooting)

## What is MCP?

The Model Context Protocol (MCP) is an open standard for connecting AI assistants to external data sources and tools. It provides a way for AI agents to:

- **Access Tools**: Execute functions and operations
- **Read Resources**: Access databases, files, and external data
- **Use Prompts**: Leverage pre-built prompt templates
- **Maintain Sessions**: Keep state across interactions

AshAi's MCP implementation integrates seamlessly with Ash resources and domains, automatically exposing your business logic as AI-accessible tools.

## Quick Start

### 1. Add MCP Router to Your Phoenix Application

```elixir
# In your router.ex
defmodule MyAppWeb.Router do
  use MyAppWeb, :router

  # Add MCP routes
  scope "/api" do
    pipe_through :api
    
    # Basic MCP server without authentication
    forward "/mcp", AshAi.Mcp.Router,
      tools: [:create_user, :list_posts, :send_email],
      otp_app: :my_app
  end
end
```

### 2. Define Your Domain with Tools

```elixir
defmodule MyApp.Blog do
  use Ash.Domain, extensions: [AshAi]

  resources do
    resource MyApp.Blog.Post
    resource MyApp.Blog.User
  end

  # Expose actions as MCP tools
  tools do
    tool :create_post, MyApp.Blog.Post, :create
    tool :list_posts, MyApp.Blog.Post, :read
    tool :update_post, MyApp.Blog.Post, :update
    tool :delete_post, MyApp.Blog.Post, :destroy
  end
end
```

### 3. Start Your Application

```bash
mix phx.server
```

Your MCP server is now available at `http://localhost:4000/api/mcp`!

## Basic Configuration

### Domain Configuration

The MCP server automatically discovers tools, resources, and prompts from your Ash domains:

```elixir
defmodule MyApp.CRM do
  use Ash.Domain, extensions: [AshAi]

  resources do
    resource MyApp.CRM.Customer
    resource MyApp.CRM.Order
    resource MyApp.CRM.Product
  end

  tools do
    # Expose specific actions as tools
    tool :create_customer, MyApp.CRM.Customer, :create
    tool :find_customer, MyApp.CRM.Customer, :by_email
    tool :place_order, MyApp.CRM.Order, :create
    tool :get_order_status, MyApp.CRM.Order, :read
  end
end
```

### Router Options

Configure the MCP router with various options:

```elixir
forward "/mcp", AshAi.Mcp.Router,
  # Required: Your OTP application name
  otp_app: :my_app,
  
  # Optional: Specific tools to expose (defaults to all)
  tools: [:create_customer, :place_order],
  
  # Optional: Enable authentication
  auth_enabled?: true,
  auth_strategies: [:github, :google],
  require_auth?: false,
  
  # Optional: Custom session configuration
  session_timeout: :timer.hours(2),
  max_sessions: 1000
```

## Exposing Tools

### Simple Tool Exposure

Expose any Ash action as an MCP tool:

```elixir
# In your domain
tools do
  tool :send_notification, MyApp.Notifications, :send
  tool :process_payment, MyApp.Billing, :charge_card
  tool :generate_report, MyApp.Analytics, :create_report
end
```

### Tool with Custom Configuration

```elixir
tools do
  # Tool with custom name and description
  tool :email_customer, MyApp.Communications, :send_email do
    description "Send an email to a customer with optional template"
    argument :template, :string, allow_nil?: true
    argument :priority, :string, constraints: [one_of: ["low", "normal", "high"]]
  end
end
```

### Resource Definition for Tools

Define your resources with actions that work well as tools:

```elixir
defmodule MyApp.Blog.Post do
  use Ash.Resource, 
    domain: MyApp.Blog,
    data_layer: AshPostgres.DataLayer

  attributes do
    uuid_primary_key :id
    attribute :title, :string, allow_nil?: false
    attribute :content, :string
    attribute :published, :boolean, default: false
    create_timestamp :created_at
    update_timestamp :updated_at
  end

  actions do
    defaults [:create, :read, :update, :destroy]

    # Custom action that works great as an MCP tool
    create :publish do
      description "Publish a blog post with SEO optimization"
      
      argument :title, :string, allow_nil?: false
      argument :content, :string, allow_nil?: false
      argument :tags, {:array, :string}, default: []
      argument :auto_seo, :boolean, default: true
      
      change set_attribute(:published, true)
      change MyApp.Blog.Changes.OptimizeForSEO
    end

    # Read action with useful filtering
    read :by_status do
      description "Find posts by publication status"
      argument :published, :boolean, allow_nil?: false
      filter expr(published == ^arg(:published))
    end
  end
end
```

## Resource Capabilities

MCP's resource capability allows AI agents to read from your data sources:

### Automatic Resource Exposure

All Ash resources in your domains are automatically available through the MCP resources capability:

```bash
# AI agent can request:
# mcp://MyApp.Blog/Post - Access blog posts
# mcp://MyApp.CRM/Customer - Access customer data
# mcp://MyApp.Inventory/Product - Access product catalog
```

### Custom Resource Descriptions

Add descriptions to your resources for better AI understanding:

```elixir
defmodule MyApp.CRM.Customer do
  use Ash.Resource,
    domain: MyApp.CRM,
    description: "Customer records with contact information and purchase history"

  attributes do
    uuid_primary_key :id
    attribute :email, :string, description: "Primary contact email"
    attribute :name, :string, description: "Full customer name"
    attribute :phone, :string, description: "Contact phone number"
    attribute :status, :string, constraints: [one_of: ["active", "inactive", "suspended"]]
  end

  # Actions automatically become resource operations
  actions do
    defaults [:create, :read, :update]
    
    read :active_customers do
      description "Get all active customers"
      filter expr(status == "active")
    end
  end
end
```

## Prompt Templates

Create reusable prompt templates for common AI tasks:

### System Prompts

```elixir
defmodule MyApp.Blog.Post do
  use Ash.Resource, extensions: [AshAi]

  # Define prompt-backed actions
  actions do
    create :generate_content do
      description "Generate blog post content using AI"
      
      argument :topic, :string, allow_nil?: false
      argument :tone, :string, constraints: [one_of: ["professional", "casual", "technical"]]
      argument :length, :integer, default: 500
      
      # This action uses AI to generate content
      run AshAi.Actions.Prompt
    end
  end
  
  # The prompt will be automatically available via MCP
  # as "MyApp.Blog.Post.generate_content"
end
```

### Custom Prompt Templates

```elixir
# Prompts are automatically discovered from prompt-backed actions
# AI agents can use:
# - prompts/list: Get available prompt templates  
# - prompts/get: Render a specific prompt with arguments

# Example prompt usage:
# Template: "blog.generate_content"
# Arguments: {"topic": "AI in Healthcare", "tone": "professional", "length": 800}
```

## Authentication Setup

### OAuth Configuration

Enable OAuth authentication for secure MCP access:

```elixir
# config/config.exs
config :my_app, MyAppWeb.Endpoint,
  # ... other config

# OAuth provider configuration
config :my_app, :oauth,
  github: [
    client_id: System.get_env("GITHUB_CLIENT_ID"),
    client_secret: System.get_env("GITHUB_CLIENT_SECRET")
  ],
  google: [
    client_id: System.get_env("GOOGLE_CLIENT_ID"), 
    client_secret: System.get_env("GOOGLE_CLIENT_SECRET")
  ]
```

### Router with Authentication

```elixir
# Authenticated MCP endpoint
scope "/api" do
  pipe_through :api
  
  forward "/mcp", AshAi.Mcp.Router,
    otp_app: :my_app,
    tools: [:all],
    
    # Enable OAuth authentication
    auth_enabled?: true,
    auth_strategies: [:github, :google],
    require_auth?: false,  # Allow both auth'd and unauth'd access
    
    # OAuth redirect URLs
    success_redirect: "/dashboard",
    failure_redirect: "/login?error=oauth_failed"
end

# Optional: OAuth-only routes
scope "/api/secure" do
  pipe_through :api
  
  forward "/mcp", AshAi.Mcp.Router,
    otp_app: :my_app,
    tools: [:admin_tools, :sensitive_operations],
    auth_enabled?: true,
    require_auth?: true  # Require authentication
end
```

### Authentication Flow

1. **Initialize OAuth**: `GET /api/mcp/auth/github`
2. **Handle Callback**: User completes OAuth flow
3. **Get Session**: MCP client receives session ID
4. **Use Session**: Include `MCP-Session-ID` header in requests

```bash
# Example authenticated request
curl -X POST http://localhost:4000/api/mcp \
  -H "Content-Type: application/json" \
  -H "MCP-Session-ID: your-session-id" \
  -d '{"method": "tools/call", "params": {"name": "create_customer", "arguments": {...}}}'
```

## Advanced Configuration

### Custom Capability Development

Create custom MCP capabilities:

```elixir
defmodule MyApp.Mcp.CustomCapability do
  @behaviour AshAi.Mcp.Capability

  @impl true
  def capability_name, do: "custom"

  @impl true  
  def capability_config do
    %{
      "custom" => %{
        "operations" => ["process", "analyze"],
        "version" => "1.0.0"
      }
    }
  end

  @impl true
  def list_items(_opts) do
    {:ok, [
      %{"name" => "data_processor", "description" => "Process data files"},
      %{"name" => "sentiment_analyzer", "description" => "Analyze text sentiment"}
    ]}
  end

  @impl true
  def handle_method("custom/process", params, session_id, opts) do
    # Custom processing logic
    {:ok, %{"result" => "processed", "session" => session_id}}
  end

  def handle_method(_method, _params, _session_id, _opts) do
    :not_handled
  end
end

# Register the capability
AshAi.Mcp.Registry.register_capability(:custom, MyApp.Mcp.CustomCapability)
```

### Environment-Specific Configuration

```elixir
# config/dev.exs
config :my_app, :mcp,
  auth_required: false,
  debug_mode: true,
  session_timeout: :timer.minutes(30)

# config/prod.exs  
config :my_app, :mcp,
  auth_required: true,
  debug_mode: false,
  session_timeout: :timer.hours(4),
  rate_limiting: [
    max_requests: 1000,
    window: :timer.minutes(15)
  ]
```

### Session Management

```elixir
# Custom session configuration
forward "/mcp", AshAi.Mcp.Router,
  otp_app: :my_app,
  
  # Session options
  session_timeout: :timer.hours(2),
  max_sessions: 1000,
  cleanup_interval: :timer.minutes(10),
  
  # Session storage (default: ETS)
  session_adapter: MyApp.SessionStore
```

## Client Integration

### MCP Client Libraries

Popular MCP client libraries that work with AshAi:

- **Python**: `mcp-client`
- **TypeScript**: `@modelcontextprotocol/client`
- **Rust**: `mcp-client-rs`

### Python Example

```python
from mcp_client import MCPClient

# Connect to your AshAi MCP server
client = MCPClient("http://localhost:4000/api/mcp")

# Initialize connection
await client.initialize("my-ai-agent", "1.0.0")

# List available tools
tools = await client.list_tools()
print(f"Available tools: {[tool['name'] for tool in tools]}")

# Execute a tool
result = await client.call_tool("create_customer", {
    "name": "John Doe",
    "email": "john@example.com",
    "phone": "+1234567890"
})

print(f"Created customer: {result}")

# Access resources  
resources = await client.list_resources()
customer_data = await client.read_resource("mcp://MyApp.CRM/Customer")

# Use prompt templates
prompts = await client.list_prompts()
generated = await client.get_prompt("blog.generate_content", {
    "topic": "MCP Integration",
    "tone": "technical",
    "length": 600
})
```

### Claude Desktop Integration

Configure Claude Desktop to use your MCP server:

```json
// claude_desktop_config.json
{
  "mcpServers": {
    "my-app": {
      "command": "curl",
      "args": [
        "-X", "POST",
        "http://localhost:4000/api/mcp",
        "-H", "Content-Type: application/json"
      ],
      "env": {
        "MCP_SESSION_ID": "your-session-id"
      }
    }
  }
}
```

## Troubleshooting

### Common Issues

#### 1. Tools Not Appearing

**Problem**: MCP client can't see your tools

**Solutions**:
- Verify domain is properly configured with `tools do` block
- Check that actions exist on the specified resource
- Ensure OTP app name matches your application
- Check MCP server logs for registration errors

```elixir
# Debug tool registration
AshAi.Mcp.Registry.list_capabilities()
```

#### 2. Authentication Failures

**Problem**: OAuth flow fails or sessions expire

**Solutions**:
- Verify OAuth provider credentials in config
- Check redirect URLs match OAuth app settings
- Ensure session store is working correctly
- Check network connectivity for OAuth callbacks

```elixir
# Debug session state
AshAi.Mcp.Session.list_sessions()
```

#### 3. Permission Errors

**Problem**: Tools execute but return permission errors

**Solutions**:
- Check Ash policies and authorizers
- Verify actor context is properly set
- Ensure authenticated user has required permissions
- Review Ash action argument validation

#### 4. Resource Access Issues

**Problem**: MCP resources return empty or error responses

**Solutions**:
- Verify resource relationships and aggregates
- Check database connectivity
- Review Ash policies on read actions
- Ensure proper tenant context if using multitenancy

### Debugging Tips

#### Enable Debug Logging

```elixir
# config/dev.exs
config :logger, level: :debug

# In your application
require Logger
Logger.debug("MCP Tool executed: #{inspect(result)}")
```

#### Test MCP Endpoints Manually

```bash
# Test initialization
curl -X POST http://localhost:4000/api/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize", 
    "params": {
      "protocolVersion": "1.0.0",
      "clientInfo": {"name": "test", "version": "1.0.0"}
    }
  }'

# Test tool listing
curl -X POST http://localhost:4000/api/mcp \
  -H "Content-Type: application/json" \
  -H "MCP-Session-ID: session-id-from-init" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/list"
  }'
```

#### Inspect Registry State

```elixir
# In IEx console
iex> AshAi.Mcp.Registry.list_capabilities()
iex> AshAi.Mcp.Session.list_sessions()
```

### Performance Optimization

#### Session Management

```elixir
# Optimize session cleanup
config :ash_ai, AshAi.Mcp.Session,
  cleanup_interval: :timer.minutes(5),
  session_timeout: :timer.hours(1),
  max_sessions: 500
```

#### Tool Execution

```elixir
# Use async execution for slow tools
defmodule MyApp.SlowOperations do
  use Ash.Resource

  actions do
    create :process_large_file do
      # Use async execution
      run {MyApp.AsyncProcessor, :process}
    end
  end
end
```

#### Resource Optimization

```elixir
# Optimize resource queries
defmodule MyApp.CRM.Customer do
  actions do
    read :for_mcp do
      # Limit fields for MCP access
      select [:id, :name, :email, :status]
      # Add pagination
      pagination offset?: true, keyset?: true, default_limit: 50
    end
  end
end
```

---

This tutorial covers the essential aspects of using AshAi's MCP implementation. For more advanced topics, check out the [API documentation](https://hexdocs.pm/ash_ai) and [source code examples](https://github.com/ash-project/ash_ai).

## Next Steps

- Explore the [MCP Protocol Specification](https://spec.modelcontextprotocol.io/)
- Check out [example MCP integrations](https://github.com/modelcontextprotocol/examples)
- Join the [Ash Framework community](https://discord.gg/D7FNG2q) for support
- Contribute to [AshAi development](https://github.com/ash-project/ash_ai)