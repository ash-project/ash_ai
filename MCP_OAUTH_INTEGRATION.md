# MCP OAuth Authentication Integration

## Overview

This document describes the OAuth authentication integration for AshAi MCP servers. The implementation provides secure authentication for MCP endpoints while maintaining compatibility with the existing AshAuthentication framework.

## Architecture

### Components

1. **AshAi.Mcp.Auth** - Main authentication module providing OAuth integration
2. **AshAi.Mcp.Auth.Strategy** - OAuth2 strategy helpers for multiple providers
3. **AshAi.Mcp.Auth.OAuthRouter** - OAuth flow handling and callback processing
4. **Enhanced MCP Router** - Authentication middleware integration
5. **Enhanced Session Management** - User context and authentication state

### Integration Points

The OAuth implementation integrates with:
- **AshAuthentication** - Leverages existing OAuth2 strategies and configuration
- **MCP Sessions** - Links OAuth authentication with MCP session lifecycle
- **Ash Context** - Provides authenticated user as actor for Ash operations

## Configuration

### Basic Setup

```elixir
# In Phoenix router
scope "/mcp" do
  forward "/", AshAi.Mcp.Router,
    otp_app: :my_app,
    auth_enabled?: true,
    auth_strategies: [:github, :google],
    require_auth?: false  # Optional authentication
end
```

### Required Environment Variables

```bash
# GitHub OAuth
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret

# Google OAuth  
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
```

### AshAuthentication Integration

The implementation is designed to work with existing AshAuthentication configurations:

```elixir
# In your user resource
defmodule MyApp.Accounts.User do
  use Ash.Resource, 
    extensions: [AshAuthentication]

  authentication do
    strategies do
      oauth2 :github do
        client_id fn _, _ -> System.get_env("GITHUB_CLIENT_ID") end
        client_secret fn _, _ -> System.get_env("GITHUB_CLIENT_SECRET") end
        redirect_uri fn _, _ -> "http://localhost:4000/mcp/auth/github/callback" end
      end
    end
  end
end
```

## OAuth Flow

### 1. Authorization Request

```
GET /mcp/auth/{provider}
```

Initiates OAuth flow by redirecting to provider's authorization server.

**Parameters:**
- `provider` - OAuth provider name (github, google, etc.)

**Response:**
- `302 Redirect` to OAuth provider authorization URL

### 2. Authorization Callback

```
GET /mcp/auth/{provider}/callback?code=...&state=...
```

Handles OAuth provider callback, exchanges code for token, and creates MCP session.

**Parameters:**
- `code` - Authorization code from provider
- `state` - CSRF protection state parameter

**Response:**
- `302 Redirect` to success or failure page

### 3. Authentication Status

```
GET /mcp/auth/status
```

Returns current authentication status for MCP clients.

**Response:**
```json
{
  "authenticated": true,
  "user": {
    "id": 1,
    "email": "user@example.com"
  },
  "session_id": "mcp_session_uuid",
  "auth_method": "session"
}
```

## Authentication Methods

### 1. Session-Based Authentication

After OAuth completion, users are authenticated via session cookies:

```http
Cookie: mcp_session_id=uuid; current_user_id=1
```

### 2. Bearer Token Authentication

For API access, bearer tokens can be used:

```http
Authorization: Bearer your_jwt_token
```

### 3. Unauthenticated Access

When `require_auth?: false`, MCP endpoints work without authentication:

```elixir
# User context will be nil
%{actor: nil, authenticated?: false}
```

## MCP Session Integration

### Enhanced Session Structure

```elixir
%AshAi.Mcp.Session{
  id: "session_uuid",
  auth_context: %{
    user: %User{},
    provider: :github,
    authenticated_at: ~U[2024-01-01 00:00:00Z]
  },
  status: :active,
  # ... other session fields
}
```

### Authentication Context

Authenticated requests include user context:

```elixir
%{
  actor: %User{id: 1, email: "user@example.com"},
  context: %{
    authenticated?: true,
    auth_method: :session,
    mcp_session: %Session{...}
  }
}
```

## Supported OAuth Providers

### Built-in Provider Support

- **GitHub** - Full support with user info normalization
- **Google** - OAuth2 with Google APIs integration
- **Discord** - Discord OAuth with avatar URL handling
- **Microsoft** - Microsoft Graph integration

### Provider Configuration

Each provider has default configuration but can be customized:

```elixir
# Custom provider configuration
%{
  name: :custom_provider,
  authorization_url: "https://provider.com/oauth/authorize",
  token_url: "https://provider.com/oauth/token",
  user_url: "https://provider.com/api/user",
  scopes: ["read:user", "user:email"]
}
```

## Security Features

### CSRF Protection

- State parameter validation
- Session-based state storage
- Automatic state cleanup after use

### Token Security

- JWT tokens with configurable expiration
- Bearer token validation and refresh
- Secure session management

### Origin Validation

- Callback URL validation
- Provider-specific security measures
- Error handling for security violations

## Error Handling

### OAuth Errors

Common OAuth errors are handled gracefully:

```json
{
  "error": "invalid_grant",
  "error_description": "The authorization code is invalid"
}
```

### MCP Protocol Errors

Authentication errors are mapped to MCP-compliant responses:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32000,
    "message": "Authentication required"
  }
}
```

## Usage Examples

### Phoenix Router Setup

```elixir
defmodule MyAppWeb.Router do
  use MyAppWeb, :router

  scope "/api" do
    # Authenticated MCP endpoint
    forward "/mcp", AshAi.Mcp.Router,
      otp_app: :my_app,
      auth_enabled?: true,
      auth_strategies: [:github],
      require_auth?: true

    # Public MCP endpoint
    forward "/mcp-public", AshAi.Mcp.Router,
      otp_app: :my_app,
      auth_enabled?: false
  end
end
```

### MCP Client Authentication

```javascript
// 1. Initiate OAuth flow
window.open('/mcp/auth/github', 'oauth', 'width=500,height=600');

// 2. Check authentication status
const response = await fetch('/mcp/auth/status');
const status = await response.json();

if (status.authenticated) {
  // 3. Use MCP with authentication
  const mcpResponse = await fetch('/mcp', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'mcp-session-id': status.session_id
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      method: 'tools/list',
      id: 1
    })
  });
}
```

### Programmatic Token Usage

```elixir
# Generate token for API access
token = AshAi.Mcp.Auth.generate_token(user)

# Use token in requests
conn = put_req_header(conn, "authorization", "Bearer #{token}")
```

## Advanced Features

### Multi-Provider Support

```elixir
# Support multiple OAuth providers
auth_strategies: [:github, :google, :microsoft]
```

### Custom User Creation

```elixir
# Override user creation logic
defp create_or_update_user(user_info, strategy, opts) do
  case MyApp.Accounts.find_or_create_user(user_info) do
    {:ok, user} -> {:ok, user}
    {:error, reason} -> {:error, reason}
  end
end
```

### Tenant-Aware Authentication

```elixir
# Multi-tenant authentication
%{
  actor: user,
  tenant: determine_tenant(user, oauth_info),
  context: %{...}
}
```

## Testing

### Mock OAuth Provider

```elixir
# Test configuration
config :my_app, :oauth_mock, true

# Mock responses
defmodule MockOAuthProvider do
  def get_user_info(_token) do
    {:ok, %{
      id: "test_user",
      email: "test@example.com",
      name: "Test User"
    }}
  end
end
```

### Integration Tests

```elixir
defmodule MyApp.McpAuthTest do
  use MyAppWeb.ConnCase

  test "OAuth flow creates MCP session" do
    # Simulate OAuth callback
    conn = get(conn, "/mcp/auth/github/callback", %{
      code: "test_code",
      state: "test_state"
    })

    assert redirected_to(conn) == "/mcp/auth/success"
    assert get_session(conn, :mcp_session_id)
  end

  test "authenticated MCP requests include user context" do
    user = create_user()
    conn = authenticate_user(conn, user)

    response = post(conn, "/mcp", %{
      jsonrpc: "2.0",
      method: "tools/list",
      id: 1
    })

    # Verify user context is passed to MCP operations
    assert response.status == 200
  end
end
```

## Production Considerations

### Performance

- ETS-based session storage for fast lookups
- Cached OAuth strategy configurations
- Efficient token validation

### Monitoring

- OAuth flow success/failure metrics
- Authentication attempt logging
- Session lifecycle tracking

### Scaling

- Stateless token-based authentication option
- Distributed session storage support
- Load balancer session affinity

This OAuth integration provides enterprise-grade authentication for MCP servers while maintaining the simplicity and flexibility of the AshAi ecosystem.