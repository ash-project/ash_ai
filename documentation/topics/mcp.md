# MCP

AshAi provides a pre-built MCP server that can be used to expose your
tool definitions to an MCP client (typically some kind of IDE, or Claude Desktop for example).

The protocol version we implement is 2025-03-26. As of this writing, many tools have not yet been updated to support this version. You will generally need to use some kind of proxy until tools have been updated accordingly. The only proxy that is known to support the latest protocol verison is https://www.npmjs.com/package/mcp-remote.

However, there is a bug that requires us to "claim" that we are using an old protocol version: https://github.com/geelen/mcp-remote/issues/66. See the installation snippet below for more.

## Installation

### Authentication

We don't currently support the OAuth2 flow out of the box with AshAi, but the goal is to eventually support this with AshAuthentication. You can always implement that yourself, but the quikest way to value is to use the new `api_key` strategy.

Use `mix ash_authentication.add_strategy api_key` to install it if you haven't already.

Then, create a separate pipeline for `:mcp`, and add the api key plug to it:

```elixir
pipeline :mcp do
  plug AshAuthentication.Strategy.ApiKey.Plug,
    resource: YourApp.Accounts.User,
    # Use `required?: false` to allow unauthenticated
    # users to connect, for example if some tools
    # are publicly accessible.
    required?: false
end
```

### Add the MCP server to your router

```elixir
scope "/mcp" do
  pipe_through :api_key

  forward "/", AshAi.Mcp.Router,
    tools: [
      :list,
      :of,
      :tools
    ],
    # If using mcp-remote, and this issue is not fixed yet: https://github.com/geelen/mcp-remote/issues/66
    # You will need to set the `protocol_version_statement` to the
    # older version.
    protocol_version_statement: "2024-11-05",
    otp_app: :shirabe
end
```
