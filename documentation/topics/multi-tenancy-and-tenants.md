<!--
SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>

SPDX-License-Identifier: MIT
-->

# Multi-tenancy and tenants

If your domains use Ash [multitenancy](https://hexdocs.pm/ash/multitenancy.html), every Ash call must run with the correct **tenant** (and usually **actor**). AshAi participates in those calls when it runs tools, reads data, or executes prompt-backed actions—so **you** need to supply tenant (or a full **scope**) the same way you would elsewhere in your application.

This guide describes how **ash_ai threads tenant** through the main APIs. For **how tenants are modeled** (attribute vs context strategies, Postgres row-level isolation, etc.), follow the Ash and data-layer guides for your stack.

---

## Tool loop (`AshAi.ToolLoop.run/2`, `AshAi.ToolLoop.stream/2`)

The tool loop accepts the same **`tenant:`** option as other validated `AshAi` options (alongside `:actor`, `:otp_app`, and so on). That tenant is forwarded into tool execution so reads, writes, and generic actions use it consistently.

**Example:**

```elixir
AshAi.ToolLoop.stream(messages,
  otp_app: :my_app,
  tools: true,
  actor: current_user,
  tenant: current_tenant
)
```

If you omit `:tenant`, tool calls behave like any other Ash call without a tenant—as allowed or required by each resource.

`AshAi.ToolLoop.run/2` takes the same options.

Callbacks such as `on_tool_start` receive an `AshAi.ToolStartEvent` that includes `:tenant`, which is useful for logging or tying tool runs back to your request context.

---

## MCP server

When using the MCP HTTP server, `AshAi.Mcp.Server` derives options from the connection:

```elixir
tenant: Ash.PlugHelpers.get_tenant(conn)
```

Your plugs must set the tenant on the connection the same way you would for other Ash-aware Phoenix endpoints (AshAuthentication, custom session resolver, subdomain parsing, headers, etc.). See `Ash.PlugHelpers` documentation for the helpers your app uses to store actor, tenant, and Ash context on `conn`.

If no tenant appears on tools, trace whether `get_tenant/1` returns `nil` for that route—that usually means plugs or assigns are incomplete, not that AshAi is “dropping” the tenant.

---

## Prompt-backed actions (`run prompt(...)`)

Prompt-backed actions run an inner tool loop. The loop’s `FlowState` is built with tenant taken from the action invocation context (the same broader context pattern Ash uses alongside `:actor`).

**Practically:** invoke the prompt action with the same tenant and execution context you already use for other multitenant actions in your domains. Prefer Ash’s **action input** and **execution-scope** conventions for your Ash version (see Ash docs) rather than reinventing helpers.

---

## Generated chat (`mix ash_ai.gen.chat`)

The generated responders pass `tenant:` through to `AshAi.ToolLoop.stream`, and they use `scope: context` on reads where the codegen templates expect an Ash change/request context. In other words:

- Ensure the context you pass around in generated code carries your tenant requirements. The codegen passes **`scope: context`** into **`Ash.read!`**—that **`context`** is your Ash change/request context; populate **`tenant`** and **`actor`** on it the same way as in the rest of your multitenant app (see [multitenancy](https://hexdocs.pm/ash/multitenancy.html)).
- If something reads “the wrong tenant” or no tenant after generation, inspect how context is populated in LiveView/controllers and align it with Ash’s multitenant docs—AshAi forwards what you supply.

For LiveView/chat, multitenancy is the same **`tenant:`**, **`PlugHelpers`**, and **`scope`/context** story as throughout this guide—the supported tool loop APIs are **`AshAi.ToolLoop.run/2`** and **`AshAi.ToolLoop.stream/2`** (validated via **`AshAi.Options`**); the LangChain-era helper **`AshAi.setup_ash_ai/2`** was removed. See [LangChain to ReqLLM migration](langchain-to-reqllm-migration.md).

Typical plumbing in a multitenant Phoenix app:

- Set **tenant** and **actor** on **`conn`** with **`Ash.PlugHelpers`** (or your stack’s equivalent) so HTTP-driven flows match the rest of the app.
- Expose the current tenant on **`socket.assigns`** (or build an **`Ash.Scope`**) and pass **`tenant:`** anywhere you pass **`actor:`**—including **`AshPhoenix.Form`** helpers and Ash interface calls. **`mix ash_ai.gen.chat`** templates **often** show **`actor:`** only by default; multitenant apps usually add **`tenant:`** to those generated calls and to any custom reads/writes beside them.
