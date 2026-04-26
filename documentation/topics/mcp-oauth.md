<!--
SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>

SPDX-License-Identifier: MIT
-->

# OAuth 2.1 for the MCP server

ash_ai's MCP server can authenticate end-users via OAuth 2.1, making it directly compatible
with **ChatGPT Apps SDK** custom connectors and **Claude.ai** custom MCP connectors. A user
pastes your server URL into ChatGPT/Claude, signs in via their browser, and the client
performs the full OAuth 2.1 + PKCE + Dynamic Client Registration flow against your app.

This guide covers the production OAuth setup. If you only need machine-to-machine auth, the
existing `AshAuthentication.Strategy.ApiKey.Plug` integration is simpler — see the README.

## Architecture

ash_ai plays both OAuth roles in a single process:

- **Resource Server (RS)** — your `/mcp` endpoint validates bearer tokens.
- **Authorization Server (AS)** — your app issues tokens via `/oauth/authorize`, `/oauth/token`,
  `/oauth/register`, plus `.well-known` metadata endpoints.

The two roles share an HS256 signing secret. Tokens are RFC 8707-bound to the canonical MCP URL,
so they cannot be replayed against other resource servers.

## Prerequisites

1. AshAuthentication is installed (`mix igniter.install ash_authentication`).
2. You have a `User` resource managed by AshAuthentication.
3. `:plug` and `:phoenix_html` deps are reachable (both are optional in ash_ai but required for
   the OAuth surface).

## Step 1 — Create the four OAuth resources

ash_ai expects four Ash resources in your app. The simplest path is to copy the structure of
the test fixtures in `test/support/oauth_*_resource.ex` into your accounts domain. Each resource
uses your app's data layer (`AshPostgres.DataLayer` for production):

- `MyApp.Accounts.OAuthClient` — registered OAuth clients
- `MyApp.Accounts.OAuthAuthorizationCode` — short-lived authorization codes
- `MyApp.Accounts.OAuthRefreshToken` — refresh tokens (sha256-hashed)
- `MyApp.Accounts.OAuthConsent` — per-user, per-client consent records

The key actions each resource must support are summarised in `docs/superpowers/specs/2026-04-23-oauth21-mcp-design.md` §5.

Generate Postgres migrations once the resources are in place:

```sh
mix ash_postgres.generate_migrations --name add_oauth_resources
mix ash.migrate
```

> A `mix ash_ai.gen.oauth` task that scaffolds these resources is planned. Until it ships,
> see the test fixtures as a reference.

## Step 2 — Configure ash_ai's OAuth layer

Add the following block to `config/runtime.exs`:

```elixir
config :my_app, AshAi.Oauth,
  user_resource: MyApp.Accounts.User,
  issuer_url: System.fetch_env!("ISSUER_URL"),                   # e.g. "https://app.example.com"
  canonical_mcp_url: System.fetch_env!("MCP_CANONICAL_URL"),     # e.g. "https://app.example.com/mcp"
  signing_secret: System.fetch_env!("MCP_SIGNING_SECRET"),       # 32+ random bytes, base64 or hex
  # ...or pass a {Module, opts} tuple where Module implements AshAuthentication.Secret
  client_resource: MyApp.Accounts.OAuthClient,
  authorization_code_resource: MyApp.Accounts.OAuthAuthorizationCode,
  refresh_token_resource: MyApp.Accounts.OAuthRefreshToken,
  consent_resource: MyApp.Accounts.OAuthConsent,
  access_token_ttl: {1, :hour},
  refresh_token_ttl: {30, :days},
  authorization_code_ttl: {10, :minutes},
  scopes: ["mcp"],
  sign_in_path: "/sign-in"   # AshAuthentication sign-in route; receives ?return_to=...
```

`canonical_mcp_url` is the audience the resource server will validate on every bearer token.
It must match exactly the URL that ChatGPT/Claude is told the MCP server lives at — including
scheme, host, port, and path.

## Step 3 — Wire up the router

```elixir
# lib/my_app_web/router.ex
defmodule MyAppWeb.Router do
  use MyAppWeb, :router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :protect_from_forgery
    plug :put_secure_browser_headers
    plug :load_from_session  # AshAuthentication
  end

  pipeline :mcp do
    plug AshAi.Mcp.BearerPlug,
      otp_app: :my_app,
      required?: true
  end

  # OAuth + well-known metadata at app root
  scope "/" do
    pipe_through :browser
    forward "/", AshAi.Oauth.Router, otp_app: :my_app
  end

  # Existing MCP transport, now bearer-protected
  scope "/mcp" do
    pipe_through :mcp

    forward "/", AshAi.Mcp.Router,
      otp_app: :my_app,
      tools: [...your tool list...]
  end
end
```

`AshAi.Oauth.Router` only matches the paths it owns (`/oauth/*` and `/.well-known/oauth-*`)
and passes everything else through, so mounting it at `/` is safe.

## Step 4 — Optional: add the boot validator

```elixir
# lib/my_app/application.ex
def start(_type, _args) do
  children = [
    ...,
    {AshAi.Oauth.Startup, otp_app: :my_app}
  ]
  ...
end
```

This raises on startup if any required `AshAi.Oauth` config key is missing or any referenced
resource module fails to compile, which catches typos before the first request.

## Step 5 — Verify with curl

```sh
# 1. Should 401 with WWW-Authenticate
curl -i https://app.example.com/mcp -X POST -d '{}'

# 2. Should return RFC 9728 metadata
curl https://app.example.com/.well-known/oauth-protected-resource | jq

# 3. Should return RFC 8414 metadata
curl https://app.example.com/.well-known/oauth-authorization-server | jq

# 4. Should register a fresh client
curl https://app.example.com/oauth/register \
  -H "content-type: application/json" \
  -d '{"client_name":"test","redirect_uris":["http://localhost:9999/cb"],"token_endpoint_auth_method":"none"}'
```

For end-to-end testing, point [tidewave's mcp-proxy-rust](https://github.com/tidewave-ai/mcp_proxy_rust)
at your server and connect from a local MCP client.

## Step 6 — Connect from ChatGPT or Claude

### ChatGPT (Apps SDK / Custom Connectors)

1. Settings → Connectors → Add custom connector.
2. Paste your MCP URL (e.g. `https://app.example.com/mcp`).
3. ChatGPT performs DCR + PKCE, opens your browser to `/oauth/authorize`, you sign in and
   approve, the connector activates.

### Claude.ai (Custom Connectors)

Same flow as ChatGPT — same MCP URL, same OAuth dance, same consent screen.

## Troubleshooting

**The connector says "audience mismatch" or "invalid token".**
The token's `aud` claim doesn't match `canonical_mcp_url`. This usually means the URL the
client used to reach you doesn't match the configured canonical URL — check trailing slashes,
http vs https, and any reverse-proxy header rewriting.

**ChatGPT is stuck at "OAuth client registration failed".**
Some ChatGPT builds expect a `client_secret` even for `auth_method: "none"`. Set:
```elixir
config :my_app, AshAi.Oauth, dcr_always_return_client_secret: true
```
This returns an empty `client_secret: ""` in the DCR response; the token endpoint still
ignores any value the client presents.

**The consent page shows but submitting it loops back.**
Make sure your `:browser` pipeline runs `:protect_from_forgery` and that the `_csrf_token`
hidden input is being sent. If you've replaced `consent_template`, ensure your replacement
preserves the CSRF token field.

**The user is signed in but the consent page asks them to sign in again.**
The plug expects `Ash.PlugHelpers.get_actor(conn)` to return the user. If your app uses a
custom session loader, make sure it sets the actor on the conn (AshAuthentication's
`load_from_session` does this by default).

**Tokens silently fail at the resource server.**
Run with `:debug`-level logging and inspect `AshAi.Oauth.Jwt.verify/2`'s return value. The
specific error tells you whether it's signature, issuer, audience, or expiry.

## Relationship with AshAuthentication

ash_ai's OAuth layer is built on top of AshAuthentication, not as a replacement
for it. Concretely:

| Concern | Provider |
|---|---|
| User identity, sign-in, password reset, etc. | **AshAuthentication** (your existing User + strategies) |
| Session loading on browser-driven flows (e.g. `/oauth/authorize`) | **AshAuthentication** (`load_from_session`) |
| API-key auth on `/mcp` (simpler alternative) | **AshAuthentication.Strategy.ApiKey.Plug** |
| Signing-key resolution (`signing_secret` config) | **`AshAuthentication.Secret`** behaviour |
| OAuth 2.1 token mint/verify with audience binding | **`AshAi.Oauth.Jwt`** (purpose-built; see its module doc for why) |
| OAuth 2.1 wire flow (`/oauth/*`, RFC 9728/8414 metadata, DCR, PKCE) | **ash_ai** |
| Persisted OAuth artifacts (clients, codes, refresh tokens, consents) | **ash_ai** (Ash resources in your domain) |

The two systems share:
- The same Joken JWT library (transitive via AshAuthentication)
- The same `AshAuthentication.Secret` pattern for runtime secret resolution
- The same `Ash.PlugHelpers.set_actor`/`get_actor` convention

They do **not** share:
- A token table — `AshAuthentication.TokenResource` tracks JTIs of
  AshAuthentication's own session tokens; our `OAuthRefreshToken` stores
  hashed opaque refresh tokens (not JWTs). Future JTI revocation for
  access tokens may share TokenResource — that's a v2 decision.
- Token-issuing code — our access tokens carry an `aud` claim bound to the
  MCP canonical URL per RFC 8707, which AshAuthentication doesn't enforce.

If you have AshAuthentication wired up for sign-in already, the OAuth layer
slots in alongside without duplicating any of it.

## Security posture

See [mcp-oauth-security.md](./mcp-oauth-security.md) for the full security checklist.
