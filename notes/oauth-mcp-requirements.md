# OAuth 2.1 for AshAi MCP Apps — Requirements

Status: working document
Last updated: 2026-04-23

## 1. Goal

Let a user connect an ash_ai-powered MCP server (exposing tools + MCP Apps UI resources) to **ChatGPT Apps SDK** and **Claude.ai custom connectors**, with OAuth 2.1. The user pastes a server URL into ChatGPT/Claude, signs in via their browser, and tokens flow.

Target success criteria, end-to-end:

1. User in ChatGPT/Claude clicks **Add connector** → pastes `https://app.example.com/mcp`.
2. Client does OAuth 2.1 discovery, DCR, PKCE auth code. User sees a consent screen identifying the client (ChatGPT/Claude) and the app.
3. Access token issued with `aud = https://app.example.com/mcp`.
4. All subsequent MCP JSON-RPC calls carry `Authorization: Bearer <token>`; `actor` is set from the token's subject.
5. UI resources render in ChatGPT/Claude sandboxed iframes; widget-initiated tool calls reuse the same token.

## 2. Roles (OAuth 2.1)

| Role | Who | Lives where |
|---|---|---|
| **Resource Owner** | End user (human) | Browser |
| **Client** | ChatGPT / Claude / Codex / Cursor / etc. | External |
| **Resource Server (RS)** | The MCP server endpoint (`/mcp`) | ash_ai lib, user's Phoenix app |
| **Authorization Server (AS)** | Mints tokens, runs `/authorize`, `/token`, `/register` | **TBD — see §6** |

MCP spec 2025-06-18 cleanly separates RS and AS. The AS can be co-hosted with the RS or be entirely external.

## 3. End-to-end wire flow (the happy path)

### 3.1 Initial MCP request, unauthenticated

```
POST https://app.example.com/mcp
Content-Type: application/json
{"jsonrpc":"2.0","method":"initialize","id":1,...}
```

### 3.2 RS challenges

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://app.example.com/.well-known/oauth-protected-resource"
```

### 3.3 Client fetches Protected Resource Metadata (RFC 9728)

```
GET https://app.example.com/.well-known/oauth-protected-resource

200 OK
Content-Type: application/json
{
  "resource": "https://app.example.com/mcp",
  "authorization_servers": ["https://app.example.com"],
  "scopes_supported": ["mcp"],
  "bearer_methods_supported": ["header"],
  "resource_documentation": "https://app.example.com/docs/mcp"
}
```

Notes:
- `resource` MUST equal the canonical URI the MCP server will validate in token `aud`.
- `authorization_servers[0]` is the AS's **issuer URL** — a base URL without `.well-known`.

### 3.4 Client fetches Authorization Server Metadata (RFC 8414)

```
GET https://app.example.com/.well-known/oauth-authorization-server

200 OK
{
  "issuer": "https://app.example.com",
  "authorization_endpoint": "https://app.example.com/oauth/authorize",
  "token_endpoint": "https://app.example.com/oauth/token",
  "registration_endpoint": "https://app.example.com/oauth/register",
  "jwks_uri": "https://app.example.com/oauth/jwks",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["none", "client_secret_basic"],
  "scopes_supported": ["mcp"]
}
```

`none` in `token_endpoint_auth_methods_supported` covers PKCE public clients (ChatGPT default).

### 3.5 Dynamic Client Registration (RFC 7591)

ChatGPT and Claude both call this on every connect — you end up with many ephemeral clients. Request:

```
POST https://app.example.com/oauth/register
Content-Type: application/json
{
  "client_name": "ChatGPT",
  "redirect_uris": ["https://chatgpt.com/connector/oauth/<callback_id>"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none"
}

201 Created
{
  "client_id": "mcp_c_01HXYZ...",
  "client_id_issued_at": 1714000000,
  "redirect_uris": [...],
  "grant_types": [...],
  "token_endpoint_auth_method": "none"
}
```

No `client_secret` for `auth_method: none` (per RFC 7591 §3.2.1). **Known bug** ([OpenAI community](https://community.openai.com/t/mcp-with-oauth-dynamic-registration-chatgpt-registers-with-token-endpoint-auth-method-none-but-still-expects-a-client-secret/1366118)): some ChatGPT builds still expect one. Workaround: issue a dummy `client_secret` anyway.

### 3.6 Authorization request (PKCE + resource)

ChatGPT opens the user's browser to:

```
GET https://app.example.com/oauth/authorize
  ?response_type=code
  &client_id=mcp_c_01HXYZ...
  &redirect_uri=https://chatgpt.com/connector/oauth/<callback_id>
  &code_challenge=<base64url(sha256(verifier))>
  &code_challenge_method=S256
  &scope=mcp
  &state=<random>
  &resource=https%3A%2F%2Fapp.example.com%2Fmcp
```

Server behavior:

1. If user is not signed in → redirect to AshAuthentication sign-in, return here on success.
2. **Consent screen** (required): "Allow **ChatGPT** to access your account at **app.example.com** for scope **mcp**?"
   - MUST show client name from DCR, scopes, redirect_uri.
   - Per-client consent recorded against user (prevents confused-deputy).
3. On approve: issue authorization code, bind it to `{user_id, client_id, redirect_uri, code_challenge, scope, resource}`. Short TTL (≤ 10 min).
4. Redirect to `redirect_uri?code=<code>&state=<state>`.

### 3.7 Token exchange

```
POST https://app.example.com/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=<code>
&redirect_uri=https%3A%2F%2Fchatgpt.com%2Fconnector%2Foauth%2F<id>
&code_verifier=<verifier>
&client_id=mcp_c_01HXYZ...
&resource=https%3A%2F%2Fapp.example.com%2Fmcp
```

Server validates:
- code exists, not consumed, not expired
- `client_id` matches binding
- `redirect_uri` matches binding
- `sha256(code_verifier)` matches stored challenge
- `resource` matches binding

Response:

```
200 OK
Cache-Control: no-store
{
  "access_token": "<JWT>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "<opaque>",
  "scope": "mcp"
}
```

Access token JWT claims:

```json
{
  "iss": "https://app.example.com",
  "sub": "<ash_user_id>",
  "aud": "https://app.example.com/mcp",
  "client_id": "mcp_c_01HXYZ...",
  "scope": "mcp",
  "iat": 1714000000,
  "nbf": 1714000000,
  "exp": 1714003600,
  "jti": "<uuid>"
}
```

### 3.8 Authenticated MCP requests

```
POST https://app.example.com/mcp
Authorization: Bearer <JWT>
Content-Type: application/json
...
```

RS validation per request (OAuth 2.1 §5.2 + RFC 8707):
- Signature verify against JWKS (or HS256 with a shared secret).
- `iss == "https://app.example.com"`.
- **`aud == "https://app.example.com/mcp"`** — MUST. This is the audience binding the whole design depends on.
- `exp > now`, `nbf ≤ now`.
- `jti` not revoked.
- Optional: `scope` contains required scope for the RPC method.

Load actor: `AshAi.Accounts.User |> Ash.get!(sub, ...)`.

### 3.9 Refresh

```
POST /oauth/token
grant_type=refresh_token
&refresh_token=<opaque>
&client_id=...
&resource=https://app.example.com/mcp
```

OAuth 2.1 §4.3.1 requires **refresh token rotation** for public clients. Old refresh token revoked, new one issued.

## 4. MCP Apps-specific extras on top of base OAuth

From ChatGPT Apps SDK docs and MCP 2025-06-18:

1. **`_meta["mcp/www_authenticate"]` on tool errors**. When a tool returns `isError: true` because of missing scope, put a `WWW-Authenticate`-style value in `_meta` so the client can surface a re-auth UI. (Not all tools need this.)
2. **Per-tool `securitySchemes`**. Tools may declare what scopes they need via MCP metadata; RS still enforces. AshAi's `tool` DSL would grow a `scope` option.
3. **UI resource rendering ⊗ cookies**. The sandboxed iframe has no cookies. Any tool invocation the widget makes goes through the MCP server with the same bearer token. **Nothing new needed** on auth — this just means the MCP transport must stay bearer-auth, not cookie-auth.
4. **Sandbox domain** already computed by `AshAi.Mcp.Server.sandbox_domain/1` from `server_url`. Ensure `server_url` is derived from the RS's canonical URI so the sandbox hash stays stable across deploy hosts.
5. **mTLS from ChatGPT** (optional, but documented). ChatGPT presents OpenAI-managed client certs. Honoring these is a server-op deployment concern, not a library concern — out of scope for ash_ai.

## 5. The exhaustive endpoint list the library must surface

Grouped by role:

### Resource Server (ash_ai)

| Path | Method | Purpose | Exists today? |
|---|---|---|---|
| `/mcp` (user-mounted) | POST / GET / DELETE | Existing MCP transport | ✅ |
| `/.well-known/oauth-protected-resource` | GET | RFC 9728 metadata | ❌ |
| MCP 401 → `WWW-Authenticate` | — | Challenge header | ❌ |
| Token validation plug | — | Bearer validation, actor load | ⚠ partial (via external ApiKey today) |

### Authorization Server

| Path | Method | Purpose | Exists today? |
|---|---|---|---|
| `/.well-known/oauth-authorization-server` | GET | RFC 8414 metadata | ❌ |
| `/oauth/jwks` | GET | Public keys (if asymmetric signing) | ❌ |
| `/oauth/register` | POST | RFC 7591 DCR | ❌ |
| `/oauth/authorize` | GET | Start flow; redirect through login + consent | ❌ |
| `/oauth/authorize` (consent form POST) | POST | Record consent, issue code | ❌ |
| `/oauth/token` | POST | Code exchange + refresh | ❌ |
| `/oauth/revoke` (SHOULD) | POST | RFC 7009 | ❌ |

## 6. What AshAuthentication already provides vs what's missing

### ✅ Already in AshAuthentication

- **JWT signing/verification**: `AshAuthentication.Jwt.token_for_user/4` and `Jwt.verify/4`. Supports HS256 / RS256 / EdDSA etc. Custom claims via `extra_claims` map — we can set `aud`, `scope`, `client_id`, etc.
- **JWT secret/signer config**: `AshAuthentication.Secret` behaviour (env var, runtime.exs) — we reuse.
- **Revocation infrastructure**: `AshAuthentication.TokenResource` stores `jti`s and supports `revoke/2`, `token_revoked?/2`. Reusable for refresh tokens and revocation endpoint.
- **User resource / sign-in**: any existing password / magic link / OAuth2-client strategy. User browser session when they visit `/oauth/authorize`.
- **Request-time actor assignment**: pattern established by `AshAuthentication.Strategy.ApiKey.Plug` — we'll have an analogous `AshAi.Mcp.BearerPlug`.
- **Custom strategy behaviour**: `AshAuthentication.Strategy.Custom` with `transform/2` + `verify/2` if we want to package this as a strategy.
- **Plug integration conventions**: `load_from_bearer/2` exists and is the pattern users know.

### ❌ Missing — needs building

1. **OAuth clients as a stored entity.** No `OAuthClient` resource. Need CRUD, including ephemeral DCR clients. Likely `AshAi.Oauth.Client` Ash resource; backed by Postgres or ETS.
2. **Authorization codes storage.** Short-lived (≤10 min), one-shot. Could be ETS, Cachex, or a Postgres table with `expires_at` + cleanup oban job. Store binds `{user_id, client_id, redirect_uri, code_challenge, scope, resource}`.
3. **Refresh tokens storage.** Opaque token → `{client_id, user_id, scope, resource, expires_at}`. Use `TokenResource` with custom record type, or separate `AshAi.Oauth.RefreshToken`.
4. **Per-client per-user consent record.** `AshAi.Oauth.Consent` — binds `user_id × client_id × scopes`. Required to mitigate confused-deputy (MCP security best practices, 2025-06-18).
5. **Protected Resource Metadata plug.** Serve JSON at `/.well-known/oauth-protected-resource`. Derives `resource` from configured canonical URI.
6. **Authorization Server Metadata plug.** Serve JSON at `/.well-known/oauth-authorization-server`.
7. **DCR endpoint plug.** `POST /oauth/register` — RFC 7591.
8. **Authorize endpoint plug + consent LiveView/template.** The only view layer we need. Can be a plain HEEx render (no JS) to keep dependencies minimal. Honors pre-login (punt to AshAuthentication sign-in).
9. **Token endpoint plug.** `POST /oauth/token` — code→token and refresh→token.
10. **Revoke endpoint plug (optional).** `POST /oauth/revoke`.
11. **401 + WWW-Authenticate** wrapping of the MCP router. Currently MCP router doesn't challenge — it just assumes actor is set upstream. We need a bearer plug in front that produces proper challenges when `required?: true`.
12. **Audience validation** on bearer verification. AshAuthentication's JWT verify checks signature + standard claims but doesn't natively enforce `aud`. We'll wrap or extend.
13. **PKCE helpers.** `:crypto.hash(:sha256, verifier) |> Base.url_encode64(padding: false)` etc. — tiny, just needs to be right.
14. **JWKS endpoint** (if we go asymmetric). If HS256, skip — but **ChatGPT Apps SDK's Stytch guide assumes JWKS**. Recommend RS256/EdDSA.
15. **Canonical URI config.** Single source of truth (e.g. `config :my_app, AshAi.Mcp, canonical_url: "https://app.example.com/mcp"`). Must match token `aud`, RS metadata `resource`, and sandbox domain derivation.

## 7. Library shape — what changes in ash_ai

Conceptual module layout (names TBD):

```
AshAi.Mcp.Router                 # existing, grows bearer plug integration
AshAi.Mcp.BearerPlug             # NEW — 401+WWW-Authenticate challenge, actor load
AshAi.Mcp.Metadata.ProtectedResource   # NEW — /.well-known/oauth-protected-resource
AshAi.Oauth.Router               # NEW — mounts AS routes
AshAi.Oauth.Metadata.AuthServer  # NEW — /.well-known/oauth-authorization-server
AshAi.Oauth.Metadata.Jwks        # NEW — /oauth/jwks
AshAi.Oauth.Register             # NEW — DCR
AshAi.Oauth.Authorize            # NEW — GET + POST (consent)
AshAi.Oauth.Token                # NEW — token endpoint
AshAi.Oauth.Revoke               # NEW — optional
AshAi.Oauth.Client               # NEW — Ash resource
AshAi.Oauth.AuthorizationCode    # NEW — Ash resource (short-lived)
AshAi.Oauth.RefreshToken         # NEW — Ash resource (or via TokenResource)
AshAi.Oauth.Consent              # NEW — Ash resource
AshAi.Oauth.ConsentView          # NEW — HEEx render
```

Dependency question: does the `AshAi.Oauth.*` tree live in ash_ai or as a sibling (`ash_oauth2_provider`)? Argue for either:

- **In ash_ai**: easiest install for users, tightly coupled to the MCP use case, no version drift.
- **Sibling library**: clean separation, reusable beyond MCP, can grow scopes/admin UI later. ash_ai depends on it optionally.

## 8. Config surface the user sees

```elixir
# config/runtime.exs
config :my_app, AshAi.Mcp,
  canonical_url: System.fetch_env!("MCP_CANONICAL_URL"),  # https://app.example.com/mcp
  issuer_url:    System.fetch_env!("MCP_ISSUER_URL"),     # https://app.example.com
  signing_key:   {AshAi.Oauth.Secret, []},                # or raw PEM for RS256

# lib/my_app_web/router.ex
scope "/" do
  pipe_through :browser
  forward "/oauth", AshAi.Oauth.Router, otp_app: :my_app
  get "/.well-known/oauth-protected-resource", AshAi.Mcp.Metadata.ProtectedResource, []
  get "/.well-known/oauth-authorization-server", AshAi.Oauth.Metadata.AuthServer, []
end

pipeline :mcp do
  plug AshAi.Mcp.BearerPlug,
    required?: true,
    resource: MyApp.Accounts.User
end

scope "/mcp" do
  pipe_through :mcp
  forward "/", AshAi.Mcp.Router, tools: [...], otp_app: :my_app
end
```

## 9. Open decisions (need your input before design finalization)

1. **Live in ash_ai or sibling lib?** (see §7)
2. **Signing algorithm: HS256 (simple) or RS256/EdDSA (JWKS-friendly, recommended by Stytch for ChatGPT)?**
3. **Persistence backend: require Postgres or provide ETS/Cachex fallback?** Postgres gives durability across restarts (matters for refresh tokens and ephemeral DCR clients). But many small apps won't want another Ash resource set.
4. **Client cleanup policy:** ChatGPT/Claude DCR on every connect → client table grows. TTL on unused clients? Oban cleanup job? Ignore for v1?
5. **Consent UX:** Phoenix LiveView (if AshAuthenticationPhoenix is loaded) or plain controller + HEEx? Plain is fewer deps.
6. **Refresh token rotation in v1 or v2?** Spec says SHOULD; real-world clients break without it over long connections. Probably v1.
7. **Scopes beyond `mcp`?** v1: single `mcp` scope covering everything. v2: per-tool `mcp:tool:<name>` and per-resource scopes.
8. **"Ship the AS" vs "document external AS"?** Given ChatGPT requires DCR and most IdPs don't do DCR well, I think ship-the-AS is the only realistic choice. Confirm.
9. **Backwards compat:** keep the existing "api-key via ApiKey.Plug" option working? (Yes — it's the easy path.)

## 10. Risk & complexity flags

- **Consent screen gets it wrong** → confused-deputy attack. Must be per-client, not per-third-party-AS.
- **Audience validation drift** — canonical URL must match in three places (token mint, RS validation, metadata response). One config var that all three read from.
- **Public-client DCR flood** (see Claude/ChatGPT pattern) — storage blows up if unbounded.
- **Refresh rotation races** — concurrent refresh from the same client must be serialized or versioned.
- **Spec version variance** — we target 2025-06-18; ChatGPT and Claude may still exercise 2025-03-26 fallbacks (`protocol_version_statement` already handles this in [router](lib/ash_ai/mcp/router.ex)).
- **ChatGPT `client_secret` bug** — known issue where `token_endpoint_auth_method: none` clients still expect `client_secret` back. Workaround: always return a value.
- **JWKS rotation** — if we go asymmetric, key rollover must be supported (publish both kids for a window).

## 11. What we are explicitly NOT doing (v1)

- Client credentials grant (agent-to-agent, no human).
- Device code grant.
- mTLS auth for clients.
- `resource_indicator` enforcement beyond the `resource` parameter in the auth/token endpoints.
- Fine-grained per-tool scope elevation (`WWW-Authenticate: scope=...` challenges).
- Admin UI for viewing/revoking clients/tokens.
- Token introspection endpoint (RFC 7662).
- DPoP sender-constrained tokens.
- Signed metadata (RFC 8414 `signed_metadata`).

## 12. Next step

Pick the approach + resolve §9 decisions, then write the formal design doc.
