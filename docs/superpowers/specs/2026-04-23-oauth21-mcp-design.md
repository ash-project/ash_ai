# OAuth 2.1 for AshAi MCP — Design

Status: proposed
Date: 2026-04-23
Related: [requirements](../../../notes/oauth-mcp-requirements.md)

## 1. Goal

Let a user connect an ash_ai-powered MCP server (tools + MCP Apps UI resources) to **ChatGPT Apps SDK** and **Claude.ai custom connectors** via OAuth 2.1, out of the box. Paste URL → browser sign-in → connected.

## 2. Non-goals (v1)

- Client credentials grant (agent-to-agent), device code grant, mTLS, DPoP.
- Fine-grained per-tool scopes.
- Token introspection endpoint (RFC 7662).
- Admin UI for managing clients/tokens.
- Signed metadata (RFC 8414 `signed_metadata`).
- Extraction into a sibling library (deferred — design makes it a file move).

## 3. Architecture

ash_ai plays both OAuth 2.1 roles, co-hosted in the user's Phoenix app:

- **Resource Server (RS)** — the existing MCP transport (`AshAi.Mcp.Router`) with a new bearer-validating plug and a protected-resource metadata endpoint in front.
- **Authorization Server (AS)** — new `AshAi.Oauth` subtree with six HTTP endpoints + four Ash resources + a consent view.

AS and RS share a single HS256 signing secret (resolved via `AshAuthentication.Secret`), so the RS verifies tokens minted by the AS without JWKS. The design leaves an obvious upgrade path to RS256 + JWKS for extraction.

```
┌────────────── User's Phoenix app ───────────────┐
│                                                 │
│  /.well-known/oauth-protected-resource  ◄── RS  │
│  /.well-known/oauth-authorization-server◄── AS  │
│  /oauth/register  (DCR)                 ◄── AS  │
│  /oauth/authorize (GET + POST consent)  ◄── AS  │
│  /oauth/token                           ◄── AS  │
│  /oauth/revoke                          ◄── AS  │
│  /mcp  (existing, + new BearerPlug)     ◄── RS  │
│                                                 │
└─────────────────────────────────────────────────┘
```

## 4. User-facing API

### 4.1 Configuration — plain application config

OAuth server config is singleton and app-wide, so it lives in `config/runtime.exs`, not on a per-domain DSL. This matches the dominant Elixir-ecosystem pattern (`ex_oauth2_provider`, Guardian). The existing `tools do` and `mcp_resources do` DSLs stay on domains — they describe domain-scoped exposure to MCP, which OAuth server identity is not.

```elixir
# config/runtime.exs
config :my_app, AshAi.Oauth,
  # Required
  user_resource: MyApp.Accounts.User,
  issuer_url: System.fetch_env!("ISSUER_URL"),            # "https://app.example.com"
  canonical_mcp_url: System.fetch_env!("MCP_URL"),        # "https://app.example.com/mcp"
  signing_secret: {AshAi.Oauth.Secret, []},               # AshAuthentication.Secret module

  # Generated resources (defaults are inferred from user_resource's domain)
  client_resource: MyApp.Accounts.OAuthClient,
  authorization_code_resource: MyApp.Accounts.OAuthAuthorizationCode,
  refresh_token_resource: MyApp.Accounts.OAuthRefreshToken,
  consent_resource: MyApp.Accounts.OAuthConsent,

  # Tunables with defaults
  access_token_ttl: {1, :hour},
  refresh_token_ttl: {30, :days},
  authorization_code_ttl: {10, :minutes},
  scopes: ["mcp"],
  consent_template: AshAi.Oauth.ConsentView,              # override for custom HEEx
  dcr_always_return_client_secret: false                  # ChatGPT compat toggle (see §6.4)
```

At boot, `AshAi.Oauth.Application` validates required keys are present and all referenced modules compile; missing config raises a clear error.

The `consent_template` module exports `render(:consent, assigns)` returning a `Phoenix.HTML.Safe` value. `AshAi.Oauth.ConsentView` ships as the default.

A generator (`mix ash_ai.gen.oauth`) creates the four Ash resources in the user's app with their chosen data_layer (defaulting to whatever their `user_resource` uses — typically `ash_postgres`) and writes the `config/runtime.exs` block above with sensible defaults.

### 4.2 Router integration

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
    # existing AshAuthentication session loader
    plug :load_from_session
  end

  pipeline :mcp do
    plug AshAi.Mcp.BearerPlug,
      otp_app: :my_app,
      required?: true
  end

  # One-line mount for all OAuth + metadata endpoints
  scope "/" do
    pipe_through :browser
    forward "/", AshAi.Oauth.Router, otp_app: :my_app
  end

  scope "/mcp" do
    pipe_through :mcp
    forward "/", AshAi.Mcp.Router,
      otp_app: :my_app,
      tools: [...]
  end
end
```

`AshAi.Oauth.Router` routes only the paths it owns (`/.well-known/oauth-*`, `/oauth/*`) and passes everything else through, so mounting at `/` is safe. All plugs take `otp_app:` and read config via `Application.get_env(otp_app, AshAi.Oauth)`.

### 4.3 Back-compat

The existing `AshAuthentication.Strategy.ApiKey.Plug` flow keeps working untouched. A user can pipe `BearerPlug` *and* `ApiKey.Plug` — `required?: false` on both means either can authenticate. BearerPlug is purely additive.

## 5. Data model — four Ash resources

Generated into the user's domain by `mix ash_ai.gen.oauth`. Attributes shown at the logical level; data_layer is user's choice.

### 5.1 OAuthClient

| Attribute | Type | Notes |
|---|---|---|
| `id` (PK) | UUIDv7 | also the OAuth `client_id` |
| `client_name` | string | from DCR metadata |
| `redirect_uris` | `{:array, :string}` | exact-match validated |
| `grant_types` | `{:array, :string}` | subset of `["authorization_code", "refresh_token"]` |
| `token_endpoint_auth_method` | string | `"none"` (PKCE public) or `"client_secret_basic"` |
| `client_secret_hash` | string (nullable) | bcrypt — only for confidential |
| `scope` | string | space-separated |
| `last_used_at` | utc_datetime_usec | for cleanup |
| `created_at` / `updated_at` | timestamps | |

Actions: `register` (create), `get_by_id`, `touch` (update last_used), `destroy`.

### 5.2 OAuthAuthorizationCode

Short-lived (≤10 min). One-shot consumption.

| Attribute | Type | Notes |
|---|---|---|
| `id` (PK) | UUIDv7 | the `code` value |
| `client_id` | UUIDv7 | belongs_to OAuthClient |
| `user_id` | UUIDv7 | belongs_to user_resource |
| `redirect_uri` | string | exact value used in /authorize |
| `code_challenge` | string | PKCE S256 |
| `scope` | string | granted scope |
| `resource` | string | canonical MCP URI, bound to future token `aud` |
| `expires_at` | utc_datetime_usec | |
| `consumed_at` | utc_datetime_usec (nullable) | replay detection |

Actions: `create`, `consume` (atomic claim), `destroy_expired`.

### 5.3 OAuthRefreshToken

The client-facing refresh token is 32 random bytes encoded via `Base.url_encode64(..., padding: false)`. We persist only the sha256 hash; lookup is by hash.

| Attribute | Type | Notes |
|---|---|---|
| `id` (PK) | UUIDv7 | |
| `token_hash` | string | `Base.encode16(:crypto.hash(:sha256, raw_token), case: :lower)` |
| `client_id` | UUIDv7 | belongs_to OAuthClient |
| `user_id` | UUIDv7 | belongs_to user_resource |
| `scope` | string | |
| `resource` | string | |
| `expires_at` | utc_datetime_usec | |
| `rotated_to_id` | UUIDv7 (nullable) | on rotation, points at new row |
| `revoked_at` | utc_datetime_usec (nullable) | |

Actions: `issue`, `rotate` (mark rotated, issue new), `revoke`, `destroy_expired`.

### 5.4 OAuthConsent

Per-user per-client consent record. **Critical**: mitigates confused-deputy.

| Attribute | Type | Notes |
|---|---|---|
| `id` (PK) | UUIDv7 | |
| `user_id` | UUIDv7 | belongs_to user_resource |
| `client_id` | UUIDv7 | belongs_to OAuthClient |
| `scope` | string | consented scope (superset of what AS issues) |
| `granted_at` | utc_datetime_usec | |

Unique on `(user_id, client_id)`. Actions: `grant`, `revoke`, `get_for`.

## 6. Wire flow — authoritative reference

All endpoints use the shared signing secret via `AshAuthentication.Jwt`. All state changes go through Ash actions so policies apply.

### 6.1 Challenge (RS side)

`AshAi.Mcp.BearerPlug`. Error behavior:

- `401` with `WWW-Authenticate: Bearer resource_metadata="..."` — no token, bad signature, wrong issuer, expired, revoked, audience mismatch.
- `403` — token valid but scope insufficient for the requested operation (future use when per-tool scopes land; in v1 always `401` paths).

```
receive conn
  read Authorization: Bearer <jwt>
  if missing and required?:
    halt 401
    WWW-Authenticate: Bearer resource_metadata="<issuer>/.well-known/oauth-protected-resource"
  if present:
    verify signature (HS256, shared secret) via AshAuthentication.Jwt.verify/2
    check iss == configured_issuer
    check aud matches configured_canonical_mcp_url   # string, or array containing it (RFC 8707)
    check exp > now, nbf ≤ now (already done by verify)
    check jti not revoked via AshAuthentication.TokenResource
    load user: Ash.get(user_resource, claims["sub"], authorize?: false)
    Ash.PlugHelpers.set_actor(conn, user)
    assign conn :oauth_claims, %{scope: ..., client_id: ..., jti: ...}
```

### 6.2 Protected Resource Metadata

`GET /.well-known/oauth-protected-resource`

```json
{
  "resource": "<canonical_mcp_url>",
  "authorization_servers": ["<issuer_url>"],
  "scopes_supported": ["mcp"],
  "bearer_methods_supported": ["header"]
}
```

### 6.3 Authorization Server Metadata

`GET /.well-known/oauth-authorization-server`

```json
{
  "issuer": "<issuer_url>",
  "authorization_endpoint": "<issuer_url>/oauth/authorize",
  "token_endpoint": "<issuer_url>/oauth/token",
  "registration_endpoint": "<issuer_url>/oauth/register",
  "revocation_endpoint": "<issuer_url>/oauth/revoke",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["none", "client_secret_basic"],
  "scopes_supported": ["mcp"]
}
```

### 6.4 DCR — `POST /oauth/register`

1. Parse JSON body (RFC 7591 fields).
2. Validate `redirect_uris` non-empty, all `https://` or `http://localhost*`.
3. Default `grant_types` to `["authorization_code"]`, `response_types` to `["code"]`, `token_endpoint_auth_method` to `"none"`.
4. Reject any `grant_types` outside `["authorization_code", "refresh_token"]`.
5. `OAuthClient.register/1` → generate id.
6. For `token_endpoint_auth_method: "none"`: return no `client_secret` (but see workaround below).
7. Respond `201` with full echo-back.

**ChatGPT `client_secret` workaround** (config-gated): per [OpenAI community bug](https://community.openai.com/t/mcp-with-oauth-dynamic-registration-chatgpt-registers-with-token-endpoint-auth-method-none-but-still-expects-a-client-secret/1366118), some ChatGPT builds misbehave when `client_secret` is omitted for `auth_method: none`. Add a config option `dcr_always_return_client_secret: true` (default `false`) that returns a dummy `client_secret: ""` in the response. `/token` endpoint ignores any secret presented by an `auth_method: none` client regardless. Document the flag as a "turn on if ChatGPT is misbehaving" toggle.

### 6.5 Authorize (GET) — `GET /oauth/authorize`

Query: `response_type=code`, `client_id`, `redirect_uri`, `code_challenge`, `code_challenge_method=S256`, `scope`, `state`, `resource`.

1. Validate parameters. Fail fast with `400` for malformed requests. For `redirect_uri` violations, **do not redirect** — render an HTML error.
2. Load client by `client_id`. Verify `redirect_uri` exact-match against registered list.
3. Verify `code_challenge_method == "S256"` (reject "plain").
4. Verify `resource` matches `canonical_mcp_url` after both are normalized (lowercase scheme + host, no trailing slash, no fragment).
5. If user not signed in (no actor on conn) → store full query as `:oauth_redirect_after_login` in session, redirect to `AshAuthentication`'s sign-in route. On success, user returns here.
6. Load existing `OAuthConsent` for `(user, client)`. If present and covers the requested scope: skip to step 8.
7. Render consent HEEx page:
   - Client name (from `OAuthClient.client_name`)
   - Scope description(s)
   - Redirect URI to be used
   - CSRF token
   - Approve / Deny buttons (POST to the same path)
8. On approve: create `OAuthAuthorizationCode`, create or update `OAuthConsent`, `302` to `redirect_uri?code=<code>&state=<state>`.
9. On deny: `302` to `redirect_uri?error=access_denied&state=<state>`.

### 6.6 Authorize (POST consent) — `POST /oauth/authorize`

Body: CSRF token + authorization params + `action=approve|deny`. Same logic as steps 8–9 above.

### 6.7 Token — `POST /oauth/token`

Content-Type: `application/x-www-form-urlencoded`. Cache-Control: `no-store` on every response.

#### `grant_type=authorization_code`

1. Read `code`, `redirect_uri`, `code_verifier`, `client_id`, `resource`.
2. `OAuthClient` lookup + auth:
   - `auth_method: none` → no secret check.
   - `auth_method: client_secret_basic` → verify `Authorization: Basic` header against `client_secret_hash`.
3. `OAuthAuthorizationCode.consume/1` — atomic update setting `consumed_at`; fails if already consumed, expired, or not found.
4. Verify bindings: `client_id`, `redirect_uri`, `resource` all match row.
5. Verify PKCE: compute `expected = Base.url_encode64(:crypto.hash(:sha256, code_verifier), padding: false)` then `Plug.Crypto.secure_compare(expected, code.code_challenge)`.
6. Mint access token via `AshAuthentication.Jwt.token_for_user/4` with `extra_claims`:
   - `iss`, `sub` (user.id), `aud` (resource), `client_id`, `scope`, `iat`, `nbf`, `exp`, `jti`.
7. Issue refresh token: generate 32 random bytes, store `sha256` hash, TTL from config.
8. Respond:
   ```json
   {"access_token":"<jwt>","token_type":"Bearer","expires_in":3600,"refresh_token":"<opaque>","scope":"mcp"}
   ```

#### `grant_type=refresh_token`

1. Lookup `OAuthRefreshToken` by `sha256(refresh_token)`.
2. Verify not expired, not revoked, not already rotated.
3. Verify `client_id` and `resource` params match row.
4. **Rotate**: mark row `rotated_to_id = new_id`, create new refresh token, mint new access token.
5. Respond same shape.

Concurrency: `OAuthRefreshToken.rotate/1` uses `atomic` update on `rotated_to_id == nil` condition. Second rotation attempt from a stolen token hits a revoked branch and we revoke the whole chain (OAuth 2.1 §6.1 — reuse detection).

### 6.8 Revoke — `POST /oauth/revoke`

RFC 7009. Body: `token`, optional `token_type_hint`.

1. Try refresh-token hash lookup; if found, `revoke/1` the whole chain.
2. Else try JTI lookup on access tokens (via `AshAuthentication.TokenResource.revoke/2`).
3. Always respond `200`.

## 7. Module layout

Designed so extraction to `ash_oauth2_provider` is a git mv.

```
lib/ash_ai/
├── mcp/
│   ├── router.ex              # existing
│   ├── server.ex              # existing
│   ├── dev.ex                 # existing
│   ├── bearer_plug.ex         # NEW
│   └── metadata/
│       └── protected_resource.ex  # NEW
└── oauth/                     # NEW — future extraction candidate
    ├── router.ex              # mounts the subtree
    ├── metadata/
    │   └── auth_server.ex
    ├── register.ex            # Plug
    ├── authorize.ex           # Plug
    ├── token.ex               # Plug
    ├── revoke.ex              # Plug
    ├── pkce.ex                # S256 helpers
    ├── secret.ex              # AshAuthentication.Secret impl for default secret
    ├── consent_view.ex        # HEEx template module
    ├── config.ex              # thin wrapper over Application.get_env/2
    └── startup.ex             # boot-time config validator (child_spec)
```

## 8. Config read path

Single source of truth: `config :my_app, AshAi.Oauth, ...` in `runtime.exs`. Read at request time via a thin wrapper:

```elixir
# AshAi.Oauth.Config — thin wrapper over Application.get_env/2
AshAi.Oauth.Config.user_resource(otp_app)        # => MyApp.Accounts.User
AshAi.Oauth.Config.issuer_url(otp_app)           # => "https://app.example.com"
AshAi.Oauth.Config.canonical_mcp_url(otp_app)    # => "https://app.example.com/mcp"
AshAi.Oauth.Config.signing_secret(otp_app)       # => resolves AshAuthentication.Secret
AshAi.Oauth.Config.access_token_ttl(otp_app)     # => 3600 (normalized to seconds)
# ...
```

Every plug receives `otp_app:` in its opts. Config read is a map lookup — cheap, no process state. Tests override via `Application.put_env/3` inside setup blocks.

Validation at boot via `AshAi.Oauth.Application` (or a `{:ok, ...}` return from a child start function in the user's supervision tree):

```elixir
# in user's lib/my_app/application.ex, as a child
AshAi.Oauth.Startup.child_spec(otp_app: :my_app)
```

This verifies required keys present, resources compile, URLs parse, secret resolves — and raises with a clear message pointing at the missing/bad key.

## 9. Security checklist (MCP Best Practices)

Each item is a test case in §10.

- ✅ **PKCE S256 enforced** — `/authorize` rejects `plain`.
- ✅ **Audience binding** — token `aud` (string, or array containing the value) MUST match `canonical_mcp_url` exactly; RS rejects mismatched tokens. We mint tokens with `aud` as a string for simplicity.
- ✅ **No token passthrough** — RS never forwards the bearer to a downstream service.
- ✅ **HTTPS-only** — redirect URIs restricted to `https://` or `localhost`.
- ✅ **Exact redirect_uri match** — no pattern matching.
- ✅ **Per-client consent** — `OAuthConsent` keyed on `(user, client)`, checked before every auth code issuance.
- ✅ **CSRF on consent form** — via Phoenix CSRF token.
- ✅ **`state` parameter validated** — documented requirement; session cookie used.
- ✅ **Session IDs are user-bound** — the MCP server already derives actor from the bearer token (not the session ID); session hijacking risk neutralized.
- ✅ **Refresh token rotation + reuse detection** — §6.7.
- ✅ **Short access token TTL** — default 1h.
- ✅ **Authorization codes one-shot, ≤10 min** — §6.7 step 3.
- ⏳ **jti revocation** — deferred to v2. v1 ships with short access-token TTL (1h default) and revokable refresh tokens; minted access tokens themselves cannot be revoked early.

## 10. Testing strategy

### 10.1 Unit

- PKCE helpers (`:crypto.hash` ↔ `Base.url_encode64` padding).
- Per-endpoint plug modules with fixture conns.
- Each Ash action (consume, rotate, revoke).

### 10.2 Integration

- Full OAuth 2.1 round trip: unauth MCP → 401 → PRM → ASM → DCR → authorize (with and without existing consent) → token → authenticated MCP → refresh → authenticated MCP.
- Spec conformance matrix — one test per MUST in MCP 2025-06-18 §2.*.
- Confused-deputy scenario: user consents once with client A, attacker-registered client B gets blocked on `/authorize`.
- Refresh rotation race: two parallel refreshes of the same token → one succeeds, the other triggers revocation of the chain.

### 10.3 Client smoke tests

- `mcp_proxy_rust` (tidewave's proxy, already referenced in README) — local end-to-end.
- Document a manual playbook for ChatGPT connector + Claude custom connector against `mcp_proxy_rust` → local Phoenix.

## 11. Documentation deliverables

- `documentation/topics/mcp-oauth.md` — user guide (install, config, wire-up).
- `documentation/topics/mcp-oauth-security.md` — security posture & mitigations.
- README section replacing the current "Roadmap — Implement OAuth2 flow" bullet.
- Changelog entry.

## 12. Implementation phases (detailed plan deferred to writing-plans)

Approximate ordering:

1. **Foundations** — `Config` wrapper, `Startup` validator, `Secret` helper, PKCE helpers.
2. **Ash resources + generator** — `mix ash_ai.gen.oauth` scaffolds four resources + runtime.exs block.
3. **Resource server side** — `BearerPlug`, PRM endpoint. Unit tests.
4. **Metadata + DCR** — ASM endpoint, `/oauth/register`. Unit tests.
5. **Authorize + consent** — `/oauth/authorize` GET + POST, HEEx template, consent lookup. Full integration tests start here.
6. **Token** — `/oauth/token` code exchange. Full happy-path integration test.
7. **Refresh + revoke** — rotation, reuse detection, `/oauth/revoke`.
8. **Hardening** — security checklist tests, edge cases, error response precision.
9. **Docs + changelog + README update**.

## 13. Risks

- **AshAuthentication Jwt `token_for_user` may not accept arbitrary `aud`**. Mitigation: if `extra_claims` doesn't support `aud` override cleanly, drop to a direct `Joken` call with the same signer.
- **Consent HEEx without LiveView** may look crude. Mitigation: ship minimal-but-correct; users can override `consent_template`.
- **Future extraction pain** if we lean on ash_ai-internal helpers. Mitigation: `lib/ash_ai/oauth/` is self-contained, only imports public AshAuthentication APIs.
- **Config typos silent until first request**. Mitigation: `AshAi.Oauth.Startup` validates on boot.
- **ChatGPT/Claude client quirks** (e.g., the `client_secret` bug) may surface late. Mitigation: `dcr_always_return_client_secret` toggle; client smoke-test playbook in docs.

## 14. Prior art in the Elixir ecosystem

Surveyed to validate config choice and to confirm we aren't reinventing:

### OAuth server libraries

- **[Boruta](https://github.com/malach-it/boruta_auth)** — most feature-complete Elixir OAuth/OIDC provider. OpenID certified (May 2023). Implements RFC 6749, 7009, 7636 (PKCE), 7662, OpenID Core, OpenID DCR. Uses a behaviour callback pattern: you implement `Boruta.Oauth.Application` with `token/2`, `authorize/2`, `introspect/2`. Ships Phoenix controller/view generators. Uses Ecto directly.
  - **Why not use as our AS core?** (1) Its storage layer assumes Ecto schemas; wrapping for Ash resources would reinvent most of the substrate. (2) It implements OIDC + implicit + hybrid + credentials — surface area we don't need. (3) Does not implement RFC 9728 (PRM) or RFC 8707 (audience binding); the MCP-specific bits would still be ours to build. (4) Adapting it cleanly ≈ same effort as building targeted AS code on AshAuthentication.
  - **What we borrow**: consent flow controller structure; error response shapes (RFC-exact); the idea of keeping the token endpoint stateless.
  - **Documented recommendation for users not on AshAuth**: "use Boruta" will be in our README as the alternative path.

- **[ex_oauth2_provider](https://github.com/danschultzer/ex_oauth2_provider)** — older, maintenance mode (last release Aug 2023), Doorkeeper-inspired. No PKCE/DCR/OAuth 2.1. **Useful reference for the app-config pattern**: confirms plain `config :my_app, ExOauth2Provider, repo: …, resource_owner: …` is idiomatic for this kind of library in Elixir.

- **[Guardian](https://github.com/ueberauth/guardian)** — JWT auth framework, not an AS. Pattern: `use Guardian, otp_app: :my_app`. Referenced as a signer/plug precedent.

### Elixir MCP libraries

- **[ExMCP](https://github.com/azmaveth/ex_mcp)** — implements the OAuth 2.1 *client* side (auto 401→discover→PKCE→token, RFC 7009 revocation, JWT client auth). No AS. Useful reference if we ever need to ship an MCP client.
- **[Hermes/Anubis MCP](https://github.com/cloudwalk/hermes-mcp)** — MCP SDK for Elixir. No auth.
- **[mcp_sse](https://github.com/kend/mcp_sse)** — SSE MCP server. No auth.

### Ecosystem conclusion

No Elixir library currently implements the MCP 2025-06-18 **server-side** auth story (RS + AS + PRM + audience binding). We're not duplicating work; we're filling a gap. Boruta is the closest prior art for the AS side, and its behaviour-style integration informs our design (callback-shaped `Config` module instead of a DSL).

### Config-pattern validation

The `config :my_app, AshAi.Oauth, ...` choice is validated by two points of prior art:
1. `ex_oauth2_provider` uses the same shape.
2. AshAuthentication itself uses plain config for secrets (`{AshAuthentication.Secret, []}`) and we reuse that convention.

Known gotchas we will address:
- **Tests**: ship a test helper that sets config via `Application.put_env` + `on_exit` cleanup.
- **Boot validation**: `AshAi.Oauth.Startup` child process verifies config on app boot.
- **Dynamic values**: support `{:system, "VAR"}` tuples alongside literal strings and `AshAuthentication.Secret` modules.

## 15. Open questions (to resolve during implementation)

1. Should `AshAi.Oauth.Router` own `/.well-known/oauth-protected-resource` too (to keep routing in one place), or leave it on the MCP side? Currently drafted on the Oauth Router to simplify the user's router file, but logically it's an RS concern.
2. Do we want a separate sub-scope (e.g. `mcp:tools`, `mcp:resources`) inside the single top-level `mcp` scope, even in v1, to make future expansion non-breaking? Probably yes — ship with `scopes: ["mcp"]` but expose the list so users can widen it.
3. Consent "remember me" duration — unlimited by default, or expire after N days? Default unlimited, configurable.
