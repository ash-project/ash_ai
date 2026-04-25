<!--
SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>

SPDX-License-Identifier: MIT
-->

# MCP OAuth security posture

This document explains what the ash_ai OAuth implementation enforces, the threats those
controls address, and what is explicitly out of scope for v1.

## Spec compliance

ash_ai targets the [MCP 2025-06-18 authorization specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization),
plus the supporting RFCs:

- **OAuth 2.1** ([draft-ietf-oauth-v2-1-13](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13))
- **RFC 7636** PKCE — S256 only
- **RFC 7591** Dynamic Client Registration
- **RFC 8414** Authorization Server Metadata
- **RFC 9728** Protected Resource Metadata
- **RFC 8707** Resource Indicators (audience binding)
- **RFC 7009** Token Revocation

## What's enforced

### Audience binding (RFC 8707)

Every minted access token carries `aud` set to the configured `canonical_mcp_url`. The
resource server rejects any token whose audience does not match. This is the single most
important defense against confused-deputy attacks where a token issued for one MCP server
is replayed against another.

### PKCE S256

The `/oauth/authorize` endpoint rejects `code_challenge_method=plain`. Only S256 is accepted.
The token endpoint verifies the `code_verifier` against the stored `code_challenge` using
constant-time comparison (`Plug.Crypto.secure_compare`).

### Per-client consent

Each OAuth client must obtain explicit user consent on first authorization. Consent is
recorded in `OAuthConsent` keyed on `(user_id, client_id)`. This prevents the
[confused deputy attack](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices#confused-deputy-problem)
where a previously-approved upstream consent cookie is leveraged by an attacker-registered
DCR client.

### Authorization code one-shot, short-lived

Authorization codes have a 10-minute TTL by default and are consumed atomically. Replay
attempts hit a `consumed_at` check and return `invalid_grant`.

### Refresh token rotation + reuse detection (OAuth 2.1 §4.3.1)

Every refresh exchange produces a brand new refresh token; the old one is marked rotated.
A second refresh attempt with the rotated token revokes the entire chain — this is the
spec-recommended response to suspected token theft.

### Exact redirect URI matching

`/oauth/authorize` and `/oauth/token` both validate that `redirect_uri` exactly matches
one of the values registered for the client. Pattern matching and wildcard support are not
implemented and will not be added.

### HTTPS-only redirect URIs

DCR rejects `http://` redirect URIs except for `localhost`, `127.0.0.1`, and `::1` (for
local development). All authorization-server endpoints assume HTTPS in production.

### CSRF on consent submission

The consent form includes a CSRF token issued by `Plug.CSRFProtection`. Submissions
without a valid token are rejected.

### Bearer-only tokens

Access tokens are accepted only via the `Authorization: Bearer <token>` header. Tokens in
URI query strings are rejected, per OAuth 2.1 §5.

### Token revocation

`/oauth/revoke` accepts refresh tokens by raw value, hashes them, and marks the matching
row revoked. Per RFC 7009, the endpoint always returns 200 regardless of whether the token
existed (timing-attack resistant).

### Boot-time config validation

`AshAi.Oauth.Application` (optional supervisor child) validates that all required config
keys are present, that issuer/canonical URLs are well-formed `http(s)` URIs with hosts,
and that all referenced resource modules compile. Misconfigured deployments fail fast at
boot rather than at first request.

## What is *not* in v1

Documented for transparency. Patches welcome.

- **DPoP** sender-constrained tokens
- **mTLS** client authentication
- **Token introspection endpoint** (RFC 7662)
- **Fine-grained per-tool scopes** — currently a single `mcp` scope covers everything
- **Asymmetric (RS256/EdDSA) signing + JWKS endpoint** — HS256 only, since AS and RS are
  co-hosted and share the secret. The architecture supports swapping in RS256 with
  minimal changes when the AS is extracted into a separate process.
- **Client credentials grant** — agent-to-agent flows
- **Device code grant** — TV/CLI flows
- **Admin UI for managing clients/tokens** — ad-hoc Ash queries for now
- **Signed metadata** (RFC 8414 `signed_metadata`)
- **Automatic client cleanup** — DCR clients accumulate; consider a periodic Oban job
  pruning `last_used_at` older than your tolerance

## Known interop quirks

### ChatGPT and `client_secret`

Some ChatGPT builds reject DCR responses that omit `client_secret` even when
`token_endpoint_auth_method` is `none`. If you observe registration failures in ChatGPT,
enable the workaround:

```elixir
config :my_app, AshAi.Oauth, dcr_always_return_client_secret: true
```

This returns an empty `client_secret: ""` in the DCR response. The token endpoint ignores
any value the client subsequently presents for `auth_method: "none"` clients.

### DCR client churn

ChatGPT and Claude both register a new OAuth client every time a user reconnects. Over
time the `OAuthClient` table grows. An Oban scheduled job that deletes clients with
`last_used_at` older than N days is the recommended mitigation; this is left to the
deploying application.

## Audit checklist

For a deployment review, verify each of these:

- [ ] `canonical_mcp_url` matches the public URL of the MCP endpoint exactly
- [ ] `signing_secret` is at least 32 random bytes, never logged, never committed
- [ ] HTTPS terminates in front of the app; the `:browser` pipeline includes
      `:put_secure_browser_headers`
- [ ] `:protect_from_forgery` is in the `:browser` pipeline
- [ ] No tool implementation passes the user's bearer token to a downstream API
      (token-passthrough is forbidden — see the spec)
- [ ] Refresh-token TTL matches your session expectations
- [ ] Postgres migrations for the four OAuth resources have been deployed
- [ ] `AshAi.Oauth.Application` is in your supervision tree (catches boot-time misconfig)
