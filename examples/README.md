<!--
SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>

SPDX-License-Identifier: MIT
-->

# OAuth 2.1 MCP demo

A self-contained, runnable demo of the ash_ai OAuth 2.1 surface against an
in-memory ETS-backed user/client/token store. No Postgres, no migrations,
no Phoenix project — just a single `mix run` that boots a Bandit server.

## Quick start

```sh
# Terminal 1 — boot the demo server
mix run --no-halt examples/oauth_demo.exs

# Terminal 2 — walk the full OAuth 2.1 flow with curl
bash examples/test-oauth.sh
```

What you get:

- `http://localhost:4000/mcp` — bearer-protected MCP endpoint that echoes
  the authenticated user.
- `http://localhost:4000/.well-known/oauth-protected-resource` — RFC 9728
  metadata.
- `http://localhost:4000/.well-known/oauth-authorization-server` — RFC 8414
  metadata.
- `/oauth/register`, `/oauth/authorize`, `/oauth/token`, `/oauth/revoke` —
  the full AS surface.

The demo seeds one user (`demo@example.com`) and auto-signs them in on
`/oauth/authorize` — a real app would put `AshAuthentication`'s
`load_from_session` in the pipeline instead.

## What the curl walkthrough covers

`test-oauth.sh` runs every step a real client does:

1. Unauthenticated MCP request → 401 with `WWW-Authenticate`
2. Fetch Protected Resource Metadata
3. Fetch Authorization Server Metadata
4. Dynamic Client Registration (creates a fresh client)
5. Generate PKCE pair, hit `/oauth/authorize`, extract the code from the redirect
6. Exchange the code for access + refresh tokens
7. Make an authenticated MCP request
8. Refresh the token (rotation)
9. Try to reuse the rotated refresh (should fail with `invalid_grant`)
10. Verify the descendant refresh is also revoked (chain revocation)
11. Hit `/oauth/revoke` with a non-matching `client_id` (no-op)

If everything's wired up correctly you should see green JSON all the way
through, ending with `✓ End-to-end OAuth 2.1 flow complete.`

## Connecting from ChatGPT or Claude

ChatGPT and Claude only accept `https://` for production custom connectors.
For local testing you need a tunnel. With cloudflared:

```sh
cloudflared tunnel --url http://localhost:4000
```

Then set `ISSUER_URL` and `MCP_URL` in `examples/oauth_demo.exs` to the
tunnel URL (or restart with both rewritten via env), and paste the tunnel
URL + `/mcp` into ChatGPT's "Add custom connector" or Claude's "Add
custom connector via MCP."

The demo's `auto-sign-in` plug is designed for the `test-oauth.sh` walk-through
— for browser-driven OAuth from ChatGPT/Claude you'd want to swap it
for AshAuthentication's real sign-in flow. See
`documentation/topics/mcp-oauth.md` for the production wiring.

## Cleaning up

The demo uses ETS, so everything (clients, codes, tokens, consents)
disappears when you stop the server with `Ctrl-C`.
