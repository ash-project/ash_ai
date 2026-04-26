#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT
#
# Walks through the full OAuth 2.1 MCP wire flow against the demo server
# (examples/oauth_demo.exs) running on http://localhost:4000.
#
# Run from the repo root after starting the demo server:
#
#     # terminal 1
#     mix run --no-halt examples/oauth_demo.exs
#
#     # terminal 2
#     bash examples/test-oauth.sh
#
# Requires: curl, jq.

set -euo pipefail

BASE="${BASE:-http://localhost:4000}"
MCP_URL="$BASE/mcp"
REDIRECT_URI="http://localhost:9999/cb"

step() {
  echo
  echo "──────────────────────────────────────────────────────────────"
  echo "▶ $1"
  echo "──────────────────────────────────────────────────────────────"
}

# ── 1. Unauthenticated MCP request → 401 + WWW-Authenticate ─────────

step "1. Unauthenticated MCP request"
WWW_AUTH=$(curl -s -i -X POST -d '{}' "$MCP_URL" | grep -i "^www-authenticate:" | tr -d '\r')
echo "$WWW_AUTH"

PRM_URL=$(echo "$WWW_AUTH" | grep -oE 'resource_metadata="[^"]+"' | cut -d'"' -f2)
echo
echo "Extracted PRM URL: $PRM_URL"

# ── 2. Fetch Protected Resource Metadata (RFC 9728) ──────────────────

step "2. GET $PRM_URL"
PRM=$(curl -s "$PRM_URL")
echo "$PRM" | jq .

AS_ISSUER=$(echo "$PRM" | jq -r '.authorization_servers[0]')

# ── 3. Fetch Authorization Server Metadata (RFC 8414) ────────────────

step "3. GET $AS_ISSUER/.well-known/oauth-authorization-server"
ASM=$(curl -s "$AS_ISSUER/.well-known/oauth-authorization-server")
echo "$ASM" | jq .

REGISTRATION_ENDPOINT=$(echo "$ASM" | jq -r '.registration_endpoint')
AUTHORIZE_ENDPOINT=$(echo "$ASM" | jq -r '.authorization_endpoint')
TOKEN_ENDPOINT=$(echo "$ASM" | jq -r '.token_endpoint')
REVOKE_ENDPOINT=$(echo "$ASM" | jq -r '.revocation_endpoint')

# ── 4. Dynamic Client Registration (RFC 7591) ────────────────────────

step "4. POST $REGISTRATION_ENDPOINT (DCR)"
DCR_BODY=$(cat <<EOF
{
  "client_name": "test-cli",
  "redirect_uris": ["$REDIRECT_URI"],
  "token_endpoint_auth_method": "none"
}
EOF
)

DCR_RESPONSE=$(curl -s -X POST "$REGISTRATION_ENDPOINT" \
  -H "content-type: application/json" \
  -d "$DCR_BODY")

echo "$DCR_RESPONSE" | jq .
CLIENT_ID=$(echo "$DCR_RESPONSE" | jq -r '.client_id')

# ── 5. Build PKCE pair + start authorization flow ────────────────────

step "5. PKCE + authorization request"

# PKCE: 43-128 chars, base64url. We'll just use the RFC fixture.
VERIFIER="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CHALLENGE=$(printf '%s' "$VERIFIER" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
echo "verifier:  $VERIFIER"
echo "challenge: $CHALLENGE"

STATE="cli-$RANDOM"
RESOURCE="$MCP_URL"

AUTHORIZE_URL="$AUTHORIZE_ENDPOINT?response_type=code&client_id=$CLIENT_ID&redirect_uri=$(printf '%s' $REDIRECT_URI | jq -sRr @uri)&code_challenge=$CHALLENGE&code_challenge_method=S256&scope=mcp&state=$STATE&resource=$(printf '%s' $RESOURCE | jq -sRr @uri)"

echo
echo "Authorize URL (the demo auto-signs-in a user, so this directly issues a code):"
echo "  $AUTHORIZE_URL"

# Follow the 302 to extract the code
LOCATION=$(curl -s -i "$AUTHORIZE_URL" | grep -i "^location:" | tr -d '\r' | sed 's/^[Ll]ocation: //')

if [ -z "$LOCATION" ]; then
  echo
  echo "❌ No Location header — did the demo server auto-sign-in fire?"
  echo "Response body:"
  curl -s "$AUTHORIZE_URL" | head -50
  exit 1
fi

echo
echo "Redirected to: $LOCATION"

CODE=$(echo "$LOCATION" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
RETURNED_STATE=$(echo "$LOCATION" | sed -n 's/.*[?&]state=\([^&]*\).*/\1/p')
echo "code:  $CODE"
echo "state: $RETURNED_STATE  (expected $STATE)"

# ── 6. Token exchange ────────────────────────────────────────────────

step "6. POST $TOKEN_ENDPOINT (code → tokens)"

TOKEN_RESPONSE=$(curl -s -X POST "$TOKEN_ENDPOINT" \
  -H "content-type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=$CODE" \
  --data-urlencode "redirect_uri=$REDIRECT_URI" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "code_verifier=$VERIFIER" \
  --data-urlencode "resource=$RESOURCE")

echo "$TOKEN_RESPONSE" | jq .

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')
REFRESH_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.refresh_token')

# ── 7. Authenticated MCP request ─────────────────────────────────────

step "7. POST $MCP_URL with Bearer token"
curl -s -X POST "$MCP_URL" \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -d '{}' | jq .

# ── 8. Refresh ───────────────────────────────────────────────────────

step "8. POST $TOKEN_ENDPOINT (refresh → rotate)"
REFRESH_RESPONSE=$(curl -s -X POST "$TOKEN_ENDPOINT" \
  -H "content-type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=refresh_token" \
  --data-urlencode "refresh_token=$REFRESH_TOKEN" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "resource=$RESOURCE")

echo "$REFRESH_RESPONSE" | jq .
NEW_REFRESH=$(echo "$REFRESH_RESPONSE" | jq -r '.refresh_token')

# ── 9. Reuse the rotated refresh token (should fail + revoke chain) ──

step "9. Reuse the rotated refresh token (should fail)"
curl -s -X POST "$TOKEN_ENDPOINT" \
  -H "content-type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=refresh_token" \
  --data-urlencode "refresh_token=$REFRESH_TOKEN" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "resource=$RESOURCE" | jq .

step "10. The descendant refresh is now revoked too (chain check)"
curl -s -X POST "$TOKEN_ENDPOINT" \
  -H "content-type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=refresh_token" \
  --data-urlencode "refresh_token=$NEW_REFRESH" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "resource=$RESOURCE" | jq .

step "11. Revoke endpoint with non-matching client_id (no-op)"
curl -s -i -X POST "$REVOKE_ENDPOINT" \
  -H "content-type: application/x-www-form-urlencoded" \
  --data-urlencode "token=$ACCESS_TOKEN" \
  --data-urlencode "client_id=00000000-0000-0000-0000-000000000000" | head -3

echo
echo "✓ End-to-end OAuth 2.1 flow complete."
