<!--
SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>

SPDX-License-Identifier: MIT
-->

# MCP Client Authorization

`AshAi.Mcp.Client` connects to MCP servers, and `AshAi.Mcp.OAuth` gets it tokens for servers that
use OAuth. AshAi keeps no state of its own, so it runs the same on every node: what it has to
remember between requests goes through an `AshAi.Mcp.OAuth.Store` that your application provides.

The quickest way to get one is the generator, which writes an `ash_postgres` store with its secrets
encrypted by `ash_cloak`, plus the routes for the authorization flow:

```bash
mix ash_ai.gen.mcp_oauth
```

This guide covers what the generated code does, for when you'd rather write your own, for example
to keep credentials in an existing secrets store.

## The flow

1. Give an MCP server `AshAi.Mcp.OAuth` as its auth, with the store and the owner of the tokens,
   usually the signed-in user's id:

   ```elixir
   AshAi.Mcp.Client.server(
     name: "linear",
     url: "https://mcp.linear.app/mcp",
     auth: {AshAi.Mcp.OAuth, store: MyApp.McpStore, owner: user.id, redirect_uri: callback_url}
   )
   ```

2. Without a usable token, requests return `{:error, {:authorization_required, info}}`. A tool
   loop pauses instead, with the error in `paused_calls`. Send the user to the URL from
   `AshAi.Mcp.OAuth.authorize_url/3`, passing `challenge: info.www_authenticate`.

3. The authorization server redirects back to your callback route. Pass its query params and the
   **signed-in** owner to `AshAi.Mcp.OAuth.handle_callback/3`. It refuses to complete an
   authorization for anyone but the owner who started it, so one user can't send another an
   authorization link and receive their tokens.

4. Run the paused tool loop again. The call that needed authorization runs now.

Tokens are refreshed before they expire. When a refresh token stops working, requests return
`:authorization_required` again. A server that needs more scopes returns
`{:error, {:insufficient_scope, info}}`, handled the same way.

## Disconnecting

`AshAi.Mcp.OAuth.disconnect/3` revokes an owner's tokens at the authorization server (RFC 7009),
when it offers revocation, and deletes them from the store. Call it when a user disconnects an MCP
server, and for each of their servers before deleting their account or removing them from an
organization. Deleting tokens alone stops your application from using them, but the grant stays
active at the authorization server until it expires or the user revokes it there.

The tokens are deleted even when revoking them fails, so disconnecting always works on your side.
`{:error, {:revocation_failed, reason}}` tells you the authorization server may still honor the
grant.

## Writing a store

The store keeps three kinds of record. Each struct has `to_map/1` and `from_map/1` for a JSON-safe
map, so a store can treat them as opaque data under a key:

| Record | Key | Holds |
| --- | --- | --- |
| `AshAi.Mcp.OAuth.Token` | server, owner | Access and refresh tokens |
| `AshAi.Mcp.OAuth.Client` | server, issuer | A client registered through Dynamic Client Registration, sometimes with a secret |
| `AshAi.Mcp.OAuth.Pending` | `state` | An authorization in progress, with its PKCE verifier |

Beyond getting and putting, a store has four responsibilities:

* **Encrypt the data.** Tokens, client secrets, and PKCE verifiers all grant access.
* **Take pending authorizations once.** `take_pending/2` must read and delete in one step, such
  as a `DELETE ... RETURNING` or a read under a row lock followed by a delete in one transaction.
* **Lock across nodes, without holding a connection.** `with_lock/4` must serialize callers for
  the same server and owner on every node. Many authorization servers rotate refresh tokens and
  revoke the whole grant when an old one is reused, so two nodes refreshing at once would force the
  user to authorize again. The locked function makes requests to the authorization server, so a
  database lock, which holds a connection while others wait and while the requests run, lets a slow
  authorization server exhaust your connection pool. Use a lease instead: claim the token's row with
  a conditional update until a timestamp, poll while someone else holds it, and clear it afterwards.
* **Prune abandoned pending authorizations.** AshAi rejects them after `:pending_ttl` (10 minutes
  by default) but doesn't delete them.

A sketch with Ecto, using one table of encrypted maps:

```elixir
defmodule MyApp.McpStore do
  @behaviour AshAi.Mcp.OAuth.Store

  import Ecto.Query
  alias AshAi.Mcp.OAuth.{Client, Pending, Token}
  alias MyApp.{McpRecord, Repo}

  def get_token(server, owner, _), do: fetch("token", [server, owner], &Token.from_map/1)
  def put_token(server, owner, token, _), do: put("token", [server, owner], Token.to_map(token))
  def delete_token(server, owner, _), do: delete("token", [server, owner])

  def get_client(server, issuer, _), do: fetch("client", [server, issuer], &Client.from_map/1)
  def put_client(server, client, _), do: put("client", [server, client.issuer], Client.to_map(client))

  def put_pending(pending, _), do: put("pending", [pending.state], Pending.to_map(pending))

  def take_pending(state, _) do
    query = from r in McpRecord, where: r.kind == "pending" and r.key == ^key([state]), select: r

    case Repo.delete_all(query) do
      {1, [record]} -> {:ok, Pending.from_map(record.data)}
      _ -> :error
    end
  end

  defp key(parts), do: Jason.encode!(parts)

  # fetch/3, put/3, and delete/2 read, upsert, and delete one `McpRecord` by
  # kind and key. Its `data` column is encrypted, for example with a Cloak type.
  # with_lock/4 takes a lease on the token's row, as described above.
end
```

See `AshAi.Mcp.OAuth.Store` for each callback's contract, and the store `mix ash_ai.gen.mcp_oauth`
generates for a complete lease.

## Client identity

Authorization servers need to know which application is asking. `AshAi.Mcp.OAuth` tries, in order:

* **Pre-registered credentials** in `:pre_registered`, for servers that make you register an
  application by hand. They're keyed by MCP server and must name their issuer, so another server
  can't borrow them.
* **A Client ID Metadata Document**, when the authorization server supports them and you set
  `:client_metadata_url`. Serve it with `AshAi.Mcp.OAuth.ClientMetadataPlug` from a public HTTPS
  URL.
* **Dynamic Client Registration**, which needs nothing but the store.

## Private networks

The client and the OAuth requests only connect to public addresses, so a URL that a user or a
server supplies can't reach services on your network. List the exceptions, such as `"localhost"`
in development or an internal MCP server, in `:allowed_private_hosts`, on both the
`AshAi.Mcp.Client.Server` and the `AshAi.Mcp.OAuth` options.
