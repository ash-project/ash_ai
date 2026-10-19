<!--
SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>

SPDX-License-Identifier: MIT
-->

# Using MCP Servers with Ash AI Tool Loops

MCP servers let an LLM use tools that live in other services, like your issue tracker or your
team's docs. `AshAi.ToolLoop` can call those tools right alongside the tools from your Ash actions.

In this guide, we'll take the chat that `mix ash_ai.gen.chat` generates and teach it to use MCP
servers, with each user connecting their own accounts. Along the way, we'll point out what the
generated code is doing for you, so that you can do the same thing in a tool loop of your own.

## Goals

In this guide we will:

1. Generate a chat, along with storage for each user's MCP credentials
2. See what an MCP server's tools look like
3. Give the chat the tools from the servers a user has connected
4. Add a page where users connect and disconnect servers
5. See how the chat handles a server that needs the user, and ask users before tool calls run

## Requirements

You'll need a Phoenix application with Ash, AshPostgres and AshAuthentication, with a user
resource. If you don't have one yet, the
[quick start](Mix.Tasks.AshAi.Gen.Chat.html#module-quick-start) for `mix ash_ai.gen.chat` will
create one for you.

> ### This just gives you a starting point {: .warning}
>
> You will almost certainly need to build quite a bit more, around things especially like managing
> MCP servers, tool approvals etc.

## Generate the chat

```bash
mix ash_ai.gen.chat --user MyApp.Accounts.User --live
```

This gives us conversation and message resources, an Oban job that writes each reply with
`AshAi.ToolLoop.stream/2`, and a chat page at `/chat`. The rest of this guide is changes to the
code it generates, which is yours to change however you like.

> ### Already have a generated chat? {: .info}
>
> Chats generated before ash_ai supported MCP servers can't wait on the user. The easiest way to
> see what changed is to generate a chat in a scratch app and compare. Look at the `awaiting`,
> `resume_requested` and `approvals` attributes and the `:resume` action on messages, the `Respond`
> change, and the markup under replies.

## Generate storage for credentials

MCP servers that act on a user's behalf generally use OAuth. Each user has to authorize your app,
and we have to keep the tokens we get back somewhere safe. `mix ash_ai.gen.mcp_oauth` generates
all of that for us:

```bash
mix ash_ai.gen.mcp_oauth --user MyApp.Accounts.User
mix ash.migrate
```

This adds:

- Resources for each user's tokens, encrypted with `ash_cloak`
- `MyApp.McpAuth.options/1`, which returns the `AshAi.Mcp.OAuth` options for a given user
- `MyAppWeb.McpAuthController`, with routes that send a user off to authorize an MCP server
  (`/mcp-auth/authorize`), bring them back (`/mcp-auth/callback`), and disconnect them
  (`/mcp-auth/connection`)

It works as-is in development and test. In production you'll need to set a `CLOAK_KEY`, which we
cover [at the end](#going-to-production). If you'd rather keep credentials somewhere else, see the
[MCP Client Authorization](mcp-client-authorization.md) guide.

## What do MCP tools look like?

Before we wire anything up, let's look at what we actually get from an MCP server. Open
`iex -S mix` and connect to DeepWiki's MCP server, which is public, so it doesn't need
authorization:

```elixir
{:ok, conn} = AshAi.Mcp.Client.connect(name: "deepwiki", url: "https://mcp.deepwiki.com/mcp")
{:ok, definitions} = AshAi.Mcp.Client.list_tools(conn)

Enum.map(definitions, & &1["name"])
# => ["ask_wiki_question", "read_wiki_contents", "read_wiki_structure"]
```

Those are the server's tool definitions, exactly as it sent them. To hand them to a tool loop, we
turn them into ReqLLM tools:

```elixir
tools = AshAi.Mcp.Client.req_llm_tools(conn, definitions)

Enum.map(tools, fn {tool, _callback} -> tool.name end)
# => ["mcp__deepwiki__ask_wiki_question", "mcp__deepwiki__read_wiki_contents",
#     "mcp__deepwiki__read_wiki_structure"]
```

Each one is a `{tool, callback}` pair. The names are prefixed with the server's name, so tools
from different servers can't collide, and when the model calls one, its callback calls the tool on
the server. You can call a tool yourself, too:

```elixir
{:ok, result} =
  AshAi.Mcp.Client.call_tool(conn, "read_wiki_structure", %{"repoName" => "ash-project/ash"})

result.content
# => [%{"type" => "text", "text" => "Available pages for ash-project/ash: ..."}]
```

Those `{tool, callback}` pairs are exactly what `AshAi.ToolLoop` takes as `:extra_tools`, and for
a public server, that's really all there is to it. The rest of this guide is about servers that
need to know who the user is.

## Give the chat MCP tools

For a server that uses OAuth, we give it `AshAi.Mcp.OAuth` as its `auth`, along with the options
for the user. Every request to that server then carries the user's token, which is refreshed for
us when it expires.

Let's add a module that lists the MCP servers our chat can use, and builds the tools from the ones
a user has connected:

```elixir
# lib/my_app/chat/mcp_servers.ex

defmodule MyApp.Chat.McpServers do
  @moduledoc "The MCP servers the chat can use."

  require Logger

  # The model sees each server's tools as `mcp__<name>__<tool>`
  @servers [
    [name: "linear", url: "https://mcp.linear.app/mcp"]
  ]

  def all, do: @servers

  def server(config, user) do
    AshAi.Mcp.Client.server(
      name: config[:name],
      url: config[:url],
      auth: {AshAi.Mcp.OAuth, MyApp.McpAuth.options(user.id)},
      allowed_private_hosts: MyApp.McpAuth.allowed_private_hosts()
    )
  end

  @doc "Tools from the servers `user` has connected, for `AshAi.ToolLoop`'s `extra_tools`."
  def tools(user) do
    Enum.flat_map(@servers, fn config ->
      with {:ok, conn} <- AshAi.Mcp.Client.connect(server(config, user)),
           {:ok, definitions} <- AshAi.Mcp.Client.list_tools(conn) do
        AshAi.Mcp.Client.req_llm_tools(conn, definitions)
      else
        # Not connected yet, or the server no longer accepts their token
        {:error, {kind, _info}} when kind in [:authorization_required, :insufficient_scope] ->
          []

        {:error, _reason} ->
          Logger.warning("Couldn't list the tools of the #{config[:name]} MCP server")
          []
      end
    end)
  end
end
```

Listing a server's tools needs the user's token too, so a server the user hasn't connected doesn't
contribute any tools. The model won't know it exists until they connect it.

Now we pass these to the tool loop. Each reply is written by the generated `Respond` change, in an
Oban job that runs as the user who sent the message. That means `context.actor` is the user whose
tokens we want. Build the tools at the start of the reply, and pass them as `:extra_tools`:

```elixir
# lib/my_app/chat/message/changes/respond.ex

Ash.Changeset.before_transaction(changeset, fn changeset ->
  message = changeset.data
  mcp_tools = MyApp.Chat.McpServers.tools(context.actor)

  ...

  |> AshAi.ToolLoop.stream(
    ...
    approvals: approvals(message.approvals),
    extra_tools: mcp_tools
  )
```

There's one more spot to update in the same function. The change stores a fingerprint of the
system prompt and the tools with each reply. When an earlier reply is replayed, its reasoning is
only kept if the fingerprint still matches, since reasoning is tied to the tools it was produced
with. So the MCP tools need to be part of the fingerprint too:

```elixir
fingerprint =
  Transcript.fingerprint(
    system_prompt(),
    AshAi.list_tools(
      otp_app: :my_app,
      tools: true,
      actor: context.actor,
      tenant: context.tenant
    ) ++ Enum.map(mcp_tools, fn {tool, _callback} -> tool end)
  )
```

## Let users connect

Users need somewhere to connect their accounts. Let's add a page that lists our servers, with a
Connect or Disconnect button for each. The buttons are just forms that post to the routes we
generated earlier.

```elixir
# lib/my_app_web/live/mcp_connections_live.ex

defmodule MyAppWeb.McpConnectionsLive do
  use MyAppWeb, :live_view

  require Ash.Query

  on_mount {MyAppWeb.LiveUserAuth, :live_user_required}

  def mount(_params, _session, socket) do
    user = socket.assigns.current_user

    # Tokens are stored under each server's canonical URL
    connected =
      MyApp.McpAuth.Token
      |> Ash.Query.filter(user_id == ^user.id)
      |> Ash.Query.select([:server])
      |> Ash.read!(authorize?: false)
      |> MapSet.new(& &1.server)

    servers =
      for config <- MyApp.Chat.McpServers.all() do
        {:ok, resource} = AshAi.Mcp.OAuth.canonical_resource(config[:url])
        %{name: config[:name], url: config[:url], connected?: resource in connected}
      end

    {:ok, assign(socket, :servers, servers)}
  end

  def render(assigns) do
    ~H"""
    <div class="mx-auto max-w-lg p-8">
      <h1 class="mb-4 text-lg font-semibold">Connections</h1>
      <div :for={server <- @servers} class="flex items-center justify-between border-b py-3">
        <span>{server.name}</span>
        <.form :if={!server.connected?} for={%{}} action={~p"/mcp-auth/authorize"} method="post">
          <input type="hidden" name="server_url" value={server.url} />
          <input type="hidden" name="return_to" value={~p"/connections"} />
          <button class="btn btn-sm btn-primary">Connect</button>
        </.form>
        <.form :if={server.connected?} for={%{}} action={~p"/mcp-auth/connection"} method="delete">
          <input type="hidden" name="server_url" value={server.url} />
          <input type="hidden" name="return_to" value={~p"/connections"} />
          <button class="btn btn-sm">Disconnect</button>
        </.form>
      </div>
    </div>
    """
  end
end
```

The tokens are stored under each server's canonical URL, which is why we compare against
`AshAi.Mcp.OAuth.canonical_resource/1` instead of the URL as we wrote it.

Then add the route next to the chat's, inside the `ash_authentication_live_session`:

```elixir
# lib/my_app_web/router.ex

live "/connections", McpConnectionsLive
```

## Try it out

Start your server and visit `/connections`. Press Connect, and you'll be sent to the MCP server to
sign in and approve your app, then brought back. Your app registers itself with the server's
authorization server the first time, so there's nothing to set up for each server.

Now head over to `/chat` and ask for something that needs one of the server's tools. You'll see
each tool call as a badge on the reply.

## When a server needs the user

Sometimes a server stops accepting a user's access in the middle of a reply. They might have
revoked it, or a tool might need more permissions than they granted. The generated chat already
handles this, so there's nothing to change here, but it's worth knowing what's going on.

When this happens, the MCP tool doesn't fail. Instead, it asks the tool loop to pause. The reply
stops, and shows a Connect button for that server along with a Continue button. The user connects,
comes back to the chat, and presses Continue. The tool call that needed them runs, and the reply
picks up where it left off. If they send another message instead, the buttons go away, and the
model is told that the call didn't run.

If a server stops accepting a user's access between replies, there's nothing to pause. Its tools
are left out of the next reply, and `/connections` shows Connect for it again. AshAi refreshes
tokens before they expire, so this only happens when a server actually stops accepting them.

> ### In your own tool loop {: .tip}
>
> A paused loop returns an `AshAi.ToolLoop.Result` with `status: :paused`, and each call that needs
> the user in `paused_calls`, as `%{call: call, reason: {kind, info}}`. `kind` is
> `:authorization_required` or `:insufficient_scope`, and `info` has the `server_url` and the
> server's challenge in `www_authenticate`.
>
> Send the user to the URL from `AshAi.Mcp.OAuth.authorize_url/3`, passing
> `challenge: info.www_authenticate` so that they're asked for what the server wants. Once they're
> back, run the loop again with `result.messages`. The call was left unanswered, so it runs first.
>
> The generated chat stores what a reply is waiting on in its `awaiting` attribute. Continue runs
> the message's `:resume` action, which runs the `Respond` change again with the reply added to the
> history.

## Ask before tool calls

MCP servers can do things on the user's behalf, like creating issues or sending messages, so you'll
probably want users to approve some calls before they run. The generated chat already has Approve
and Deny buttons for this. It just doesn't ask about anything yet, because which calls need
approval is up to you.

In the `Respond` change, uncomment `approve_tool_call:` and return `:ask` for the calls to
approve:

```elixir
# lib/my_app/chat/message/changes/respond.ex

approve_tool_call: fn
  %{name: "mcp__" <> _}, _context -> :ask
  _call, _context -> :ok
end,
```

Now the reply stops before those calls, and shows them with Approve and Deny buttons. Approving
runs them, and denying tells the model the user said no. If an approved call then needs the user
to reconnect, they won't be asked to approve it again.

The function gets each call's `name` and `arguments`, so you can be as specific as you like. For
example, to let reads through and ask about everything else:

```elixir
approve_tool_call: fn
  %{name: "mcp__linear__" <> tool}, _context when tool in ["list_issues", "get_issue"] -> :ok
  %{name: "mcp__" <> _}, _context -> :ask
  _call, _context -> :ok
end,
```

> ### In your own tool loop {: .tip}
>
> Returning `:ask` stops the loop with `status: :awaiting_approval`, and the calls in
> `pending_approvals`. To continue, run it again with an `:approvals` map from call ids to
> `:approve` or `{:deny, reason}`. Calls that were approved and then paused come back in
> `Result.approvals`. Store them and pass them back, so the user isn't asked twice.

## Disconnecting

Disconnecting from `/connections` revokes the user's tokens at the authorization server, if it
supports revocation, and deletes them.

If you delete users, call `MyApp.McpAuth.disconnect_all(user.id)` first. Deleting a user deletes
their tokens along with them, but only revoking them ends the grants on the authorization servers'
side.

## Going to production

- **Set `CLOAK_KEY`.** This is what encrypts the stored tokens. You can generate one with
  `32 |> :crypto.strong_rand_bytes() |> Base.encode64()`. Don't lose it! If you do, every user has
  to connect again.
- **Serve your app over HTTPS at its public URL.** The callback URL is built from your endpoint's
  `url` config, which Phoenix sets from `PHX_HOST`. Over HTTPS, your app also identifies itself to
  authorization servers with a Client ID Metadata Document, served at
  `/mcp-auth/client-metadata.json`.
- **Register by hand where you have to.** A few authorization servers don't let apps register
  themselves. Register your app with them yourself, with
  `https://your-app.example.com/mcp-auth/callback` as its redirect URI, and add the credentials to
  `MyApp.McpAuth.options/1`:

  ```elixir
  pre_registered: %{
    "https://mcp.example.com/mcp" => [
      issuer: "https://auth.example.com",
      client_id: System.fetch_env!("EXAMPLE_CLIENT_ID"),
      client_secret: System.fetch_env!("EXAMPLE_CLIENT_SECRET")
    ]
  }
  ```

- **Allow private hosts on purpose.** Your app only connects to public addresses, so that a URL
  from a server can't be used to reach services on your network. If you want to use an MCP server
  on your own network, add its host to `config :my_app, :mcp_allowed_private_hosts`. Development
  allows `localhost`.

You can run all of this on as many nodes as you like. AshAi doesn't keep anything in memory
between requests, and token refreshes are coordinated through the database.

## What next?

- **Keep tools stable across a conversation.** The tools are listed at the start of every reply,
  so if a server changes its tools, they change mid-conversation, and you lose prompt caching. You
  can store the definitions from `AshAi.Mcp.Client.list_tools/1` when a conversation starts, and
  build the tools from those instead. See "Tool definitions and prompt caching" in
  `AshAi.Mcp.Client`.
- **Use servers that take an API key.** Pass `headers:` to `AshAi.Mcp.Client.server/1` instead of
  `auth:`.
- **Keep credentials somewhere else.** See the [MCP Client Authorization](mcp-client-authorization.md)
  guide for writing your own store.
