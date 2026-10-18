# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.OAuth.Store do
  @moduledoc """
  Persists what `AshAi.Mcp.OAuth` needs between requests.

  AshAi never stores credentials itself. Configure a store with
  `store: {module, store_opts}` (or just `store: module`); every callback
  receives `store_opts` as its last argument. `mix ash_ai.gen.mcp_oauth`
  generates a store backed by `ash_postgres`, with its secrets encrypted by
  `ash_cloak`.

  Three kinds of records are stored:

  - `AshAi.Mcp.OAuth.Client` - a client registered through Dynamic Client
    Registration, keyed by the MCP server it was registered for and the
    authorization server's issuer. Each MCP server gets its own registration,
    so the authorization server asks for consent again instead of reusing a
    grant made for another MCP server.
  - `AshAi.Mcp.OAuth.Token` - the tokens for one MCP server and one owner. The
    owner is whatever the caller passes as `:owner`, such as a user id; AshAi
    treats it as opaque.

  An MCP server is identified by its canonical resource URI (see
  `AshAi.Mcp.OAuth.canonical_resource/1`).
  - `AshAi.Mcp.OAuth.Pending` - an authorization in progress, keyed by its
    `state` parameter, from `AshAi.Mcp.OAuth.authorize_url/3` until the
    callback.

  Each struct has `to_map/1` and `from_map/1` for JSON-safe serialization, and
  hides its secrets from `inspect/1`. Encrypt the secrets at rest. Client
  secrets, access and refresh tokens, and PKCE verifiers all grant access.

  `c:with_lock/4` must serialize callers for the same server and owner, across
  nodes if the application runs on several. Token refresh runs inside it and
  re-reads the token first, so concurrent requests refresh a rotating refresh
  token only once. The function it runs makes requests to the authorization
  server, so don't hold a database connection or transaction for the lock: a
  row lock or advisory lock does, and a slow authorization server would then
  exhaust the connection pool. A lease works instead, such as a row claimed
  with a conditional update until a timestamp, as the store
  `mix ash_ai.gen.mcp_oauth` generates does.
  """

  alias AshAi.Mcp.OAuth.{Client, Pending, Token}

  @type opts :: term()

  @doc "The client registered for the MCP server `server` with the authorization server `issuer`."
  @callback get_client(server :: String.t(), issuer :: String.t(), opts()) ::
              {:ok, Client.t()} | :error

  @doc "Stores a client registered for `server`, replacing any for `server` and its issuer."
  @callback put_client(server :: String.t(), Client.t(), opts()) :: :ok | {:error, term()}

  @doc "The tokens `owner` holds for the MCP server `server`."
  @callback get_token(server :: String.t(), owner :: term(), opts()) :: {:ok, Token.t()} | :error

  @doc "Stores tokens, replacing any existing ones for `server` and `owner`."
  @callback put_token(server :: String.t(), owner :: term(), Token.t(), opts()) ::
              :ok | {:error, term()}

  @doc "Deletes the tokens for `server` and `owner`, if any."
  @callback delete_token(server :: String.t(), owner :: term(), opts()) :: :ok

  @doc """
  Runs `fun` while holding a lock for `server` and `owner`, returning its result.

  When the lock can't be had in reasonable time, return `{:error, reason}`
  without running `fun`.
  """
  @callback with_lock(server :: String.t(), owner :: term(), (-> result), opts()) ::
              result | {:error, term()}
            when result: term()

  @doc "Stores an authorization in progress."
  @callback put_pending(Pending.t(), opts()) :: :ok | {:error, term()}

  @doc """
  Removes and returns the authorization in progress with this `state`.

  A pending authorization must be usable only once, so remove it as part of the
  same operation.
  """
  @callback take_pending(state :: String.t(), opts()) :: {:ok, Pending.t()} | :error

  @doc false
  def call(store, function, args) do
    {module, store_opts} =
      case store do
        {module, store_opts} when is_atom(module) -> {module, store_opts}
        module when is_atom(module) -> {module, []}
      end

    apply(module, function, args ++ [store_opts])
  end
end
