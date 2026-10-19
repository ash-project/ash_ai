# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.Client.Auth do
  @moduledoc """
  Supplies credentials for the requests `AshAi.Mcp.Client` makes to an MCP server.

  Configure a server with `auth: {module, opts}`. Before each request the client
  calls `c:headers/2`. When the server answers 401 or 403, the client calls
  `c:handle_challenge/3`, and retries the request once if it returns `:retry`.

  `AshAi.Mcp.OAuth` implements this behaviour for the MCP authorization spec.
  """

  @typedoc """
  What the server answered when it rejected a request.

  `www_authenticate` is the raw `WWW-Authenticate` header, or `nil` when the
  server sent none.
  """
  @type challenge :: %{
          status: 401 | 403,
          www_authenticate: String.t() | nil
        }

  @doc """
  Headers to add to a request to the MCP server at `server_url`.

  Return `{:error, reason}` when no usable credentials exist, for example
  `{:error, {:authorization_required, info}}` when the user has to authorize.
  """
  @callback headers(server_url :: String.t(), opts :: keyword()) ::
              {:ok, [{String.t(), String.t()}]} | {:error, term()}

  @doc """
  Called when the server rejects a request with 401 or 403.

  Return `:retry` after obtaining new credentials (for example by refreshing a
  token) and the client retries the request once. Otherwise return
  `{:error, reason}`, which the client returns to its caller.
  """
  @callback handle_challenge(server_url :: String.t(), challenge(), opts :: keyword()) ::
              :retry | {:error, term()}
end
