# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.OAuth.Token do
  @moduledoc """
  The tokens one owner holds for one MCP server.

  Besides the token response itself, a token records what refreshing it needs:
  the authorization server's `issuer` and `token_endpoint`, the `client_id` it
  was issued to, and the `resource` it is bound to.

  `scope` is the granted scope, space-separated. When the token response omits
  it, it is the scope that was requested.
  """

  @derive {Inspect, except: [:access_token, :refresh_token]}
  defstruct [
    :access_token,
    :refresh_token,
    :expires_at,
    :scope,
    :server_url,
    :resource,
    :issuer,
    :client_id,
    :token_endpoint,
    :obtained_at,
    token_type: "Bearer"
  ]

  @type t :: %__MODULE__{
          access_token: String.t(),
          refresh_token: String.t() | nil,
          expires_at: DateTime.t() | nil,
          scope: String.t() | nil,
          server_url: String.t(),
          resource: String.t(),
          issuer: String.t(),
          client_id: String.t(),
          token_endpoint: String.t(),
          obtained_at: DateTime.t() | nil,
          token_type: String.t()
        }

  @version 1

  @doc """
  Whether the access token is still usable `skew` seconds from now.

  A token without an expiry is assumed usable until the server rejects it.
  """
  @spec fresh?(t(), non_neg_integer()) :: boolean()
  def fresh?(%__MODULE__{expires_at: nil}, _skew), do: true

  def fresh?(%__MODULE__{expires_at: expires_at}, skew) do
    DateTime.compare(expires_at, DateTime.add(DateTime.utc_now(), skew, :second)) == :gt
  end

  @doc "Converts the token to a JSON-safe map with string keys."
  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{} = token) do
    %{
      "version" => @version,
      "access_token" => token.access_token,
      "refresh_token" => token.refresh_token,
      "token_type" => token.token_type,
      "expires_at" => AshAi.Mcp.OAuth.Serialize.datetime(token.expires_at),
      "scope" => token.scope,
      "server_url" => token.server_url,
      "resource" => token.resource,
      "issuer" => token.issuer,
      "client_id" => token.client_id,
      "token_endpoint" => token.token_endpoint,
      "obtained_at" => AshAi.Mcp.OAuth.Serialize.datetime(token.obtained_at)
    }
  end

  @doc "Builds a token from a map produced by `to_map/1`."
  @spec from_map(map()) :: t()
  def from_map(%{} = map) do
    %__MODULE__{
      access_token: map["access_token"],
      refresh_token: map["refresh_token"],
      token_type: map["token_type"] || "Bearer",
      expires_at: AshAi.Mcp.OAuth.Serialize.parse_datetime(map["expires_at"]),
      scope: map["scope"],
      server_url: map["server_url"],
      resource: map["resource"],
      issuer: map["issuer"],
      client_id: map["client_id"],
      token_endpoint: map["token_endpoint"],
      obtained_at: AshAi.Mcp.OAuth.Serialize.parse_datetime(map["obtained_at"])
    }
  end
end
