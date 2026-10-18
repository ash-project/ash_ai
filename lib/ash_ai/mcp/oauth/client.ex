# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.OAuth.Client do
  @moduledoc """
  An OAuth client registered with one authorization server.

  `:source` says how the client was obtained:

  - `:pre_registered` - supplied by the application through `:pre_registered`.
  - `:cimd` - a Client ID Metadata Document; `client_id` is the document's URL.
  - `:dcr` - registered through Dynamic Client Registration (RFC 7591) and
    persisted with `c:AshAi.Mcp.OAuth.Store.put_client/3`.

  Credentials belong to the authorization server that issued them, named by
  `:issuer`.
  """

  @derive {Inspect, except: [:client_secret, :registration_access_token]}
  defstruct [
    :issuer,
    :client_id,
    :client_secret,
    :client_secret_expires_at,
    :registration_access_token,
    :registration_client_uri,
    :source,
    token_endpoint_auth_method: "none",
    redirect_uris: []
  ]

  @type t :: %__MODULE__{
          issuer: String.t(),
          client_id: String.t(),
          client_secret: String.t() | nil,
          client_secret_expires_at: DateTime.t() | nil,
          registration_access_token: String.t() | nil,
          registration_client_uri: String.t() | nil,
          source: :pre_registered | :cimd | :dcr,
          token_endpoint_auth_method: String.t(),
          redirect_uris: [String.t()]
        }

  @version 1

  @doc "Converts the client to a JSON-safe map with string keys."
  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{} = client) do
    %{
      "version" => @version,
      "issuer" => client.issuer,
      "client_id" => client.client_id,
      "client_secret" => client.client_secret,
      "client_secret_expires_at" =>
        AshAi.Mcp.OAuth.Serialize.datetime(client.client_secret_expires_at),
      "registration_access_token" => client.registration_access_token,
      "registration_client_uri" => client.registration_client_uri,
      "source" => client.source && Atom.to_string(client.source),
      "token_endpoint_auth_method" => client.token_endpoint_auth_method,
      "redirect_uris" => client.redirect_uris
    }
  end

  @doc "Builds a client from a map produced by `to_map/1`."
  @spec from_map(map()) :: t()
  def from_map(%{} = map) do
    %__MODULE__{
      issuer: map["issuer"],
      client_id: map["client_id"],
      client_secret: map["client_secret"],
      client_secret_expires_at:
        AshAi.Mcp.OAuth.Serialize.parse_datetime(map["client_secret_expires_at"]),
      registration_access_token: map["registration_access_token"],
      registration_client_uri: map["registration_client_uri"],
      source: source(map["source"]),
      token_endpoint_auth_method: map["token_endpoint_auth_method"] || "none",
      redirect_uris: map["redirect_uris"] || []
    }
  end

  defp source("pre_registered"), do: :pre_registered
  defp source("cimd"), do: :cimd
  defp source("dcr"), do: :dcr
  defp source(_), do: nil
end
