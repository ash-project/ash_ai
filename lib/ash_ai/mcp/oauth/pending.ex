# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.OAuth.Pending do
  @moduledoc """
  An authorization in progress, from `AshAi.Mcp.OAuth.authorize_url/3` until
  `AshAi.Mcp.OAuth.handle_callback/3`.

  It holds the PKCE `code_verifier`, which is a secret, and the `issuer`
  recorded from the authorization server's validated metadata, which the
  callback checks the response's `iss` against (RFC 9207).

  `owner` is stored as given, so it must be JSON-safe for `to_map/1` to be.
  """

  @derive {Inspect, except: [:code_verifier]}
  defstruct [
    :state,
    :owner,
    :server_url,
    :resource,
    :issuer,
    :client_id,
    :redirect_uri,
    :scope,
    :code_verifier,
    :token_endpoint,
    :created_at,
    iss_parameter_supported: false
  ]

  @type t :: %__MODULE__{
          state: String.t(),
          owner: term(),
          server_url: String.t(),
          resource: String.t(),
          issuer: String.t(),
          client_id: String.t(),
          redirect_uri: String.t(),
          scope: String.t() | nil,
          code_verifier: String.t(),
          token_endpoint: String.t(),
          created_at: DateTime.t(),
          iss_parameter_supported: boolean()
        }

  @version 1

  @doc "Converts the pending authorization to a JSON-safe map with string keys."
  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{} = pending) do
    %{
      "version" => @version,
      "state" => pending.state,
      "owner" => pending.owner,
      "server_url" => pending.server_url,
      "resource" => pending.resource,
      "issuer" => pending.issuer,
      "client_id" => pending.client_id,
      "redirect_uri" => pending.redirect_uri,
      "scope" => pending.scope,
      "code_verifier" => pending.code_verifier,
      "token_endpoint" => pending.token_endpoint,
      "created_at" => AshAi.Mcp.OAuth.Serialize.datetime(pending.created_at),
      "iss_parameter_supported" => pending.iss_parameter_supported
    }
  end

  @doc "Builds a pending authorization from a map produced by `to_map/1`."
  @spec from_map(map()) :: t()
  def from_map(%{} = map) do
    %__MODULE__{
      state: map["state"],
      owner: map["owner"],
      server_url: map["server_url"],
      resource: map["resource"],
      issuer: map["issuer"],
      client_id: map["client_id"],
      redirect_uri: map["redirect_uri"],
      scope: map["scope"],
      code_verifier: map["code_verifier"],
      token_endpoint: map["token_endpoint"],
      created_at: AshAi.Mcp.OAuth.Serialize.parse_datetime(map["created_at"]),
      iss_parameter_supported: map["iss_parameter_supported"] == true
    }
  end
end
