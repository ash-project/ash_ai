# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Oauth.Application do
  @moduledoc """
  Optional supervisor child that validates `AshAi.Oauth` config at boot.

  Add to your supervision tree:

      children = [
        ...,
        {AshAi.Oauth.Application, otp_app: :my_app}
      ]

  Will raise on start if required config is missing or invalid.
  """

  use GenServer

  @required_keys [
    :user_resource,
    :issuer_url,
    :canonical_mcp_url,
    :signing_secret,
    :client_resource,
    :authorization_code_resource,
    :refresh_token_resource,
    :consent_resource
  ]

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(opts) do
    otp_app = Keyword.fetch!(opts, :otp_app)

    config =
      case Application.get_env(otp_app, AshAi.Oauth) do
        nil -> raise "AshAi.Oauth not configured for :#{otp_app}"
        kw -> kw
      end

    Enum.each(@required_keys, fn key ->
      unless Keyword.has_key?(config, key) do
        raise "AshAi.Oauth missing required config key #{inspect(key)} for :#{otp_app}"
      end
    end)

    URI.parse(Keyword.fetch!(config, :issuer_url)) |> validate_uri(:issuer_url)
    URI.parse(Keyword.fetch!(config, :canonical_mcp_url)) |> validate_uri(:canonical_mcp_url)

    Enum.each(
      [:user_resource, :client_resource, :authorization_code_resource, :refresh_token_resource, :consent_resource],
      fn key ->
        mod = Keyword.fetch!(config, key)
        Code.ensure_loaded!(mod)
      end
    )

    {:ok, %{otp_app: otp_app}}
  end

  defp validate_uri(%URI{scheme: scheme, host: host}, _key) when scheme in ["http", "https"] and is_binary(host),
    do: :ok

  defp validate_uri(uri, key),
    do: raise("AshAi.Oauth #{key} must be a valid http(s) URL with a host: got #{inspect(uri)}")
end
