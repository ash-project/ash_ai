# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Oauth.Startup do
  @moduledoc """
  Optional supervisor child that validates `AshAi.Oauth` config at boot.

  Add to your supervision tree:

      children = [
        ...,
        {AshAi.Oauth.Startup, otp_app: :my_app}
      ]

  Will raise on start if required config is missing or invalid. Catches
  typos and missing env vars at boot rather than at first request.
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

    validate_url!(Keyword.fetch!(config, :issuer_url), :issuer_url)
    validate_url!(Keyword.fetch!(config, :canonical_mcp_url), :canonical_mcp_url)

    Enum.each(
      [:user_resource, :client_resource, :authorization_code_resource, :refresh_token_resource, :consent_resource],
      fn key ->
        mod = Keyword.fetch!(config, key)
        Code.ensure_loaded!(mod)
      end
    )

    {:ok, %{otp_app: otp_app}}
  end

  # URI.new/1 actually returns {:error, _} for malformed input; URI.parse/1
  # never errors and accepts e.g. "https:///foo" with an empty host.
  defp validate_url!(url, key) do
    case URI.new(url) do
      {:ok, %URI{scheme: scheme, host: host}} when scheme in ["http", "https"] and is_binary(host) and host != "" ->
        :ok

      _ ->
        raise "AshAi.Oauth #{key} must be a valid http(s) URL with a host: got #{inspect(url)}"
    end
  end
end
