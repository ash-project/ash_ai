# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Oauth.Config do
  @moduledoc """
  Thin wrapper around `Application.get_env/2` for OAuth configuration.

  Reads `config :my_app, AshAi.Oauth, ...` and normalizes values
  (URL canonicalization, TTL → seconds).

  All functions take the user's `otp_app` atom and read keys from the
  `AshAi.Oauth` namespace.
  """

  @ttl_units %{second: 1, seconds: 1, minute: 60, minutes: 60, hour: 3_600, hours: 3_600, day: 86_400, days: 86_400}

  @spec user_resource(atom()) :: module()
  def user_resource(otp_app), do: fetch!(otp_app, :user_resource)

  @spec issuer_url(atom()) :: String.t()
  def issuer_url(otp_app), do: otp_app |> fetch!(:issuer_url) |> normalize_url()

  @spec canonical_mcp_url(atom()) :: String.t()
  def canonical_mcp_url(otp_app), do: otp_app |> fetch!(:canonical_mcp_url) |> normalize_url()

  @spec signing_secret(atom()) :: term()
  def signing_secret(otp_app), do: fetch!(otp_app, :signing_secret)

  @spec client_resource(atom()) :: module()
  def client_resource(otp_app), do: fetch!(otp_app, :client_resource)

  @spec authorization_code_resource(atom()) :: module()
  def authorization_code_resource(otp_app), do: fetch!(otp_app, :authorization_code_resource)

  @spec refresh_token_resource(atom()) :: module()
  def refresh_token_resource(otp_app), do: fetch!(otp_app, :refresh_token_resource)

  @spec consent_resource(atom()) :: module()
  def consent_resource(otp_app), do: fetch!(otp_app, :consent_resource)

  @spec access_token_ttl(atom()) :: pos_integer()
  def access_token_ttl(otp_app), do: ttl(otp_app, :access_token_ttl, {1, :hour})

  @spec refresh_token_ttl(atom()) :: pos_integer()
  def refresh_token_ttl(otp_app), do: ttl(otp_app, :refresh_token_ttl, {30, :days})

  @spec authorization_code_ttl(atom()) :: pos_integer()
  def authorization_code_ttl(otp_app), do: ttl(otp_app, :authorization_code_ttl, {10, :minutes})

  @spec scopes(atom()) :: [String.t()]
  def scopes(otp_app), do: get(otp_app, :scopes, ["mcp"])

  @spec consent_template(atom()) :: module()
  def consent_template(otp_app), do: get(otp_app, :consent_template, AshAi.Oauth.ConsentView)

  @spec dcr_always_return_client_secret?(atom()) :: boolean()
  def dcr_always_return_client_secret?(otp_app),
    do: get(otp_app, :dcr_always_return_client_secret, false)

  @doc """
  Path users are redirected to when they hit `/oauth/authorize` without a
  session. Defaults to `nil`, in which case the plug returns `401`. Set to
  e.g. `"/sign-in"` to redirect to the AshAuthentication sign-in route.

  The original authorization request (full query string) is appended as
  `?return_to=...` so the sign-in flow can return the user to `/oauth/authorize`
  after success.
  """
  @spec sign_in_path(atom()) :: String.t() | nil
  def sign_in_path(otp_app), do: get(otp_app, :sign_in_path, nil)

  @spec all(atom()) :: keyword()
  def all(otp_app) do
    case Application.get_env(otp_app, AshAi.Oauth) do
      nil -> raise "AshAi.Oauth not configured for :#{otp_app}. Add `config :#{otp_app}, AshAi.Oauth, ...` to runtime.exs."
      kw -> kw
    end
  end

  defp fetch!(otp_app, key) do
    case all(otp_app) |> Keyword.fetch(key) do
      {:ok, value} -> value
      :error -> raise "AshAi.Oauth config key #{inspect(key)} missing for :#{otp_app}"
    end
  end

  defp get(otp_app, key, default) do
    case Application.get_env(otp_app, AshAi.Oauth) do
      nil -> default
      kw -> Keyword.get(kw, key, default)
    end
  end

  defp ttl(otp_app, key, default) do
    case get(otp_app, key, default) do
      seconds when is_integer(seconds) -> seconds
      {n, unit} when is_integer(n) and is_map_key(@ttl_units, unit) -> n * Map.fetch!(@ttl_units, unit)
      other -> raise "Invalid TTL config #{inspect(key)} for :#{otp_app}: #{inspect(other)}"
    end
  end

  @doc """
  Normalize a URL: lowercase scheme + host, strip trailing slash, no fragment.

  Used internally on configured URLs and exposed for normalizing inbound
  `resource` parameters before equality comparison (RFC 8707 §2).
  """
  @spec normalize_url(String.t()) :: String.t()
  def normalize_url(url) when is_binary(url) do
    uri = URI.parse(url)

    %URI{
      scheme: String.downcase(uri.scheme || "https"),
      host: uri.host && String.downcase(uri.host),
      port: uri.port,
      path: uri.path && String.trim_trailing(uri.path, "/")
    }
    |> URI.to_string()
    |> String.trim_trailing("/")
  end

  def normalize_url(_), do: ""
end
