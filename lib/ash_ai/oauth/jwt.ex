# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Oauth.Jwt do
  @moduledoc """
  Mint and verify OAuth 2.1 access tokens for the MCP server.

  Uses HS256 with a shared secret. Audience is bound to the canonical MCP URL
  per RFC 8707. We use Joken directly rather than `AshAuthentication.Jwt`
  because we need explicit control over the audience claim.
  """

  alias AshAi.Oauth.Config

  @signer_alg "HS256"

  @doc """
  Mint a new access token.

  Required keys: `:sub`, `:client_id`, `:scope`.
  Optional: `:ttl` (seconds, defaults to `access_token_ttl` config).
  """
  @spec mint(atom(), keyword()) :: {:ok, String.t(), map()} | {:error, term()}
  def mint(otp_app, opts) do
    sub = Keyword.fetch!(opts, :sub)
    client_id = Keyword.fetch!(opts, :client_id)
    scope = Keyword.fetch!(opts, :scope)
    ttl = Keyword.get(opts, :ttl, Config.access_token_ttl(otp_app))
    now = System.system_time(:second)

    claims = %{
      "iss" => Config.issuer_url(otp_app),
      "sub" => to_string(sub),
      "aud" => Config.canonical_mcp_url(otp_app),
      "client_id" => to_string(client_id),
      "scope" => scope,
      "iat" => now,
      "nbf" => now,
      "exp" => now + ttl,
      "jti" => Ash.UUIDv7.generate()
    }

    with {:ok, secret} <- secret(otp_app),
         signer <- Joken.Signer.create(@signer_alg, secret),
         {:ok, token, _claims} <- Joken.encode_and_sign(claims, signer) do
      {:ok, token, claims}
    end
  end

  @doc """
  Verify a token's signature, issuer, audience, and expiry.

  Returns `{:ok, claims}` on success or `{:error, reason}` on failure.
  """
  @spec verify(atom(), String.t()) :: {:ok, map()} | {:error, term()}
  def verify(otp_app, token) when is_binary(token) do
    with {:ok, secret} <- secret(otp_app),
         signer <- Joken.Signer.create(@signer_alg, secret),
         {:ok, claims} <- Joken.verify(token, signer),
         :ok <- check_iss(claims, otp_app),
         :ok <- check_aud(claims, otp_app),
         :ok <- check_exp(claims) do
      {:ok, claims}
    end
  end

  def verify(_, _), do: {:error, :invalid_token}

  defp secret(otp_app) do
    case Config.signing_secret(otp_app) do
      raw when is_binary(raw) -> {:ok, raw}
      {mod, opts} when is_atom(mod) -> mod.secret_for([], nil, opts, %{otp_app: otp_app})
      other -> {:error, {:invalid_signing_secret, other}}
    end
  end

  defp check_iss(%{"iss" => iss}, otp_app) do
    if iss == Config.issuer_url(otp_app), do: :ok, else: {:error, :invalid_issuer}
  end

  defp check_iss(_, _), do: {:error, :invalid_issuer}

  defp check_aud(%{"aud" => aud}, otp_app) do
    expected = Config.canonical_mcp_url(otp_app)

    cond do
      aud == expected -> :ok
      is_list(aud) and expected in aud -> :ok
      true -> {:error, :invalid_audience}
    end
  end

  defp check_aud(_, _), do: {:error, :invalid_audience}

  defp check_exp(%{"exp" => exp}) when is_integer(exp) do
    if System.system_time(:second) < exp, do: :ok, else: {:error, :expired}
  end

  defp check_exp(_), do: {:error, :missing_exp}
end
