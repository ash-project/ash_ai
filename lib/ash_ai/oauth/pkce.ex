# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Oauth.Pkce do
  @moduledoc """
  PKCE S256 helpers per RFC 7636.

  We only support S256 — `plain` is rejected by `/oauth/authorize`.
  """

  @doc """
  Compute the S256 code challenge for a verifier.

  challenge = base64url(sha256(verifier))
  """
  @spec challenge(String.t()) :: String.t()
  def challenge(verifier) when is_binary(verifier) do
    :sha256
    |> :crypto.hash(verifier)
    |> Base.url_encode64(padding: false)
  end

  @doc """
  Constant-time comparison of `verifier` against a stored `challenge`.

  Returns `:ok` if they match, `:error` otherwise. Bad input shapes return
  `:error` rather than crashing.
  """
  @spec verify(String.t() | nil, String.t() | nil) :: :ok | :error
  def verify(verifier, challenge) when is_binary(verifier) and is_binary(challenge) do
    expected = challenge(verifier)

    if Plug.Crypto.secure_compare(expected, challenge) do
      :ok
    else
      :error
    end
  end

  def verify(_, _), do: :error
end
