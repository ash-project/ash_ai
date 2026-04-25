# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Oauth.JwtTest do
  use ExUnit.Case, async: false

  alias AshAi.Oauth.Jwt

  setup do
    prior = Application.get_env(:ash_ai, AshAi.Oauth)

    Application.put_env(:ash_ai, AshAi.Oauth,
      user_resource: nil,
      issuer_url: "https://app.example.com",
      canonical_mcp_url: "https://app.example.com/mcp",
      signing_secret: String.duplicate("x", 64),
      access_token_ttl: 3_600,
      scopes: ["mcp"]
    )

    on_exit(fn ->
      if prior, do: Application.put_env(:ash_ai, AshAi.Oauth, prior), else: Application.delete_env(:ash_ai, AshAi.Oauth)
    end)

    :ok
  end

  test "mint/2 produces a token with required claims" do
    {:ok, token, claims} =
      Jwt.mint(:ash_ai,
        sub: "user-123",
        client_id: "client-abc",
        scope: "mcp"
      )

    assert is_binary(token)
    assert claims["iss"] == "https://app.example.com"
    assert claims["aud"] == "https://app.example.com/mcp"
    assert claims["sub"] == "user-123"
    assert claims["client_id"] == "client-abc"
    assert claims["scope"] == "mcp"
    assert is_integer(claims["iat"])
    assert is_integer(claims["exp"])
    assert is_binary(claims["jti"])
  end

  test "verify/2 round-trips a freshly minted token" do
    {:ok, token, _} = Jwt.mint(:ash_ai, sub: "u", client_id: "c", scope: "mcp")
    assert {:ok, claims} = Jwt.verify(:ash_ai, token)
    assert claims["sub"] == "u"
  end

  test "verify/2 rejects token with wrong audience" do
    Application.put_env(:ash_ai, AshAi.Oauth,
      Application.get_env(:ash_ai, AshAi.Oauth) |> Keyword.put(:canonical_mcp_url, "https://other.example.com/mcp")
    )

    {:ok, token, _} = Jwt.mint(:ash_ai, sub: "u", client_id: "c", scope: "mcp")

    Application.put_env(:ash_ai, AshAi.Oauth,
      Application.get_env(:ash_ai, AshAi.Oauth) |> Keyword.put(:canonical_mcp_url, "https://app.example.com/mcp")
    )

    assert {:error, :invalid_audience} = Jwt.verify(:ash_ai, token)
  end

  test "verify/2 rejects expired token" do
    {:ok, token, _} = Jwt.mint(:ash_ai, sub: "u", client_id: "c", scope: "mcp", ttl: -1)
    assert {:error, :expired} = Jwt.verify(:ash_ai, token)
  end

  test "verify/2 rejects garbage" do
    assert {:error, _} = Jwt.verify(:ash_ai, "not-a-jwt")
  end
end
