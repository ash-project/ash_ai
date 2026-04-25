# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Oauth.ConfigTest do
  use ExUnit.Case, async: false

  alias AshAi.Oauth.Config

  setup do
    prior = Application.get_env(:ash_ai, AshAi.Oauth)

    Application.put_env(:ash_ai, AshAi.Oauth,
      user_resource: SomeApp.User,
      issuer_url: "https://app.example.com",
      canonical_mcp_url: "https://app.example.com/mcp",
      access_token_ttl: {1, :hour},
      refresh_token_ttl: {30, :days},
      authorization_code_ttl: {10, :minutes},
      scopes: ["mcp"]
    )

    on_exit(fn ->
      if prior do
        Application.put_env(:ash_ai, AshAi.Oauth, prior)
      else
        Application.delete_env(:ash_ai, AshAi.Oauth)
      end
    end)
  end

  test "user_resource/1" do
    assert Config.user_resource(:ash_ai) == SomeApp.User
  end

  test "issuer_url/1 normalizes to no trailing slash" do
    Application.put_env(:ash_ai, AshAi.Oauth,
      Application.get_env(:ash_ai, AshAi.Oauth)
      |> Keyword.put(:issuer_url, "https://app.example.com/")
    )

    assert Config.issuer_url(:ash_ai) == "https://app.example.com"
  end

  test "canonical_mcp_url/1 normalizes lowercase scheme/host, drops trailing slash" do
    Application.put_env(:ash_ai, AshAi.Oauth,
      Application.get_env(:ash_ai, AshAi.Oauth)
      |> Keyword.put(:canonical_mcp_url, "HTTPS://APP.EXAMPLE.COM/mcp/")
    )

    assert Config.canonical_mcp_url(:ash_ai) == "https://app.example.com/mcp"
  end

  test "access_token_ttl/1 returns seconds" do
    assert Config.access_token_ttl(:ash_ai) == 3_600
  end

  test "scopes/1 defaults to [\"mcp\"]" do
    assert Config.scopes(:ash_ai) == ["mcp"]
  end

  test "fetch!/2 raises with helpful message when key missing" do
    Application.delete_env(:ash_ai, AshAi.Oauth)

    assert_raise RuntimeError, ~r/AshAi.Oauth not configured/, fn ->
      Config.user_resource(:ash_ai)
    end
  end
end
