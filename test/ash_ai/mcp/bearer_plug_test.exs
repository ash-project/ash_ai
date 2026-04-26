# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.BearerPlugTest do
  use ExUnit.Case, async: false
  import Plug.{Conn, Test}

  alias AshAi.Mcp.BearerPlug
  alias AshAi.Oauth.Jwt

  setup do
    prior = Application.get_env(:ash_ai, AshAi.Oauth)

    Application.put_env(:ash_ai, AshAi.Oauth,
      user_resource: AshAi.Test.OauthUser,
      issuer_url: "https://app.example.com",
      canonical_mcp_url: "https://app.example.com/mcp",
      signing_secret: String.duplicate("x", 64),
      access_token_ttl: 3_600,
      scopes: ["mcp"]
    )

    on_exit(fn ->
      if prior, do: Application.put_env(:ash_ai, AshAi.Oauth, prior), else: Application.delete_env(:ash_ai, AshAi.Oauth)
    end)

    {:ok, user} =
      AshAi.Test.OauthUser
      |> Ash.Changeset.for_create(:create, %{email: "u@example.com"})
      |> Ash.create(authorize?: false)

    %{user: user}
  end

  test "401 with WWW-Authenticate when no token and required?: true" do
    conn = conn(:post, "/mcp", "{}")
    conn = BearerPlug.call(conn, BearerPlug.init(otp_app: :ash_ai, required?: true))

    assert conn.status == 401
    [auth] = get_resp_header(conn, "www-authenticate")
    assert auth =~ ~r/^Bearer resource_metadata="https:\/\/app\.example\.com\/\.well-known\/oauth-protected-resource"$/
  end

  test "passes through with no token when required?: false" do
    conn = conn(:post, "/mcp", "{}")
    conn = BearerPlug.call(conn, BearerPlug.init(otp_app: :ash_ai, required?: false))

    refute conn.halted
  end

  test "401 on bad signature, with error=invalid_token in WWW-Authenticate" do
    conn = conn(:post, "/mcp", "{}") |> put_req_header("authorization", "Bearer not-a-real-jwt")
    conn = BearerPlug.call(conn, BearerPlug.init(otp_app: :ash_ai, required?: true))

    assert conn.status == 401
    [auth] = get_resp_header(conn, "www-authenticate")
    assert auth =~ ~s(error="invalid_token")
  end

  test "accepts case-insensitive Bearer scheme", %{user: user} do
    {:ok, token, _} = Jwt.mint(:ash_ai, sub: user.id, client_id: "c", scope: "mcp")

    for prefix <- ["Bearer", "bearer", "BEARER", "BeArEr"] do
      conn =
        conn(:post, "/mcp", "{}")
        |> put_req_header("authorization", "#{prefix} #{token}")

      conn = BearerPlug.call(conn, BearerPlug.init(otp_app: :ash_ai, required?: true))
      refute conn.halted, "expected #{prefix} prefix to be accepted"
    end
  end

  test "401 on audience mismatch", %{user: user} do
    Application.put_env(:ash_ai, AshAi.Oauth,
      Application.get_env(:ash_ai, AshAi.Oauth)
      |> Keyword.put(:canonical_mcp_url, "https://other.example.com/mcp")
    )

    {:ok, token, _} = Jwt.mint(:ash_ai, sub: user.id, client_id: "c", scope: "mcp")

    Application.put_env(:ash_ai, AshAi.Oauth,
      Application.get_env(:ash_ai, AshAi.Oauth)
      |> Keyword.put(:canonical_mcp_url, "https://app.example.com/mcp")
    )

    conn =
      conn(:post, "/mcp", "{}")
      |> put_req_header("authorization", "Bearer #{token}")

    conn = BearerPlug.call(conn, BearerPlug.init(otp_app: :ash_ai, required?: true))

    assert conn.status == 401
  end

  test "valid token loads actor", %{user: user} do
    {:ok, token, _} = Jwt.mint(:ash_ai, sub: user.id, client_id: "c", scope: "mcp")

    conn =
      conn(:post, "/mcp", "{}")
      |> put_req_header("authorization", "Bearer #{token}")

    conn = BearerPlug.call(conn, BearerPlug.init(otp_app: :ash_ai, required?: true))

    refute conn.halted
    assert Ash.PlugHelpers.get_actor(conn).id == user.id
    assert conn.assigns.oauth_claims["sub"] == user.id
  end
end
