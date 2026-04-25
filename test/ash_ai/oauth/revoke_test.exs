# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Oauth.RevokeTest do
  use ExUnit.Case, async: false
  import Plug.{Conn, Test}

  alias AshAi.Oauth.Revoke

  setup do
    prior = Application.get_env(:ash_ai, AshAi.Oauth)

    Application.put_env(:ash_ai, AshAi.Oauth,
      user_resource: AshAi.Test.OauthUser,
      client_resource: AshAi.Test.OAuthClient,
      authorization_code_resource: AshAi.Test.OAuthAuthorizationCode,
      refresh_token_resource: AshAi.Test.OAuthRefreshToken,
      consent_resource: AshAi.Test.OAuthConsent,
      issuer_url: "https://app.example.com",
      canonical_mcp_url: "https://app.example.com/mcp",
      signing_secret: "x",
      scopes: ["mcp"],
      refresh_token_ttl: {30, :days}
    )

    on_exit(fn ->
      if prior, do: Application.put_env(:ash_ai, AshAi.Oauth, prior), else: Application.delete_env(:ash_ai, AshAi.Oauth)
    end)

    :ok
  end

  defp post_form(form) do
    body = URI.encode_query(form)

    conn(:post, "/oauth/revoke", body)
    |> put_req_header("content-type", "application/x-www-form-urlencoded")
    |> Plug.Parsers.call(Plug.Parsers.init(parsers: [:urlencoded]))
  end

  test "always returns 200" do
    conn = Revoke.call(post_form(%{"token" => "doesnt-exist"}), Revoke.init(otp_app: :ash_ai))
    assert conn.status == 200
  end

  test "revokes a refresh token by raw value" do
    raw = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
    hash = :crypto.hash(:sha256, raw) |> Base.encode16(case: :lower)

    {:ok, row} =
      AshAi.Test.OAuthRefreshToken
      |> Ash.Changeset.for_create(:issue, %{
        token_hash: hash,
        client_id: Ash.UUIDv7.generate(),
        user_id: Ash.UUIDv7.generate(),
        scope: "mcp",
        resource_uri: "https://app.example.com/mcp",
        expires_at: DateTime.add(DateTime.utc_now(), 86_400, :second)
      })
      |> Ash.create(authorize?: false)

    conn = Revoke.call(post_form(%{"token" => raw}), Revoke.init(otp_app: :ash_ai))
    assert conn.status == 200

    {:ok, reloaded} = Ash.get(AshAi.Test.OAuthRefreshToken, row.id, authorize?: false)
    assert reloaded.revoked_at
  end
end
