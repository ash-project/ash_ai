# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Oauth.TokenTest do
  use ExUnit.Case, async: false
  import Plug.{Conn, Test}

  alias AshAi.Oauth.{Pkce, Token}

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
      signing_secret: String.duplicate("x", 64),
      access_token_ttl: 3_600,
      refresh_token_ttl: {30, :days},
      scopes: ["mcp"]
    )

    on_exit(fn ->
      if prior, do: Application.put_env(:ash_ai, AshAi.Oauth, prior), else: Application.delete_env(:ash_ai, AshAi.Oauth)
    end)

    {:ok, user} = AshAi.Test.OauthUser |> Ash.Changeset.for_create(:create, %{email: "u@example.com"}) |> Ash.create(authorize?: false)

    {:ok, client} =
      AshAi.Test.OAuthClient
      |> Ash.Changeset.for_create(:register, %{
        client_name: "C",
        redirect_uris: ["https://chatgpt.com/cb"],
        token_endpoint_auth_method: "none",
        scope: "mcp"
      })
      |> Ash.create(authorize?: false)

    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = Pkce.challenge(verifier)

    {:ok, code} =
      AshAi.Test.OAuthAuthorizationCode
      |> Ash.Changeset.for_create(:create, %{
        client_id: client.id,
        user_id: user.id,
        redirect_uri: "https://chatgpt.com/cb",
        code_challenge: challenge,
        scope: "mcp",
        resource_uri: "https://app.example.com/mcp",
        expires_at: DateTime.add(DateTime.utc_now(), 600, :second)
      })
      |> Ash.create(authorize?: false)

    {:ok, user: user, client: client, code: code, verifier: verifier}
  end

  defp post_form(form) do
    body = URI.encode_query(form)

    conn(:post, "/oauth/token", body)
    |> put_req_header("content-type", "application/x-www-form-urlencoded")
    |> Plug.Parsers.call(Plug.Parsers.init(parsers: [:urlencoded], pass: ["*/*"]))
  end

  test "exchanges authorization code for access + refresh tokens", %{client: client, code: code, verifier: verifier} do
    conn = post_form(%{
      "grant_type" => "authorization_code",
      "code" => code.id,
      "redirect_uri" => "https://chatgpt.com/cb",
      "client_id" => client.id,
      "code_verifier" => verifier,
      "resource" => "https://app.example.com/mcp"
    })

    conn = Token.call(conn, Token.init(otp_app: :ash_ai))

    assert conn.status == 200
    body = Jason.decode!(conn.resp_body)
    assert is_binary(body["access_token"])
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 3_600
    assert is_binary(body["refresh_token"])
    assert body["scope"] == "mcp"
    assert get_resp_header(conn, "cache-control") == ["no-store"]
  end

  test "rejects reused authorization code", %{client: client, code: code, verifier: verifier} do
    form = %{
      "grant_type" => "authorization_code",
      "code" => code.id,
      "redirect_uri" => "https://chatgpt.com/cb",
      "client_id" => client.id,
      "code_verifier" => verifier,
      "resource" => "https://app.example.com/mcp"
    }

    Token.call(post_form(form), Token.init(otp_app: :ash_ai))

    conn = Token.call(post_form(form), Token.init(otp_app: :ash_ai))
    assert conn.status == 400
    assert Jason.decode!(conn.resp_body)["error"] == "invalid_grant"
  end

  test "rejects bad PKCE verifier", %{client: client, code: code} do
    conn = post_form(%{
      "grant_type" => "authorization_code",
      "code" => code.id,
      "redirect_uri" => "https://chatgpt.com/cb",
      "client_id" => client.id,
      "code_verifier" => "wrong",
      "resource" => "https://app.example.com/mcp"
    })

    conn = Token.call(conn, Token.init(otp_app: :ash_ai))
    assert conn.status == 400
    assert Jason.decode!(conn.resp_body)["error"] == "invalid_grant"
  end

  test "refresh grant rotates token", %{client: client, code: code, verifier: verifier} do
    initial =
      Token.call(
        post_form(%{
          "grant_type" => "authorization_code",
          "code" => code.id,
          "redirect_uri" => "https://chatgpt.com/cb",
          "client_id" => client.id,
          "code_verifier" => verifier,
          "resource" => "https://app.example.com/mcp"
        }),
        Token.init(otp_app: :ash_ai)
      )

    %{"refresh_token" => refresh} = Jason.decode!(initial.resp_body)

    conn = post_form(%{
      "grant_type" => "refresh_token",
      "refresh_token" => refresh,
      "client_id" => client.id,
      "resource" => "https://app.example.com/mcp"
    })

    conn = Token.call(conn, Token.init(otp_app: :ash_ai))
    assert conn.status == 200
    body = Jason.decode!(conn.resp_body)
    assert is_binary(body["access_token"])
    assert is_binary(body["refresh_token"])
    refute body["refresh_token"] == refresh
  end

  test "reused refresh token revokes the chain", %{client: client, code: code, verifier: verifier} do
    initial =
      Token.call(
        post_form(%{
          "grant_type" => "authorization_code",
          "code" => code.id,
          "redirect_uri" => "https://chatgpt.com/cb",
          "client_id" => client.id,
          "code_verifier" => verifier,
          "resource" => "https://app.example.com/mcp"
        }),
        Token.init(otp_app: :ash_ai)
      )

    %{"refresh_token" => refresh} = Jason.decode!(initial.resp_body)

    refresh_form = %{
      "grant_type" => "refresh_token",
      "refresh_token" => refresh,
      "client_id" => client.id,
      "resource" => "https://app.example.com/mcp"
    }

    Token.call(post_form(refresh_form), Token.init(otp_app: :ash_ai))
    second = Token.call(post_form(refresh_form), Token.init(otp_app: :ash_ai))

    assert second.status == 400
    assert Jason.decode!(second.resp_body)["error"] == "invalid_grant"
  end
end
