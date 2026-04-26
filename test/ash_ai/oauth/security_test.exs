# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Oauth.SecurityTest do
  @moduledoc """
  Tests covering the security claims in
  `documentation/topics/mcp-oauth-security.md`:

    - Confused-deputy mitigation: per-client consent prevents a freshly
      DCR-registered attacker client from leveraging another client's
      prior consent.
    - Refresh-token reuse detection: a second refresh attempt with a
      rotated token revokes the entire chain (OAuth 2.1 §4.3.1).
    - CSRF: POST /oauth/authorize without a valid session+token pair is
      rejected with 403.
  """

  use ExUnit.Case, async: false
  import Plug.{Conn, Test}

  alias AshAi.Oauth.{Authorize, Pkce, Token}

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
      authorization_code_ttl: {10, :minutes},
      scopes: ["mcp"]
    )

    on_exit(fn ->
      if prior, do: Application.put_env(:ash_ai, AshAi.Oauth, prior), else: Application.delete_env(:ash_ai, AshAi.Oauth)
    end)

    {:ok, user} =
      AshAi.Test.OauthUser
      |> Ash.Changeset.for_create(:create, %{email: "u@example.com"})
      |> Ash.create(authorize?: false)

    {:ok, user: user}
  end

  defp register_client(name, redirect_uri) do
    {:ok, client} =
      AshAi.Test.OAuthClient
      |> Ash.Changeset.for_create(:register, %{
        client_name: name,
        redirect_uris: [redirect_uri],
        token_endpoint_auth_method: "none",
        scope: "mcp"
      })
      |> Ash.create(authorize?: false)

    client
  end

  defp authorize_query_conn(client_id, redirect_uri, challenge) do
    conn(:get, "/oauth/authorize?" <> URI.encode_query(%{
      "response_type" => "code",
      "client_id" => client_id,
      "redirect_uri" => redirect_uri,
      "code_challenge" => challenge,
      "code_challenge_method" => "S256",
      "scope" => "mcp",
      "state" => "s",
      "resource" => "https://app.example.com/mcp"
    }))
    |> Plug.Conn.fetch_query_params()
  end

  defp post_form(form) do
    body = URI.encode_query(form)

    conn(:post, "/oauth/token", body)
    |> put_req_header("content-type", "application/x-www-form-urlencoded")
    |> Plug.Parsers.call(Plug.Parsers.init(parsers: [:urlencoded], pass: ["*/*"]))
  end

  # ── Confused-deputy ──────────────────────────────────────────────────

  test "consent for one client does not auto-grant for a different client", %{user: user} do
    redirect_uri = "https://shared.example/cb"
    client_a = register_client("Legitimate", redirect_uri)
    attacker = register_client("Attacker", redirect_uri)

    # User previously consented to client_a
    AshAi.Test.OAuthConsent
    |> Ash.Changeset.for_create(:grant, %{user_id: user.id, client_id: client_a.id, scope: "mcp"})
    |> Ash.create!(authorize?: false)

    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = Pkce.challenge(verifier)

    # Attacker (client B) requests authorize. Even though A's consent exists
    # and the redirect_uri is the same, B must surface its own consent screen
    # — it must NOT auto-redirect with a code.
    conn =
      authorize_query_conn(attacker.id, redirect_uri, challenge)
      |> Ash.PlugHelpers.set_actor(user)

    conn = Authorize.call(conn, Authorize.init(otp_app: :ash_ai))

    assert conn.status == 200, "attacker should hit consent screen, not auto-issue code"
    assert conn.resp_body =~ "Authorize access"
    assert conn.resp_body =~ "Attacker"
    refute get_resp_header(conn, "location") |> Enum.any?(&String.contains?(&1, "code="))
  end

  # ── Refresh rotation reuse detection ─────────────────────────────────

  test "second use of a rotated refresh token revokes the entire chain", %{user: user} do
    client = register_client("ChainTest", "https://chain.example/cb")

    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = Pkce.challenge(verifier)

    {:ok, code} =
      AshAi.Test.OAuthAuthorizationCode
      |> Ash.Changeset.for_create(:create, %{
        client_id: client.id,
        user_id: user.id,
        redirect_uri: "https://chain.example/cb",
        code_challenge: challenge,
        scope: "mcp",
        resource_uri: "https://app.example.com/mcp",
        expires_at: DateTime.add(DateTime.utc_now(), 600, :second)
      })
      |> Ash.create(authorize?: false)

    initial =
      Token.call(
        post_form(%{
          "grant_type" => "authorization_code",
          "code" => code.id,
          "redirect_uri" => "https://chain.example/cb",
          "client_id" => client.id,
          "code_verifier" => verifier,
          "resource" => "https://app.example.com/mcp"
        }),
        Token.init(otp_app: :ash_ai)
      )

    %{"refresh_token" => first_refresh} = Jason.decode!(initial.resp_body)

    # First refresh succeeds, returns a new (rotated) refresh token
    rotation =
      Token.call(
        post_form(%{
          "grant_type" => "refresh_token",
          "refresh_token" => first_refresh,
          "client_id" => client.id,
          "resource" => "https://app.example.com/mcp"
        }),
        Token.init(otp_app: :ash_ai)
      )

    assert rotation.status == 200
    %{"refresh_token" => second_refresh} = Jason.decode!(rotation.resp_body)
    refute second_refresh == first_refresh

    # Reuse the now-rotated first_refresh — should fail and revoke the chain
    reuse =
      Token.call(
        post_form(%{
          "grant_type" => "refresh_token",
          "refresh_token" => first_refresh,
          "client_id" => client.id,
          "resource" => "https://app.example.com/mcp"
        }),
        Token.init(otp_app: :ash_ai)
      )

    assert reuse.status == 400
    assert Jason.decode!(reuse.resp_body)["error"] == "invalid_grant"

    # The descendant token (second_refresh) must now be revoked too — this
    # is the spec-required response to a suspected token theft.
    chain_check =
      Token.call(
        post_form(%{
          "grant_type" => "refresh_token",
          "refresh_token" => second_refresh,
          "client_id" => client.id,
          "resource" => "https://app.example.com/mcp"
        }),
        Token.init(otp_app: :ash_ai)
      )

    assert chain_check.status == 400, "descendant of reused chain should be unusable"
  end

  # ── CSRF ─────────────────────────────────────────────────────────────

  test "POST /oauth/authorize without _csrf_token is rejected", %{user: user} do
    client = register_client("CsrfTest", "https://csrf.example/cb")
    challenge = Pkce.challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")

    conn =
      conn(:post, "/oauth/authorize", %{
        "action" => "approve",
        "response_type" => "code",
        "client_id" => client.id,
        "redirect_uri" => "https://csrf.example/cb",
        "code_challenge" => challenge,
        "code_challenge_method" => "S256",
        "scope" => "mcp",
        "state" => "s",
        "resource" => "https://app.example.com/mcp"
        # Note: no _csrf_token
      })
      |> Plug.Test.init_test_session(%{})
      |> Plug.Conn.fetch_query_params()
      |> Ash.PlugHelpers.set_actor(user)

    # skip_csrf?: false (the production default)
    conn = Authorize.call(conn, Authorize.init(otp_app: :ash_ai))

    assert conn.status == 403
  end

  test "POST /oauth/authorize with junk _csrf_token is rejected", %{user: user} do
    client = register_client("CsrfTest2", "https://csrf2.example/cb")
    challenge = Pkce.challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")

    conn =
      conn(:post, "/oauth/authorize", %{
        "_csrf_token" => "this-is-not-a-real-csrf-token",
        "action" => "approve",
        "response_type" => "code",
        "client_id" => client.id,
        "redirect_uri" => "https://csrf2.example/cb",
        "code_challenge" => challenge,
        "code_challenge_method" => "S256",
        "scope" => "mcp",
        "state" => "s",
        "resource" => "https://app.example.com/mcp"
      })
      |> Plug.Test.init_test_session(%{"_csrf_token" => "different-session-token"})
      |> Plug.Conn.fetch_query_params()
      |> Ash.PlugHelpers.set_actor(user)

    conn = Authorize.call(conn, Authorize.init(otp_app: :ash_ai))

    assert conn.status == 403
  end
end
