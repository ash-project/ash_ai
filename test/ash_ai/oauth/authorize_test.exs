# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Oauth.AuthorizeTest do
  use ExUnit.Case, async: false
  import Plug.{Conn, Test}

  alias AshAi.Oauth.{Authorize, Pkce}

  setup do
    prior = Application.get_env(:ash_ai, AshAi.Oauth)

    Application.put_env(:ash_ai, AshAi.Oauth,
      user_resource: AshAi.Test.OauthUser,
      client_resource: AshAi.Test.OAuthClient,
      authorization_code_resource: AshAi.Test.OAuthAuthorizationCode,
      consent_resource: AshAi.Test.OAuthConsent,
      issuer_url: "https://app.example.com",
      canonical_mcp_url: "https://app.example.com/mcp",
      signing_secret: "x",
      scopes: ["mcp"],
      authorization_code_ttl: {10, :minutes}
    )

    on_exit(fn ->
      if prior, do: Application.put_env(:ash_ai, AshAi.Oauth, prior), else: Application.delete_env(:ash_ai, AshAi.Oauth)
    end)

    {:ok, user} =
      AshAi.Test.OauthUser
      |> Ash.Changeset.for_create(:create, %{email: "u@example.com"})
      |> Ash.create(authorize?: false)

    {:ok, client} =
      AshAi.Test.OAuthClient
      |> Ash.Changeset.for_create(:register, %{
        client_name: "Test Client",
        redirect_uris: ["https://chatgpt.com/cb"],
        token_endpoint_auth_method: "none",
        scope: "mcp"
      })
      |> Ash.create(authorize?: false)

    {:ok, user: user, client: client}
  end

  defp authorize_conn(params) do
    conn(:get, "/oauth/authorize?" <> URI.encode_query(params))
    |> Plug.Conn.fetch_query_params()
  end

  defp put_actor(conn, user) do
    Ash.PlugHelpers.set_actor(conn, user)
  end

  test "GET renders consent screen for authenticated user, no prior consent", %{user: user, client: client} do
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = Pkce.challenge(verifier)

    conn =
      authorize_conn(%{
        "response_type" => "code",
        "client_id" => client.id,
        "redirect_uri" => "https://chatgpt.com/cb",
        "code_challenge" => challenge,
        "code_challenge_method" => "S256",
        "scope" => "mcp",
        "state" => "abc",
        "resource" => "https://app.example.com/mcp"
      })
      |> put_actor(user)

    conn = Authorize.call(conn, Authorize.init(otp_app: :ash_ai))

    assert conn.status == 200
    assert conn.resp_body =~ "Authorize access"
    assert conn.resp_body =~ "Test Client"
  end

  test "GET issues code immediately when consent already exists", %{user: user, client: client} do
    AshAi.Test.OAuthConsent
    |> Ash.Changeset.for_create(:grant, %{user_id: user.id, client_id: client.id, scope: "mcp"})
    |> Ash.create!(authorize?: false)

    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = Pkce.challenge(verifier)

    conn =
      authorize_conn(%{
        "response_type" => "code",
        "client_id" => client.id,
        "redirect_uri" => "https://chatgpt.com/cb",
        "code_challenge" => challenge,
        "code_challenge_method" => "S256",
        "scope" => "mcp",
        "state" => "abc",
        "resource" => "https://app.example.com/mcp"
      })
      |> put_actor(user)

    conn = Authorize.call(conn, Authorize.init(otp_app: :ash_ai))

    assert conn.status == 302
    [location] = get_resp_header(conn, "location")
    assert location =~ "https://chatgpt.com/cb?code="
    assert location =~ "state=abc"
  end

  test "GET 400 on plain code_challenge_method", %{user: user, client: client} do
    conn =
      authorize_conn(%{
        "response_type" => "code",
        "client_id" => client.id,
        "redirect_uri" => "https://chatgpt.com/cb",
        "code_challenge" => "x",
        "code_challenge_method" => "plain",
        "scope" => "mcp",
        "state" => "abc",
        "resource" => "https://app.example.com/mcp"
      })
      |> put_actor(user)

    conn = Authorize.call(conn, Authorize.init(otp_app: :ash_ai))
    assert conn.status == 400
  end

  test "GET 400 on redirect_uri mismatch", %{user: user, client: client} do
    conn =
      authorize_conn(%{
        "response_type" => "code",
        "client_id" => client.id,
        "redirect_uri" => "https://attacker.example/cb",
        "code_challenge" => "x",
        "code_challenge_method" => "S256",
        "scope" => "mcp",
        "state" => "abc",
        "resource" => "https://app.example.com/mcp"
      })
      |> put_actor(user)

    conn = Authorize.call(conn, Authorize.init(otp_app: :ash_ai))
    assert conn.status == 400
  end

  test "GET 401 redirects to login when no actor", %{client: client} do
    conn =
      authorize_conn(%{
        "response_type" => "code",
        "client_id" => client.id,
        "redirect_uri" => "https://chatgpt.com/cb",
        "code_challenge" => "x",
        "code_challenge_method" => "S256",
        "scope" => "mcp",
        "state" => "abc",
        "resource" => "https://app.example.com/mcp"
      })

    conn = Authorize.call(conn, Authorize.init(otp_app: :ash_ai))
    assert conn.status == 401
  end

  test "POST approve issues code and redirects", %{user: user, client: client} do
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = Pkce.challenge(verifier)

    conn =
      conn(:post, "/oauth/authorize", %{
        "action" => "approve",
        "response_type" => "code",
        "client_id" => client.id,
        "redirect_uri" => "https://chatgpt.com/cb",
        "code_challenge" => challenge,
        "code_challenge_method" => "S256",
        "scope" => "mcp",
        "state" => "abc",
        "resource" => "https://app.example.com/mcp"
      })
      |> Plug.Conn.fetch_query_params()
      |> put_actor(user)

    conn = Authorize.call(conn, Authorize.init(otp_app: :ash_ai, skip_csrf?: true))

    assert conn.status == 302
    [location] = get_resp_header(conn, "location")
    assert location =~ "https://chatgpt.com/cb?code="
    assert location =~ "state=abc"

    consents = AshAi.Test.OAuthConsent |> Ash.read!(authorize?: false)
    assert length(consents) == 1
  end

  test "POST deny redirects with error=access_denied", %{user: user, client: client} do
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = Pkce.challenge(verifier)

    conn =
      conn(:post, "/oauth/authorize", %{
        "action" => "deny",
        "response_type" => "code",
        "client_id" => client.id,
        "redirect_uri" => "https://chatgpt.com/cb",
        "code_challenge" => challenge,
        "code_challenge_method" => "S256",
        "scope" => "mcp",
        "state" => "abc",
        "resource" => "https://app.example.com/mcp"
      })
      |> Plug.Conn.fetch_query_params()
      |> put_actor(user)

    conn = Authorize.call(conn, Authorize.init(otp_app: :ash_ai, skip_csrf?: true))

    assert conn.status == 302
    [location] = get_resp_header(conn, "location")
    assert location =~ "https://chatgpt.com/cb?error=access_denied"
    assert location =~ "state=abc"
  end
end
