# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Oauth.RegisterTest do
  use ExUnit.Case, async: false
  import Plug.{Conn, Test}

  alias AshAi.Oauth.Register

  setup do
    prior = Application.get_env(:ash_ai, AshAi.Oauth)

    Application.put_env(:ash_ai, AshAi.Oauth,
      user_resource: AshAi.Test.OauthUser,
      client_resource: AshAi.Test.OAuthClient,
      issuer_url: "https://app.example.com",
      canonical_mcp_url: "https://app.example.com/mcp",
      signing_secret: "x",
      scopes: ["mcp"]
    )

    on_exit(fn ->
      if prior, do: Application.put_env(:ash_ai, AshAi.Oauth, prior), else: Application.delete_env(:ash_ai, AshAi.Oauth)
    end)

    :ok
  end

  defp post_json(body) do
    conn(:post, "/oauth/register", Jason.encode!(body))
    |> put_req_header("content-type", "application/json")
    |> Plug.Parsers.call(Plug.Parsers.init(parsers: [:json], json_decoder: Jason))
  end

  test "201 + client_id for valid public client registration" do
    conn = post_json(%{
      "client_name" => "ChatGPT",
      "redirect_uris" => ["https://chatgpt.com/connector/oauth/abc"],
      "token_endpoint_auth_method" => "none"
    })

    conn = Register.call(conn, Register.init(otp_app: :ash_ai))

    assert conn.status == 201
    body = Jason.decode!(conn.resp_body)
    assert is_binary(body["client_id"])
    assert body["client_name"] == "ChatGPT"
    assert body["redirect_uris"] == ["https://chatgpt.com/connector/oauth/abc"]
    assert body["token_endpoint_auth_method"] == "none"
    refute Map.has_key?(body, "client_secret")
  end

  test "400 invalid_redirect_uri when redirect uses http (non-localhost)" do
    conn = post_json(%{
      "client_name" => "Bad",
      "redirect_uris" => ["http://attacker.example/callback"],
      "token_endpoint_auth_method" => "none"
    })

    conn = Register.call(conn, Register.init(otp_app: :ash_ai))

    assert conn.status == 400
    body = Jason.decode!(conn.resp_body)
    assert body["error"] == "invalid_redirect_uri"
  end

  test "allows http://localhost redirect URIs" do
    conn = post_json(%{
      "client_name" => "Dev",
      "redirect_uris" => ["http://localhost:3000/cb"],
      "token_endpoint_auth_method" => "none"
    })

    conn = Register.call(conn, Register.init(otp_app: :ash_ai))
    assert conn.status == 201
  end

  test "400 invalid_client_metadata when redirect_uris missing" do
    conn = post_json(%{"client_name" => "X"})

    conn = Register.call(conn, Register.init(otp_app: :ash_ai))

    assert conn.status == 400
    body = Jason.decode!(conn.resp_body)
    assert body["error"] == "invalid_client_metadata"
  end

  test "returns empty client_secret when dcr_always_return_client_secret enabled" do
    Application.put_env(:ash_ai, AshAi.Oauth,
      Application.get_env(:ash_ai, AshAi.Oauth)
      |> Keyword.put(:dcr_always_return_client_secret, true)
    )

    conn = post_json(%{
      "client_name" => "ChatGPT",
      "redirect_uris" => ["https://chatgpt.com/connector/oauth/abc"],
      "token_endpoint_auth_method" => "none"
    })

    conn = Register.call(conn, Register.init(otp_app: :ash_ai))
    assert conn.status == 201
    body = Jason.decode!(conn.resp_body)
    assert body["client_secret"] == ""
  end
end
