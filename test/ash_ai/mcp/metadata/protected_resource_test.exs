# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.Metadata.ProtectedResourceTest do
  use ExUnit.Case, async: false
  import Plug.{Conn, Test}

  alias AshAi.Mcp.Metadata.ProtectedResource

  setup do
    prior = Application.get_env(:ash_ai, AshAi.Oauth)

    Application.put_env(:ash_ai, AshAi.Oauth,
      user_resource: nil,
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

  test "returns required RFC 9728 fields" do
    conn = conn(:get, "/.well-known/oauth-protected-resource")
    conn = ProtectedResource.call(conn, ProtectedResource.init(otp_app: :ash_ai))

    assert conn.status == 200
    assert get_resp_header(conn, "content-type") == ["application/json"]

    body = Jason.decode!(conn.resp_body)
    assert body["resource"] == "https://app.example.com/mcp"
    assert body["authorization_servers"] == ["https://app.example.com"]
    assert body["scopes_supported"] == ["mcp"]
    assert body["bearer_methods_supported"] == ["header"]
  end
end
