# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.ServerTest do
  use AshAi.RepoCase, async: false
  import Plug.{Conn, Test}

  alias AshAi.Mcp.Router
  alias AshAi.Test.Music

  @opts [tools: [:list_artists], otp_app: :ash_ai]

  describe "MCP RPC Protocol" do
    test "initialization creates a session" do
      conn =
        conn(
          :post,
          "/",
          %{
            method: "initialize",
            id: "1",
            params: %{
              client: %{
                name: "test_client",
                version: "1.0.0"
              }
            }
          }
        )

      response = Router.call(conn, @opts)
      assert response.status == 200
      assert get_resp_header(response, "content-type") == ["application/json"]

      session_id = List.first(get_resp_header(response, "mcp-session-id"))
      assert session_id != nil

      resp = Jason.decode!(response.resp_body)
      assert resp["jsonrpc"] == "2.0"
      assert resp["id"] == "1"
      assert resp["result"]["serverInfo"]["name"] == "MCP Server"
    end

    test "handles tool execution requests" do
      # First initialize a session
      conn =
        conn(
          :post,
          "/",
          %{
            method: "initialize",
            id: "1",
            params: %{
              client: %{
                name: "test_client",
                version: "1.0.0"
              }
            }
          }
        )

      response = Router.call(conn, @opts)
      session_id = List.first(get_resp_header(response, "mcp-session-id"))

      # Create an artist to list
      Music.create_artist_after_action!(%{
        name: "Test Artist",
        bio: "A test artist for MCP tools testing"
      })

      # Now try to execute the list_artists tool
      conn =
        conn(
          :post,
          "/",
          %{
            method: "tools/call",
            id: "2",
            params: %{
              name: "list_artists"
            }
          }
        )
        |> put_req_header("mcp-session-id", session_id)

      response = Router.call(conn, @opts)
      assert response.status == 200

      resp = Jason.decode!(response.resp_body)
      assert resp["jsonrpc"] == "2.0"
      assert resp["id"] == "2"
      assert resp["result"] != nil
      assert resp["result"]["isError"] == false
      assert %{"result" => %{"content" => [%{"type" => "text", "text" => text}]}} = resp

      # Check that our test artist is in the results
      artists = Jason.decode!(text)
      assert Enum.any?(artists, fn a -> a["name"] == "Test Artist" end)
    end
  end
end
