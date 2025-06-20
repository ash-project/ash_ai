defmodule AshAi.Mcp.ServerTest do
  use AshAi.RepoCase, async: false
  import Plug.{Conn, Test}

  alias AshAi.Mcp.Router
  alias AshAi.Test.Music

  @opts [tools: [:list_artists], otp_app: :ash_ai]

  describe "MCP RPC Protocol" do
    test "initialization creates a session" do
      body = Jason.encode!(%{
        "jsonrpc" => "2.0",
        "method" => "initialize",
        "id" => "1",
        "params" => %{
          "clientInfo" => %{
            "name" => "test_client",
            "version" => "1.0.0"
          }
        }
      })

      conn =
        conn(:post, "/", body)
        |> put_req_header("content-type", "application/json")

      response = Router.call(conn, @opts)
      assert response.status == 200
      assert ["application/json" <> _] = get_resp_header(response, "content-type")

      session_id = List.first(get_resp_header(response, "mcp-session-id"))
      assert session_id != nil

      resp = Jason.decode!(response.resp_body)
      assert resp["jsonrpc"] == "2.0"
      assert resp["id"] == "1"
      assert resp["result"]["serverInfo"]["name"] == "AshAi MCP Server"
    end

    test "handles tool execution requests" do
      # First initialize a session
      init_body = Jason.encode!(%{
        "jsonrpc" => "2.0",
        "method" => "initialize",
        "id" => "1",
        "params" => %{
          "clientInfo" => %{
            "name" => "test_client",
            "version" => "1.0.0"
          }
        }
      })

      conn =
        conn(:post, "/", init_body)
        |> put_req_header("content-type", "application/json")

      response = Router.call(conn, @opts)
      session_id = List.first(get_resp_header(response, "mcp-session-id"))

      # Create an artist to list
      Music.create_artist_after_action!(%{
        name: "Test Artist",
        bio: "A test artist for MCP tools testing"
      })

      # Now try to execute the list_artists tool
      call_body = Jason.encode!(%{
        "jsonrpc" => "2.0",
        "method" => "tools/call",
        "id" => "2",
        "params" => %{
          "name" => "list_artists"
        }
      })

      conn =
        conn(:post, "/", call_body)
        |> put_req_header("content-type", "application/json")
        |> put_req_header("mcp-session-id", session_id || "default-session")

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
