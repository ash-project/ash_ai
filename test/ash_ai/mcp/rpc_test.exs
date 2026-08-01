# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.ServerTest do
  use AshAi.RepoCase, async: false
  import Plug.{Conn, Test}

  alias AshAi.Mcp.Router
  alias AshAi.Mcp.Server
  alias AshAi.Test.Music

  defmodule ClosedAdapter do
    @moduledoc false
    # Minimal adapter that reports the connection as closed, mirroring what a
    # real adapter returns from `chunk/2` when the SSE client has disconnected.
    def chunk(_state, _body), do: {:error, :closed}
  end

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

  describe "GET" do
    test "responds 405: no unsolicited server-to-client messages are offered" do
      conn = conn(:get, "/") |> put_req_header("accept", "text/event-stream")

      response = Router.call(conn, @opts)
      assert response.status == 405
      assert get_resp_header(response, "allow") == ["POST, DELETE"]
    end
  end

  describe "DELETE" do
    test "initialize-era session termination remains supported" do
      response =
        conn(:delete, "/")
        |> put_req_header("mcp-protocol-version", "2025-06-18")
        |> put_req_header("mcp-session-id", "initialize-era-session")
        |> Router.call(@opts)

      assert response.status == 200
    end
  end

  describe "ping" do
    test "responds with an empty result" do
      conn = conn(:post, "/", %{method: "ping", id: "9"})

      response = Router.call(conn, @opts)
      assert response.status == 200

      resp = Jason.decode!(response.resp_body)
      assert resp["id"] == "9"
      assert resp["result"] == %{}
    end
  end

  describe "tool argument transformer" do
    test "rejections use the initialize-era tool-result envelope" do
      transformer = fn %AshAi.Tool{name: :list_artists}, arguments, _context ->
        assert arguments == %{"unexpected" => true}
        {:error, "Expected shape: {}"}
      end

      response =
        conn(:post, "/", %{
          "jsonrpc" => "2.0",
          "id" => "transform_legacy",
          "method" => "tools/call",
          "params" => %{
            "name" => "list_artists",
            "arguments" => %{"unexpected" => true}
          }
        })
        |> Router.call(Keyword.put(@opts, :tool_argument_transformer, transformer))

      assert response.status == 200
      result = Jason.decode!(response.resp_body)["result"]
      refute Map.has_key?(result, "resultType")
      assert result["isError"] == true
      assert result["content"] == [%{"type" => "text", "text" => "Expected shape: {}"}]
    end
  end

  describe "send_sse_event/4" do
    test "writes the event chunks to an open connection" do
      conn =
        conn(:get, "/")
        |> send_chunked(200)
        |> Server.send_sse_event("message", "hello", "1")

      assert conn.resp_body =~ "id: 1\n"
      assert conn.resp_body =~ "event: message\n"
      assert conn.resp_body =~ "data: hello\n\n"
    end

    test "returns the conn without raising when the client has disconnected" do
      conn = %{conn(:get, "/") | adapter: {ClosedAdapter, :closed}, state: :chunked}

      assert %Plug.Conn{} = Server.send_sse_event(conn, "message", "hello", "1")
    end
  end
end
