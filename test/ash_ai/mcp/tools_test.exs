# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.ToolsTest do
  @moduledoc """
  Tests for MCP tools functionality including tools/list and tools/call endpoints.
  """
  use AshAi.RepoCase, async: false
  import Plug.{Conn, Test}

  alias AshAi.Mcp.Router
  alias AshAi.Test.Music

  @opts [tools: [:list_artists], otp_app: :ash_ai]
  @opts_with_meta [tools: [:list_artists_with_meta], otp_app: :ash_ai]

  describe "tools/list" do
    test "returns available MCP tools" do
      session_id = initialize_and_get_session_id(@opts)

      response = list_tools(session_id, @opts)
      body = decode_response(response)

      assert response.status == 200
      assert body["jsonrpc"] == "2.0"
      assert body["id"] == "list_1"

      assert [%{"name" => "list_artists", "inputSchema" => %{}}] =
               body["result"]["tools"]
    end

    test "includes _meta when tool has metadata" do
      session_id = initialize_and_get_session_id(@opts_with_meta)

      response = list_tools(session_id, @opts_with_meta)
      body = decode_response(response)

      assert [
               %{
                 "_meta" => %{
                   "openai/outputTemplate" => "ui://widget/artists-list.html",
                   "openai/toolInvocation/invoking" => "Loading artists…",
                   "openai/toolInvocation/invoked" => "Artists loaded."
                 }
               }
             ] = body["result"]["tools"]
    end

    test "excludes _meta when tool has no metadata" do
      session_id = initialize_and_get_session_id(@opts)

      response = list_tools(session_id, @opts)
      body = decode_response(response)

      [tool_without_meta] = body["result"]["tools"]

      refute Map.has_key?(tool_without_meta, "_meta")
    end
  end

  describe "tools/call" do
    test "successfully executes a tool" do
      session_id = initialize_and_get_session_id(@opts)

      Music.create_artist_after_action!(%{
        name: "Test Artist",
        bio: "A test artist for MCP tools testing"
      })

      response = call_tool(session_id, "list_artists", %{}, @opts)
      body = decode_response(response)

      assert response.status == 200
      assert body["jsonrpc"] == "2.0"
      assert body["id"] == "call_1"
      assert body["result"]["isError"] == false
      refute body["result"]["_meta"]
      assert %{"result" => %{"content" => [%{"type" => "text", "text" => text}]}} = body
      assert [%{"name" => "Test Artist"}] = Jason.decode!(text)
    end

    test "includes _meta when tool has metadata" do
      session_id = initialize_and_get_session_id(@opts_with_meta)

      Music.create_artist_after_action!(%{
        name: "Test Artist",
        bio: "A test artist for MCP tools testing"
      })

      response = call_tool(session_id, "list_artists_with_meta", %{}, @opts_with_meta)
      body = decode_response(response)

      assert response.status == 200
      assert body["jsonrpc"] == "2.0"
      assert body["id"] == "call_1"
      assert body["result"] != nil
      assert body["result"]["isError"] == false
      assert body["result"]["_meta"] != nil

      assert body["result"]["_meta"]["openai/outputTemplate"] ==
               "ui://widget/artists-list.html"

      assert body["result"]["_meta"]["openai/toolInvocation/invoking"] == "Loading artists…"
      assert body["result"]["_meta"]["openai/toolInvocation/invoked"] == "Artists loaded."
    end

    test "returns error for non-existent tool" do
      session_id = initialize_and_get_session_id(@opts)

      response = call_tool(session_id, "non_existent_tool", %{}, @opts)
      body = decode_response(response)

      assert response.status == 200
      assert body["jsonrpc"] == "2.0"
      assert body["error"]["code"] == -32_602
      assert body["error"]["message"] == "Tool not found: non_existent_tool"
    end
  end

  describe "initialization" do
    test "capabilities include tools" do
      init_response =
        conn(:post, "/", %{
          "method" => "initialize",
          "id" => "init_1",
          "params" => %{"client" => %{"name" => "test_client", "version" => "1.0.0"}}
        })
        |> Router.call(@opts)

      init_body = decode_response(init_response)

      assert init_response.status == 200
      assert init_body["result"]["capabilities"]["tools"]
    end
  end

  describe "integration" do
    test "full flow: initialize -> list -> call" do
      # Step 1: Initialize
      init_response =
        conn(:post, "/", %{
          "method" => "initialize",
          "id" => "init_1",
          "params" => %{"client" => %{"name" => "test_client", "version" => "1.0.0"}}
        })
        |> Router.call(@opts)

      session_id = extract_session_id(init_response)
      init_body = decode_response(init_response)

      assert init_response.status == 200
      assert init_body["result"]["capabilities"]["tools"]

      # Step 2: List tools
      list_response = list_tools(session_id, @opts)
      list_body = decode_response(list_response)

      assert list_response.status == 200
      tools = list_body["result"]["tools"]
      assert length(tools) > 0

      # Step 3: Call a tool from the list
      first_tool = hd(tools)
      tool_name = first_tool["name"]

      # Create test data
      Music.create_artist_after_action!(%{
        name: "Integration Test Artist",
        bio: "An artist for integration testing"
      })

      call_response = call_tool(session_id, tool_name, %{}, @opts)
      call_body = decode_response(call_response)

      assert call_response.status == 200
      assert call_body["result"]["isError"] == false
      assert call_body["result"]["content"]
    end
  end

  # Helper functions

  defp initialize_and_get_session_id(opts) do
    response =
      conn(:post, "/", %{
        "method" => "initialize",
        "id" => "init_1",
        "params" => %{"client" => %{"name" => "test_client", "version" => "1.0.0"}}
      })
      |> Router.call(opts)

    extract_session_id(response)
  end

  defp list_tools(session_id, opts) do
    conn(:post, "/", %{"method" => "tools/list", "id" => "list_1"})
    |> put_req_header("mcp-session-id", session_id)
    |> Router.call(opts)
  end

  defp call_tool(session_id, tool_name, params, opts) do
    request_params = Map.put(params, "name", tool_name)

    conn(:post, "/", %{"method" => "tools/call", "id" => "call_1", "params" => request_params})
    |> put_req_header("mcp-session-id", session_id)
    |> Router.call(opts)
  end

  defp extract_session_id(response) do
    List.first(Plug.Conn.get_resp_header(response, "mcp-session-id"))
  end

  defp decode_response(response) do
    Jason.decode!(response.resp_body)
  end
end
