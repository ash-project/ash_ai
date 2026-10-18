# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.ToolAnnotationsTest do
  @moduledoc """
  Tools carry the MCP `title` and `annotations` (readOnlyHint, destructiveHint,
  idempotentHint, openWorldHint) in `tools/list`, and only the hints that were set.
  """
  use AshAi.RepoCase, async: false
  import Plug.{Conn, Test}

  alias AshAi.Mcp.Router
  alias AshAi.Tool

  @opts [otp_app: :ash_ai]

  describe "Tool.annotations/1" do
    test "maps the set hints to the specification's names and drops the rest" do
      assert Tool.annotations(%Tool{annotations: [read_only?: true, open_world?: false]}) ==
               %{"readOnlyHint" => true, "openWorldHint" => false}

      assert Tool.annotations(%Tool{annotations: [destructive?: true]}) ==
               %{"destructiveHint" => true}
    end

    test "is nil when nothing was set" do
      assert Tool.annotations(%Tool{annotations: []}) == nil
      assert Tool.annotations(%Tool{annotations: nil}) == nil
    end
  end

  describe "tools/list" do
    test "includes title and annotations when set, and only the hints that were set" do
      session_id = initialize(@opts)

      tools =
        list_tools(session_id,
          tools: [:list_artists_annotated, :create_artist_annotated, :list_artists],
          otp_app: :ash_ai
        )

      annotated = Enum.find(tools, &(&1["name"] == "list_artists_annotated"))
      assert annotated["title"] == "List artists"
      assert annotated["annotations"] == %{"readOnlyHint" => true, "openWorldHint" => false}

      created = Enum.find(tools, &(&1["name"] == "create_artist_annotated"))
      refute Map.has_key?(created, "title")
      assert created["annotations"] == %{"destructiveHint" => false, "idempotentHint" => false}
    end

    test "omits both keys for a tool that sets neither" do
      session_id = initialize(@opts)
      [plain] = list_tools(session_id, tools: [:list_artists], otp_app: :ash_ai)

      refute Map.has_key?(plain, "title")
      refute Map.has_key?(plain, "annotations")
    end
  end

  defp initialize(opts) do
    conn(:post, "/", %{
      "jsonrpc" => "2.0",
      "method" => "initialize",
      "id" => "init",
      "params" => %{
        "protocolVersion" => "2025-06-18",
        "capabilities" => %{},
        "clientInfo" => %{"name" => "test_client", "version" => "1.0.0"}
      }
    })
    |> Router.call(opts)
    |> get_resp_header("mcp-session-id")
    |> List.first()
  end

  defp list_tools(session_id, opts) do
    conn(:post, "/", %{"jsonrpc" => "2.0", "method" => "tools/list", "id" => "list"})
    |> put_req_header("mcp-session-id", session_id)
    |> Router.call(opts)
    |> Map.fetch!(:resp_body)
    |> Jason.decode!()
    |> get_in(["result", "tools"])
  end
end
