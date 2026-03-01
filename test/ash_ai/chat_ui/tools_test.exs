# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.ChatUI.ToolsTest do
  use ExUnit.Case, async: true

  alias AshAi.ChatUI.Tools

  describe "extract/1" do
    test "normalizes mixed key formats for tool calls and tool results" do
      message = %{
        :tool_calls => [
          %{
            "id" => "call_1",
            "name" => "get_all_users",
            "arguments" => %{"limit" => 10}
          },
          %{
            id: "call_2",
            name: "get_projects",
            arguments: ~s({"status":"active"})
          }
        ],
        "tool_results" => [
          %{
            "tool_call_id" => "call_1",
            "content" => %{"users" => []},
            "is_error" => false
          },
          %{
            id: "call_2",
            content: "ok",
            is_error: true
          }
        ]
      }

      assert {:ok, %{tool_calls: tool_calls, tool_results: tool_results}} = Tools.extract(message)

      assert tool_calls == [
               %{
                 id: "call_1",
                 name: "get_all_users",
                 arguments: %{"limit" => 10},
                 arguments_preview: ~s({"limit":10})
               },
               %{
                 id: "call_2",
                 name: "get_projects",
                 arguments: %{"status" => "active"},
                 arguments_preview: ~s({"status":"active"})
               }
             ]

      assert Enum.map(tool_results, &Map.take(&1, [:id, :name, :content, :is_error])) == [
               %{id: "call_1", name: "get_all_users", content: %{"users" => []}, is_error: false},
               %{id: "call_2", name: "get_projects", content: "ok", is_error: true}
             ]
    end

    test "returns Ash error tuple for invalid top-level payload" do
      assert {:error, %Ash.Error.Unknown{} = error} = Tools.extract("not a message")
      assert inspect(error) =~ "Invalid message"
    end

    test "returns Ash error tuple for invalid tool_calls container" do
      assert {:error, %Ash.Error.Unknown{} = error} = Tools.extract(%{tool_calls: true})
      assert inspect(error) =~ "Invalid tool_calls"
      assert inspect(error) =~ ":boolean"
    end

    test "uses ReqLLM.ToolCall.from_map/1 normalization for flat tool call maps" do
      message = %{
        tool_calls: [
          %{
            "id" => "call_abc",
            "name" => "read_posts",
            "arguments" => ~s({"limit":5})
          }
        ]
      }

      assert {:ok, %{tool_calls: [tool_call], tool_results: []}} = Tools.extract(message)
      assert tool_call.id == "call_abc"
      assert tool_call.name == "read_posts"
      assert tool_call.arguments == %{"limit" => 5}
    end

    test "infers tool result name from tool call id when result name is missing" do
      message = %{
        tool_calls: [%{id: "call_42", name: "read_tasks", arguments: %{}}],
        tool_results: [%{tool_call_id: "call_42", content: %{"count" => 2}}]
      }

      assert {:ok, %{tool_results: [result]}} = Tools.extract(message)
      assert result.id == "call_42"
      assert result.name == "read_tasks"
    end

    test "coerces is_error values to booleans" do
      message = %{
        tool_results: [
          %{id: "a", content: "ok", is_error: true},
          %{id: "b", content: "ok", is_error: "true"},
          %{id: "c", content: "ok", is_error: false},
          %{id: "d", content: "ok", is_error: nil},
          %{id: "e", content: "ok", is_error: "false"}
        ]
      }

      assert {:ok, %{tool_results: results}} = Tools.extract(message)

      assert Enum.map(results, &{&1.id, &1.is_error}) == [
               {"a", true},
               {"b", true},
               {"c", false},
               {"d", false},
               {"e", false}
             ]
    end

    test "generates bounded previews" do
      long_text = String.duplicate("x", 400)

      message = %{
        tool_calls: [%{id: "call_1", name: "search", arguments: %{"q" => long_text}}],
        tool_results: [%{id: "call_1", content: %{value: long_text}}]
      }

      assert {:ok, %{tool_calls: [tool_call], tool_results: [tool_result]}} =
               Tools.extract(message)

      assert String.length(tool_call.arguments_preview) <= 80
      assert String.length(tool_result.content_preview) <= 180
    end

    test "skips malformed entries and never raises on malformed lists" do
      message = %{
        tool_calls: [true, nil, %{}, %{name: "valid", arguments: [1, 2, 3]}],
        tool_results: [123, nil, %{}, %{"content" => %{"ok" => true}}]
      }

      assert {:ok, %{tool_calls: [tool_call], tool_results: [tool_result]}} =
               Tools.extract(message)

      assert is_binary(tool_call.id)
      assert String.starts_with?(tool_call.id, "call_")
      assert tool_call.name == "valid"
      assert tool_call.arguments == %{"raw" => "[1, 2, 3]"}
      assert tool_result.id == "tool_result"
      assert tool_result.content == %{"ok" => true}
    end
  end
end
