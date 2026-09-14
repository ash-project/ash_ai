# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.ResultTypeTest do
  @moduledoc """
  A model picks `result_type` itself, so it can pick one that does not exist.

  Before this was handled, an unrecognised value fell off the end of
  `execute_read/4` as a `FunctionClauseError`, which `AshAi.ToToolError` has no
  implementation for — the caller got "returning a generic error message" and
  nothing to correct.
  """
  use AshAi.RepoCase, async: false
  import Plug.{Conn, Test}

  alias AshAi.Mcp.Router

  @opts [tools: [:list_artists], otp_app: :ash_ai]

  describe "an unrecognised result_type" do
    test "comes back as a tool error naming the accepted values" do
      session_id = initialize_and_get_session_id(@opts)

      response =
        call_tool(session_id, "list_artists", %{"arguments" => %{"result_type" => "nonsense"}})

      body = decode_response(response)

      assert response.status == 200
      assert body["result"]["isError"] == true
      assert [%{"type" => "text", "text" => text}] = body["result"]["content"]
      assert text =~ "run_query"
      refute body["error"]
    end

    test "leaves the supported values working" do
      session_id = initialize_and_get_session_id(@opts)

      for result_type <- ["run_query", "count", "exists"] do
        response =
          call_tool(session_id, "list_artists", %{
            "arguments" => %{"result_type" => result_type}
          })

        assert decode_response(response)["result"]["isError"] == false,
               "#{result_type} should still be accepted"
      end
    end
  end

  defp initialize_and_get_session_id(opts) do
    :post
    |> conn("/", %{
      "method" => "initialize",
      "id" => "init_1",
      "params" => %{"client" => %{"name" => "test_client", "version" => "1.0.0"}}
    })
    |> Router.call(opts)
    |> Plug.Conn.get_resp_header("mcp-session-id")
    |> List.first()
  end

  defp call_tool(session_id, tool_name, params) do
    :post
    |> conn("/", %{
      "method" => "tools/call",
      "id" => "call_1",
      "params" => Map.put(params, "name", tool_name)
    })
    |> put_req_header("mcp-session-id", session_id)
    |> Router.call(@opts)
  end

  defp decode_response(response), do: Jason.decode!(response.resp_body)
end
