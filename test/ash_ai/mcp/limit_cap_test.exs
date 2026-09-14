# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.LimitCapTest do
  @moduledoc """
  A `limit` above the action's `max_page_size` used to be silently clamped, so
  a caller paging by its own step size skipped every row between the cap and
  the step without anything in the response saying so.
  """
  use AshAi.RepoCase, async: false
  import Plug.{Conn, Test}

  alias AshAi.Mcp.Router

  @protocol_version "2026-07-28"
  @meta_protocol_version "io.modelcontextprotocol/protocolVersion"

  defp call(tool, arguments) do
    params = %{
      "name" => to_string(tool),
      "arguments" => arguments,
      "_meta" => %{
        @meta_protocol_version => @protocol_version,
        "io.modelcontextprotocol/clientInfo" => %{"name" => "test_client", "version" => "1.0.0"},
        "io.modelcontextprotocol/clientCapabilities" => %{}
      }
    }

    response =
      :post
      |> conn("/", %{
        "jsonrpc" => "2.0",
        "id" => "req_1",
        "method" => "tools/call",
        "params" => params
      })
      |> put_req_header("mcp-protocol-version", @protocol_version)
      |> put_req_header("mcp-method", "tools/call")
      |> put_req_header("mcp-name", to_string(tool))
      |> Router.call(tools: [tool], otp_app: :ash_ai)

    assert response.status == 200

    Jason.decode!(response.resp_body)["result"]
  end

  test "asking for more than the cap is refused, and the error names the cap" do
    result = call(:list_artists_paged, %{"limit" => 300})

    assert result["isError"]

    assert hd(result["content"])["text"] =~ "maximum page size of 5"
  end

  test "asking for the cap or less is served normally" do
    result = call(:list_artists_paged, %{"limit" => 5})

    refute result["isError"]
  end

  test "omitting a limit is served normally" do
    result = call(:list_artists_paged, %{})

    refute result["isError"]
  end
end
