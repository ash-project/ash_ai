# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.ResultTypeSchemaTest do
  @moduledoc """
  The non-strict `result_type` schema used to strip `type` from both `oneOf`
  members, leaving nothing to tell a client that the aggregate form is an
  object. Clients serialized it as a string instead, and the server rejected
  the string as unsupported — so no aggregate other than a bare `count` could
  be called at all.
  """
  use AshAi.RepoCase, async: false
  import Plug.{Conn, Test}

  alias AshAi.Mcp.Router

  @protocol_version "2026-07-28"
  @meta_protocol_version "io.modelcontextprotocol/protocolVersion"

  defp result_type_schema(tool) do
    params = %{
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
        "method" => "tools/list",
        "params" => params
      })
      |> put_req_header("mcp-protocol-version", @protocol_version)
      |> put_req_header("mcp-method", "tools/list")
      |> Router.call(tools: [tool], otp_app: :ash_ai)

    assert response.status == 200

    [%{"inputSchema" => schema}] = Jason.decode!(response.resp_body)["result"]["tools"]

    get_in(schema, ["properties", "result_type"])
  end

  test "both result_type forms declare their JSON type, so a client knows which is an object" do
    assert %{"oneOf" => [scalar, aggregate]} = result_type_schema(:list_artists)

    assert scalar["type"] == "string"
    assert scalar["enum"] == ["run_query", "count", "exists"]

    assert aggregate["type"] == "object"
    assert aggregate["properties"]["aggregate"]["enum"] == ["max", "min", "sum", "avg", "count"]
  end

  test "the aggregate form names both keys as required" do
    assert %{"oneOf" => [_scalar, aggregate]} = result_type_schema(:list_artists)

    assert Enum.sort(aggregate["required"]) == ["aggregate", "field"]
  end
end
