# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.UsecTimestampSchemaTest do
  @moduledoc """
  `create_timestamp` and `update_timestamp` default to `:utc_datetime_usec`, a
  type distinct from `:utc_datetime`. Without its own clause it fell through to
  the generic branch, which carries no `:type`, so every operator on such a
  field was published as an empty `{}` schema.
  """
  use AshAi.RepoCase, async: false
  import Plug.{Conn, Test}

  alias AshAi.Mcp.Router

  @protocol_version "2026-07-28"
  @meta_protocol_version "io.modelcontextprotocol/protocolVersion"

  defp tool(name) do
    [otp_app: :ash_ai] |> AshAi.exposed_tools() |> Enum.find(&(&1.name == name))
  end

  defp tools_list(tools) do
    params = %{
      "_meta" => %{
        @meta_protocol_version => @protocol_version,
        "io.modelcontextprotocol/clientInfo" => %{"name" => "test_client", "version" => "1.0.0"},
        "io.modelcontextprotocol/clientCapabilities" => %{}
      }
    }

    :post
    |> conn("/", %{
      "jsonrpc" => "2.0",
      "id" => "req_1",
      "method" => "tools/list",
      "params" => params
    })
    |> put_req_header("mcp-protocol-version", @protocol_version)
    |> put_req_header("mcp-method", "tools/list")
    |> Router.call(tools: tools, otp_app: :ash_ai)
  end

  test "a usec timestamp is filterable as a date-time string, not an untyped value" do
    schema =
      :list_artists_oban
      |> tool()
      |> Map.put(:full_filter_schema?, true)
      |> AshAi.Tool.Schema.for_tool(strict?: false)

    created_at = get_in(schema, ["properties", "filter", "properties", "created_at"])

    assert get_in(created_at, ["properties", "eq"]) == %{
             "type" => "string",
             "format" => "date-time"
           }

    assert get_in(created_at, ["properties", "greater_than"]) == %{
             "type" => "string",
             "format" => "date-time"
           }
  end

  test "a resource with usec timestamps builds a tool schema" do
    response = tools_list([:list_artists_oban])

    assert response.status == 200

    assert [%{"name" => "list_artists_oban", "inputSchema" => schema}] =
             Jason.decode!(response.resp_body)["result"]["tools"]

    assert get_in(schema, ["properties", "filter", "description"]) =~ "created_at"
  end
end
