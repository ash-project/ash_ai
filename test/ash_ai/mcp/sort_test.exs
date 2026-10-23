# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.SortTest do
  @moduledoc """
  The sort enum used to offer every public field whose `sortable?` was true,
  which every calculation is by default. A calculation without an expression
  cannot be sorted in the data layer, so a client that picked one from the
  enum crashed the read with `UndefinedFunctionError` instead of being told.
  """
  use AshAi.RepoCase, async: false
  import Plug.{Conn, Test}

  alias AshAi.Mcp.Router

  @protocol_version "2026-07-28"
  @meta_protocol_version "io.modelcontextprotocol/protocolVersion"

  defp rpc(method, params, tool) do
    response =
      :post
      |> conn("/", %{
        "jsonrpc" => "2.0",
        "id" => "req_1",
        "method" => method,
        "params" =>
          Map.put(params, "_meta", %{
            @meta_protocol_version => @protocol_version,
            "io.modelcontextprotocol/clientInfo" => %{
              "name" => "test_client",
              "version" => "1.0.0"
            },
            "io.modelcontextprotocol/clientCapabilities" => %{}
          })
      })
      |> put_req_header("mcp-protocol-version", @protocol_version)
      |> put_req_header("mcp-method", method)
      |> put_req_header("mcp-name", to_string(tool))
      |> Router.call(tools: [tool], otp_app: :ash_ai)

    assert response.status == 200

    Jason.decode!(response.resp_body)["result"]
  end

  defp sort_fields(tool) do
    %{"tools" => [%{"inputSchema" => schema}]} = rpc("tools/list", %{}, tool)

    get_in(schema, ["properties", "sort", "items", "properties", "field", "enum"])
  end

  test "a calculation with an expression is offered as a sort field" do
    assert "has_bio" in sort_fields(:list_artists_oban)
  end

  test "a calculation without an expression is not offered as a sort field" do
    refute "bio_word_count" in sort_fields(:list_artists_oban)
  end

  test "sorting on a calculation without an expression is refused, naming the field" do
    result =
      rpc(
        "tools/call",
        %{
          "name" => "list_artists_oban",
          "arguments" => %{"sort" => [%{"field" => "bio_word_count", "direction" => "desc"}]}
        },
        :list_artists_oban
      )

    assert result["isError"]
    assert hd(result["content"])["text"] =~ "cannot sort on `bio_word_count`"
  end
end
