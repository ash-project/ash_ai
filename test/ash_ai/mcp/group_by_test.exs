# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.GroupByTest do
  @moduledoc """
  Answering "per depot, per day" by listing records means paging the whole set
  back to the caller and folding it there. `group_by` folds server-side instead,
  returning one entry per group.

  The query is streamed rather than read in one go, so memory is proportional to
  the number of groups and not to the number of records behind them.
  """
  use AshAi.RepoCase, async: false
  import Plug.{Conn, Test}

  alias AshAi.Mcp.Router
  alias AshAi.Test.Music.ArtistOban

  @protocol_version "2026-07-28"
  @meta_protocol_version "io.modelcontextprotocol/protocolVersion"

  setup do
    artist = fn label, play_count, bio ->
      ArtistOban
      |> Ash.Changeset.for_create(:create, %{
        name: "artist-#{label}-#{play_count}",
        label: label,
        play_count: play_count,
        bio: bio
      })
      |> Ash.create!(authorize?: false)
    end

    artist.("blue", 10, "a bio")
    artist.("blue", 20, nil)
    artist.("blue", 60, "another bio")
    artist.("red", 5, nil)

    :ok
  end

  defp call(arguments) do
    params = %{
      "name" => "list_artists_oban",
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
      |> put_req_header("mcp-name", "list_artists_oban")
      |> Router.call(tools: [:list_artists_oban], otp_app: :ash_ai)

    assert response.status == 200

    Jason.decode!(response.resp_body)["result"]
  end

  defp decoded(result), do: result["content"] |> List.first() |> Map.fetch!("text") |> Jason.decode!()

  defp error_text(result) do
    assert result["isError"]

    result["content"] |> List.first() |> Map.fetch!("text")
  end

  test "counts the records in each group" do
    result = call(%{"group_by" => ["label"], "result_type" => "count"})

    refute result["isError"]

    assert decoded(result) == [
             %{"group" => %{"label" => "blue"}, "count" => 3},
             %{"group" => %{"label" => "red"}, "count" => 1}
           ]
  end

  test "averages a field within each group, and reports the group size beside it" do
    result =
      call(%{
        "group_by" => ["label"],
        "result_type" => %{"aggregate" => "avg", "field" => "play_count"}
      })

    refute result["isError"]

    assert [blue, red] = decoded(result)

    assert blue == %{"group" => %{"label" => "blue"}, "count" => 3, "value" => 30.0}
    assert red == %{"group" => %{"label" => "red"}, "count" => 1, "value" => 5.0}
  end

  test "min, max and sum are folded per group" do
    for {kind, blue_value} <- [{"min", 10}, {"max", 60}, {"sum", 90}] do
      result =
        call(%{
          "group_by" => ["label"],
          "result_type" => %{"aggregate" => kind, "field" => "play_count"}
        })

      assert [%{"value" => ^blue_value} | _red] = decoded(result)
    end
  end

  test "counting a field counts only the records that have one, unlike the group size" do
    result =
      call(%{
        "group_by" => ["label"],
        "result_type" => %{"aggregate" => "count", "field" => "bio"}
      })

    assert [blue, _red] = decoded(result)

    assert blue == %{"group" => %{"label" => "blue"}, "count" => 3, "value" => 2}
  end

  test "grouping by several fields keys each entry by all of them" do
    result =
      call(%{
        "group_by" => ["label", "play_count"],
        "result_type" => "count"
      })

    groups = Enum.map(decoded(result), & &1["group"])

    assert %{"label" => "blue", "play_count" => 10} in groups
    assert %{"label" => "red", "play_count" => 5} in groups
    assert length(groups) == 4
  end

  test "a filter narrows what is grouped" do
    result =
      call(%{
        "group_by" => ["label"],
        "result_type" => "count",
        "filter" => %{"field" => "play_count", "operator" => "greater_than", "value" => 15}
      })

    assert decoded(result) == [%{"group" => %{"label" => "blue"}, "count" => 2}]
  end

  test "grouping without an aggregate says so rather than returning records" do
    assert call(%{"group_by" => ["label"], "result_type" => "run_query"})
           |> error_text() =~ ~s(result_type to be "count" or an aggregate object)
  end

  test "an aggregate the field's type cannot support is refused by name" do
    text =
      call(%{
        "group_by" => ["label"],
        "result_type" => %{"aggregate" => "avg", "field" => "name"}
      })
      |> error_text()

    assert text =~ "avg is not supported for name"
  end

  test "grouping by something that is not a groupable field is refused by name" do
    assert call(%{"group_by" => ["not_a_field"], "result_type" => "count"})
           |> error_text() =~ "not a groupable field"
  end

  test "a calculation can be grouped by, not only a stored column" do
    result =
      call(%{
        "group_by" => ["has_bio"],
        "result_type" => %{"aggregate" => "sum", "field" => "play_count"}
      })

    refute result["isError"]

    assert decoded(result) == [
             %{"group" => %{"has_bio" => false}, "count" => 2, "value" => 25},
             %{"group" => %{"has_bio" => true}, "count" => 2, "value" => 70}
           ]
  end
end
