# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.ExposedToolsTest do
  @moduledoc """
  Tests for AshAi.exposed_tools/1 filtering logic.

  This tests the core filtering functionality separate from the LLM integration.
  """
  use AshAi.RepoCase, async: true

  alias AshAi.Test.Music

  @opts [otp_app: :ash_ai]

  describe "tools filtering" do
    test "tools: nil returns all tools (default)" do
      tools = AshAi.exposed_tools(@opts)
      assert length(tools) == 6
    end

    test "tools: specific list filters to only those tools" do
      opts = Keyword.put(@opts, :tools, [:list_artists, :create_artist_after])

      assert opts
             |> AshAi.exposed_tools()
             |> Enum.map(& &1.name)
             |> MapSet.new() ==
               MapSet.new([
                 :list_artists,
                 :create_artist_after
               ])
    end

    test "tools: single tool in list" do
      opts = Keyword.put(@opts, :tools, [:create_artist_manual])
      assert [%{name: :create_artist_manual}] = AshAi.exposed_tools(opts)
    end

    test "tools: empty list returns no tools" do
      opts = Keyword.put(@opts, :tools, [])
      tools = AshAi.exposed_tools(opts)

      assert Enum.empty?(tools)
    end
  end

  describe "actions filtering" do
    test "actions: specific list filters resource/action pairs" do
      opts = Keyword.put(@opts, :actions, [{Music.ArtistAfterAction, [:read, :create]}])

      assert opts
             |> AshAi.exposed_tools()
             |> Enum.map(& &1.name)
             |> MapSet.new() ==
               MapSet.new([
                 :list_artists,
                 :create_artist_after,
                 :list_artists_with_meta
               ])
    end

    test "actions: wildcard returns all actions for resource" do
      opts = Keyword.put(@opts, :actions, [{Music.ArtistAfterAction, :*}])

      assert opts
             |> AshAi.exposed_tools()
             |> Enum.map(& &1.name)
             |> MapSet.new() ==
               MapSet.new([
                 :list_artists,
                 :create_artist_after,
                 :update_artist_after,
                 :list_artists_with_meta
               ])
    end

    test "actions: multiple resources" do
      opts =
        Keyword.put(@opts, :actions, [
          {Music.ArtistAfterAction, [:read]},
          {Music.ArtistManual, [:create]}
        ])

      assert opts
             |> AshAi.exposed_tools()
             |> Enum.map(& &1.name)
             |> MapSet.new() ==
               MapSet.new([
                 :list_artists,
                 :create_artist_manual,
                 :list_artists_with_meta
               ])
    end

    test "actions: raises when action not exposed as tool" do
      assert_raise RuntimeError, "Cannot use an action that is not exposed as a tool", fn ->
        AshAi.exposed_tools(actions: [{Music.ArtistAfterAction, [:destroy]}])
      end
    end
  end

  describe "exclude_actions filtering" do
    test "exclude_actions: removes specific resource/action pairs" do
      opts = Keyword.put(@opts, :exclude_actions, [{Music.ArtistAfterAction, :create}])
      tools = AshAi.exposed_tools(opts)

      refute :create_artist_after in Enum.map(tools, & &1.name)
    end

    test "exclude_actions: multiple exclusions" do
      opts =
        Keyword.put(@opts, :exclude_actions, [
          {Music.ArtistAfterAction, :create},
          {Music.ArtistManual, :update}
        ])

      assert opts
             |> AshAi.exposed_tools()
             |> Enum.map(& &1.name)
             |> MapSet.new() ==
               MapSet.new([
                 :list_artists,
                 :create_artist_manual,
                 :update_artist_after,
                 :list_artists_with_meta
               ])
    end
  end

  describe "combined filtering" do
    test "tools + actions: both filters applied" do
      opts =
        @opts
        |> Keyword.put(:tools, [:list_artists, :create_artist_after, :create_artist_manual])
        |> Keyword.put(:actions, [{Music.ArtistAfterAction, [:read, :create]}])

      assert opts
             |> AshAi.exposed_tools()
             |> Enum.map(& &1.name)
             |> MapSet.new() ==
               MapSet.new([:list_artists, :create_artist_after])
    end

    test "tools + exclude_actions: exclusion applied after tools filter" do
      opts =
        @opts
        |> Keyword.put(:tools, [:list_artists, :create_artist_after, :update_artist_after])
        |> Keyword.put(:exclude_actions, [{Music.ArtistAfterAction, :create}])

      assert opts
             |> AshAi.exposed_tools()
             |> Enum.map(& &1.name)
             |> MapSet.new() == MapSet.new([:list_artists, :update_artist_after])
    end

    test "all filters work together: actions + tools + exclude_actions" do
      opts =
        @opts
        |> Keyword.put(:actions, [{Music.ArtistAfterAction, :*}])
        |> Keyword.put(:tools, [:list_artists, :create_artist_after, :update_artist_after])
        |> Keyword.put(:exclude_actions, [{Music.ArtistAfterAction, :create}])

      assert opts
             |> AshAi.exposed_tools()
             |> Enum.map(& &1.name)
             |> MapSet.new() ==
               MapSet.new([:list_artists, :update_artist_after])
    end
  end

  describe "edge cases" do
    test "raises when no otp_app and no actions" do
      assert_raise RuntimeError, "Must specify `otp_app` if you do not specify `actions`", fn ->
        AshAi.exposed_tools([])
      end
    end

    test "empty result when actions filter matches nothing" do
      opts = Keyword.put(@opts, :actions, [{Music.ArtistAfterAction, [:destroy]}])

      assert_raise RuntimeError, "Cannot use an action that is not exposed as a tool", fn ->
        AshAi.exposed_tools(opts)
      end
    end

    test "empty result when tools filter matches nothing" do
      opts = Keyword.put(@opts, :tools, [:nonexistent_tool])
      tools = AshAi.exposed_tools(opts)

      assert Enum.empty?(tools)
    end

    test "returns enriched tools with domain and action metadata" do
      tools = AshAi.exposed_tools(@opts)

      for tool <- tools do
        assert tool.domain
        assert tool.action
        assert is_struct(tool.action)
        assert tool.resource
      end
    end

    test "tools are deduplicated" do
      # Even if multiple domains expose the same tool, it should appear once
      tools = AshAi.exposed_tools(@opts)

      tool_names = Enum.map(tools, & &1.name)
      assert length(tool_names) == length(Enum.uniq(tool_names))
    end
  end
end
