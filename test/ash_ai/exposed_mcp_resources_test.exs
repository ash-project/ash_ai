# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.ExposedMcpResourcesTest do
  @moduledoc """
  Tests for AshAi.exposed_mcp_resources/1 filtering logic.

  This tests the core filtering functionality separate from the MCP protocol/router.
  """
  use AshAi.RepoCase, async: true

  alias AshAi.Test.Music

  @opts [otp_app: :ash_ai]

  describe "mcp_resources filtering" do
    test "mcp_resources: :* returns all MCP resources" do
      opts = Keyword.put(@opts, :mcp_resources, :*)
      resources = AshAi.exposed_mcp_resources(opts)

      resource_names = Enum.map(resources, & &1.name)
      assert :artist_card in resource_names
      assert :artist_json in resource_names
      assert :artist_with_params in resource_names
      assert :failing_resource in resource_names
      assert :artist_card_custom in resource_names
      assert :actor_test_resource in resource_names
    end

    test "mcp_resources: nil returns all MCP resources (default)" do
      # @opts already has otp_app, should return all resources by default
      resources = AshAi.exposed_mcp_resources(@opts)
      resource_names = Enum.map(resources, & &1.name)
      assert :artist_card in resource_names
      assert :artist_json in resource_names
      assert :artist_with_params in resource_names
      assert :failing_resource in resource_names
      assert :artist_card_custom in resource_names
      assert :actor_test_resource in resource_names
    end

    test "mcp_resources: [] excludes all MCP resources" do
      opts = Keyword.put(@opts, :mcp_resources, [])
      resources = AshAi.exposed_mcp_resources(opts)

      assert Enum.empty?(resources)
    end

    test "mcp_resources: specific list filters to only those resources" do
      opts = Keyword.put(@opts, :mcp_resources, [:artist_card, :artist_json])
      resources = AshAi.exposed_mcp_resources(opts)

      assert length(resources) == 2
      resource_names = Enum.map(resources, & &1.name)
      assert :artist_card in resource_names
      assert :artist_json in resource_names
      refute :artist_with_params in resource_names
    end

    test "mcp_resources: single resource in list" do
      opts = Keyword.put(@opts, :mcp_resources, [:failing_resource])
      resources = AshAi.exposed_mcp_resources(opts)

      assert length(resources) == 1
      assert hd(resources).name == :failing_resource
    end

    test "mcp_resources + actions: both filters applied" do
      # Filter to specific MCP resources AND specific actions
      opts =
        @opts
        |> Keyword.put(:mcp_resources, [:artist_card, :artist_card_custom, :artist_json])
        |> Keyword.put(:actions, [{Music.ArtistUi, [:artist_card]}])

      resources = AshAi.exposed_mcp_resources(opts)

      # Should only return artist_card and artist_card_custom (both use artist_card action)
      # artist_json is excluded by actions filter
      assert length(resources) == 2
      resource_names = Enum.map(resources, & &1.name)
      assert :artist_card in resource_names
      assert :artist_card_custom in resource_names
      refute :artist_json in resource_names
    end

    test "mcp_resources + exclude_actions: exclusion applied after mcp_resources filter" do
      opts =
        @opts
        |> Keyword.put(:mcp_resources, [:artist_card, :artist_json, :artist_with_params])
        |> Keyword.put(:exclude_actions, [{Music.ArtistUi, :artist_json}])

      resources = AshAi.exposed_mcp_resources(opts)

      # Should return artist_card and artist_with_params, but not artist_json
      assert length(resources) == 2
      resource_names = Enum.map(resources, & &1.name)
      assert :artist_card in resource_names
      assert :artist_with_params in resource_names
      refute :artist_json in resource_names
    end

    test "mcp_resources: [] with exclude_actions has no effect (nothing to exclude)" do
      opts =
        @opts
        |> Keyword.put(:mcp_resources, [])
        |> Keyword.put(:exclude_actions, [{Music.ArtistUi, :artist_card}])

      resources = AshAi.exposed_mcp_resources(opts)

      assert Enum.empty?(resources)
    end

    test "actions: wildcard with mcp_resources filter" do
      opts =
        @opts
        |> Keyword.put(:mcp_resources, [:artist_card, :artist_json])
        |> Keyword.put(:actions, [{Music.ArtistUi, :*}])

      resources = AshAi.exposed_mcp_resources(opts)

      # Should return only artist_card and artist_json (filtered by mcp_resources)
      assert length(resources) == 2
      resource_names = Enum.map(resources, & &1.name)
      assert :artist_card in resource_names
      assert :artist_json in resource_names
    end
  end

  describe "actions filtering" do
    test "actions: specific list filters resource/action pairs" do
      opts = Keyword.put(@opts, :actions, [{Music.ArtistUi, [:artist_card]}])
      resources = AshAi.exposed_mcp_resources(opts)

      # Should return resources using the artist_card action (both artist_card and artist_card_custom)
      assert length(resources) == 2
      resource_names = Enum.map(resources, & &1.name)
      assert :artist_card in resource_names
      assert :artist_card_custom in resource_names

      # Both should have the same action
      for resource <- resources do
        assert resource.action.name == :artist_card
      end
    end

    test "actions: wildcard returns all actions for resource" do
      opts = Keyword.put(@opts, :actions, [{Music.ArtistUi, :*}])
      resources = AshAi.exposed_mcp_resources(opts)

      action_names = Enum.map(resources, & &1.action.name)
      assert :artist_card in action_names
      assert :artist_json in action_names
      assert :artist_card_with_params in action_names
      assert :failing_action in action_names
      assert :actor_test in action_names
    end
  end

  describe "exclude_actions filtering" do
    test "exclude_actions: removes specific resource/action pairs" do
      opts = Keyword.put(@opts, :exclude_actions, [{Music.ArtistUi, :artist_json}])
      resources = AshAi.exposed_mcp_resources(opts)

      refute :artist_json in Enum.map(resources, & &1.name)
    end

    test "exclude_actions: multiple exclusions" do
      opts =
        Keyword.put(@opts, :exclude_actions, [
          {Music.ArtistUi, :artist_json},
          {Music.ArtistUi, :failing_action}
        ])

      resources = AshAi.exposed_mcp_resources(opts)
      resource_names = Enum.map(resources, & &1.name)

      refute :artist_json in resource_names
      refute :failing_resource in resource_names
    end
  end

  describe "combined filtering" do
    test "all filters work together: mcp_resources + actions + exclude_actions" do
      opts =
        @opts
        |> Keyword.put(:mcp_resources, [:artist_card, :artist_card_custom, :artist_json])
        |> Keyword.put(:actions, [{Music.ArtistUi, :*}])
        |> Keyword.put(:exclude_actions, [{Music.ArtistUi, :artist_json}])

      resources = AshAi.exposed_mcp_resources(opts)

      resource_names = Enum.map(resources, & &1.name)
      assert :artist_card in resource_names
      assert :artist_card_custom in resource_names
      refute :artist_json in resource_names
    end
  end

  describe "edge cases" do
    test "raises when no otp_app and no actions" do
      assert_raise RuntimeError, "Must specify `otp_app` if you do not specify `actions`", fn ->
        AshAi.exposed_mcp_resources([])
      end
    end

    test "empty result when actions filter matches nothing" do
      opts = Keyword.put(@opts, :actions, [{Music.ArtistUi, [:nonexistent_action]}])
      resources = AshAi.exposed_mcp_resources(opts)

      assert Enum.empty?(resources)
    end

    test "returns enriched resources with domain and action metadata" do
      resources = AshAi.exposed_mcp_resources(@opts)

      for resource <- resources do
        assert resource.domain
        assert resource.action
        assert is_struct(resource.action)
        assert resource.description || resource.action.description
      end
    end
  end
end
