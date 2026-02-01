# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Verifiers.McpResourceActionsReturnStringTest do
  @moduledoc """
  Tests for the MCP resource verifier that ensures actions return strings.

  Note: This verifier runs at compile-time, so we test it by capturing compile output
  rather than catching runtime exceptions.
  """
  use ExUnit.Case, async: true

  import ExUnit.CaptureIO

  describe "McpResourceActionsReturnString verifier" do
    test "produces error when mcp_resource action does not return a string" do
      output =
        capture_io(:stderr, fn ->
          defmodule InvalidResource do
            use Ash.Resource, domain: nil

            actions do
              # This action returns an integer, not a string
              action :non_string_action, :integer do
                run fn _input, _context ->
                  {:ok, 42}
                end
              end
            end
          end

          defmodule InvalidMcpResourceDomain do
            use Ash.Domain, extensions: [AshAi]

            mcp_resources do
              mcp_resource :invalid_resource,
                           "file://invalid/resource",
                           InvalidResource,
                           :non_string_action,
                           title: "Invalid Resource"
            end

            resources do
              resource InvalidResource
            end
          end
        end)

      # Verify the error message appears in output
      assert output =~ "All mcp resource actions must return strings"
      assert output =~ ":invalid_resource"
    end

    test "does not produce error when mcp_resource action returns a string" do
      output =
        capture_io(:stderr, fn ->
          defmodule ValidResource2 do
            use Ash.Resource, domain: nil

            actions do
              # This action returns a string, which is correct
              action :string_action, :string do
                run fn _input, _context ->
                  {:ok, "valid string response"}
                end
              end
            end
          end

          defmodule ValidMcpResourceDomain2 do
            use Ash.Domain, extensions: [AshAi]

            mcp_resources do
              mcp_resource :valid_resource,
                           "file://valid/resource",
                           ValidResource2,
                           :string_action,
                           title: "Valid Resource"
            end

            resources do
              resource ValidResource2
            end
          end
        end)

      # Should not contain the error message
      refute output =~ "All mcp resource actions must return strings"
    end

    test "error message includes all invalid mcp_resource names" do
      output =
        capture_io(:stderr, fn ->
          defmodule MultipleInvalidResource do
            use Ash.Resource, domain: nil

            actions do
              action :returns_integer, :integer do
                run fn _input, _context ->
                  {:ok, 123}
                end
              end

              action :returns_boolean, :boolean do
                run fn _input, _context ->
                  {:ok, true}
                end
              end
            end
          end

          defmodule MultipleInvalidMcpResourcesDomain do
            use Ash.Domain, extensions: [AshAi]

            mcp_resources do
              mcp_resource(
                :first_invalid,
                "file://first/invalid",
                MultipleInvalidResource,
                :returns_integer,
                title: "First Invalid"
              )

              mcp_resource :second_invalid,
                           "file://second/invalid",
                           MultipleInvalidResource,
                           :returns_boolean,
                           title: "Second Invalid"
            end

            resources do
              resource MultipleInvalidResource
            end
          end
        end)

      # Verify the error message includes both resource names
      assert output =~ ":first_invalid"
      assert output =~ ":second_invalid"
      assert output =~ "All mcp resource actions must return strings"
    end

    test "allows resource with mixed actions when only valid ones are exposed" do
      output =
        capture_io(:stderr, fn ->
          defmodule MixedResource2 do
            use Ash.Resource, domain: nil

            actions do
              # Valid action that we expose
              action :string_action, :string do
                run fn _input, _context ->
                  {:ok, "valid"}
                end
              end

              # Invalid action that we DON'T expose as an mcp_resource
              action :integer_action, :integer do
                run fn _input, _context ->
                  {:ok, 42}
                end
              end
            end
          end

          defmodule MixedResourcesDomain2 do
            use Ash.Domain, extensions: [AshAi]

            mcp_resources do
              # Only expose the valid string-returning action
              mcp_resource :valid_only,
                           "file://valid/only",
                           MixedResource2,
                           :string_action,
                           title: "Valid Only"
            end

            resources do
              resource MixedResource2
            end
          end
        end)

      # Should not complain about the integer_action since it's not exposed
      refute output =~ "All mcp resource actions must return strings"
    end
  end
end
