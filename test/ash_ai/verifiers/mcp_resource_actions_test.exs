# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Verifiers.McpResourceActionsTest do
  @moduledoc """
  Tests for the verifier that checks each mcp_resource can be read.

  Note: This verifier runs at compile-time, so we test it by capturing compile output
  rather than catching runtime exceptions.
  """
  use ExUnit.Case, async: true

  import ExUnit.CaptureIO

  describe "McpResourceActions verifier" do
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
      assert output =~ "Invalid mcp_resources"
      assert output =~ ":invalid_resource"
      assert output =~ "must return :string (sent as text) or :binary (sent as a blob)"
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
      refute output =~ "Invalid mcp_resources"
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
      assert output =~ "Invalid mcp_resources"
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
      refute output =~ "Invalid mcp_resources"
    end

    test "allows a binary action without `contents`" do
      output =
        capture_io(:stderr, fn ->
          defmodule BinaryResource do
            use Ash.Resource, domain: nil

            actions do
              action :bytes, :binary do
                run fn _input, _context -> {:ok, <<0, 1, 2>>} end
              end
            end
          end

          defmodule BinaryMcpResourceDomain do
            use Ash.Domain, extensions: [AshAi]

            mcp_resources do
              mcp_resource :bytes, "file://bytes", BinaryResource, :bytes, title: "Bytes"
            end

            resources do
              resource BinaryResource
            end
          end
        end)

      refute output =~ "Invalid mcp_resources"
    end

    test "allows any return type with `contents`, but not an action that returns nothing" do
      output =
        capture_io(:stderr, fn ->
          defmodule ContentsResource do
            use Ash.Resource, domain: nil

            actions do
              action :count, :integer do
                run fn _input, _context -> {:ok, 1} end
              end

              action :nothing do
                run fn _input, _context -> :ok end
              end
            end
          end

          defmodule ContentsMcpResourceDomain do
            use Ash.Domain, extensions: [AshAi]

            mcp_resources do
              mcp_resource :count, "file://count", ContentsResource, :count,
                title: "Count",
                contents: &__MODULE__.render/2

              mcp_resource :nothing, "file://nothing", ContentsResource, :nothing,
                title: "Nothing",
                contents: &__MODULE__.render/2
            end

            resources do
              resource ContentsResource
            end

            def render(result, _context), do: AshAi.McpResource.Contents.text(to_string(result))
          end
        end)

      assert output =~ ":nothing - :nothing must return a value"
      refute output =~ ":count -"
    end

    test "rejects a missing action and a non-generic action" do
      output =
        capture_io(:stderr, fn ->
          defmodule ReadOnlyResource do
            use Ash.Resource, domain: nil

            attributes do
              uuid_primary_key :id
            end

            actions do
              defaults [:read]
            end
          end

          defmodule WrongActionsMcpResourceDomain do
            use Ash.Domain, extensions: [AshAi]

            mcp_resources do
              mcp_resource :missing, "file://missing", ReadOnlyResource, :nope, title: "Missing"
              mcp_resource :read, "file://read", ReadOnlyResource, :read, title: "Read"
            end

            resources do
              resource ReadOnlyResource
            end
          end
        end)

      assert output =~ ":missing - #{inspect(__MODULE__.ReadOnlyResource)} has no action :nope"
      assert output =~ ":read - :read is a read action; resources must use a generic action"
    end

    test "rejects a URI template variable that isn't an action argument" do
      output =
        capture_io(:stderr, fn ->
          defmodule TemplatedResource do
            use Ash.Resource, domain: nil

            actions do
              action :photo, :string do
                argument :id, :string, allow_nil?: false
                run fn input, _context -> {:ok, input.arguments.id} end
              end
            end
          end

          defmodule TemplatedMcpResourceDomain do
            use Ash.Domain, extensions: [AshAi]

            mcp_resources do
              mcp_resource :good, "photos://{id}", TemplatedResource, :photo, title: "Good"

              mcp_resource :bad, "photos://{id}/{size}{?format}", TemplatedResource, :photo,
                title: "Bad"
            end

            resources do
              resource TemplatedResource
            end
          end
        end)

      assert output =~ ":bad - the URI template variable `size` isn't an argument of :photo"
      assert output =~ ":bad - the URI template variable `format` isn't an argument of :photo"
      refute output =~ ":good -"
    end

    test "rejects an unsupported URI template when the domain compiles" do
      error =
        assert_raise Spark.Error.DslError, fn ->
          defmodule InvalidTemplateMcpResourceDomain do
            use Ash.Domain, extensions: [AshAi], validate_config_inclusion?: false

            mcp_resources do
              mcp_resource :bad, "photos://{/id}", TemplatedResource, :photo, title: "Bad"
            end
          end
        end

      assert Exception.message(error) =~ ~s(Invalid URI template "photos://{/id}")
      assert Exception.message(error) =~ "the `/` operator, which isn't supported"
    end
  end
end
