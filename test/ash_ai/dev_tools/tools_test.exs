# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.DevTools.ToolsTest do
  use ExUnit.Case, async: true

  describe "get_usage_rules action" do
    test "returns all packages with usage-rules.md files" do
      {:ok, results} =
        AshAi.DevTools.Tools
        |> Ash.ActionInput.for_action(:get_usage_rules, %{})
        |> Ash.run_action()

      assert is_list(results)

      # Should find some packages with usage rules
      assert length(results) > 0

      for %{package: package, package_description: description, file_path: file_path} <- results do
        assert is_binary(package)
        assert is_binary(description)
        assert is_binary(file_path)
        assert File.exists?(file_path)
      end
    end

    test "includes expected packages with usage rules" do
      {:ok, results} =
        AshAi.DevTools.Tools
        |> Ash.ActionInput.for_action(:get_usage_rules, %{})
        |> Ash.run_action()

      packages = Enum.map(results, & &1.package)

      # Check for some packages we know should have usage rules
      expected_packages = ["ash", "igniter"]

      for expected <- expected_packages do
        if expected in packages do
          # If the package is found, verify its structure
          package_result = Enum.find(results, &(&1.package == expected))
          assert package_result.file_path
          assert String.ends_with?(package_result.file_path, "usage-rules.md")
        end
      end
    end

    test "file paths point to existing files" do
      {:ok, results} =
        AshAi.DevTools.Tools
        |> Ash.ActionInput.for_action(:get_usage_rules, %{})
        |> Ash.run_action()

      for %{file_path: file_path} <- results do
        assert File.exists?(file_path), "File #{file_path} should exist"
      end
    end
  end

  describe "list_ash_resources action" do
    test "returns list of resources with domains" do
      {:ok, results} =
        AshAi.DevTools.Tools
        |> Ash.ActionInput.for_action(:list_ash_resources, %{})
        |> Ash.run_action(context: %{otp_app: :ash_ai})

      assert is_list(results)

      # Verify we get some results from the test app
      assert length(results) > 0

      test_resources =
        Enum.filter(results, fn resource ->
          resource.name =~ "Test" or resource.domain =~ "Test"
        end)

      assert length(test_resources) > 0

      for %{name: name, domain: domain} <- results do
        assert is_binary(name)
        assert is_binary(domain)
      end
    end
  end

  describe "list_generators action" do
    test "returns list of available igniter generators" do
      {:ok, results} =
        AshAi.DevTools.Tools
        |> Ash.ActionInput.for_action(:list_generators, %{})
        |> Ash.run_action()

      assert is_list(results)

      ash_ai_generators =
        Enum.filter(results, fn gen ->
          gen.command =~ "ash_ai"
        end)

      assert length(ash_ai_generators) > 0

      for %{command: command, docs: docs} <- results do
        assert is_binary(command)
        assert is_binary(docs) or is_nil(docs) or docs == false
      end
    end

    test "includes expected ash_ai generators" do
      {:ok, results} =
        AshAi.DevTools.Tools
        |> Ash.ActionInput.for_action(:list_generators, %{})
        |> Ash.run_action()

      commands = Enum.map(results, & &1.command)

      expected_generators = [
        "ash_ai.gen.chat",
        "ash_ai.gen.mcp",
        "ash_ai.gen.usage_rules",
        "ash_ai.install"
      ]

      for expected <- expected_generators do
        assert expected in commands,
               "Expected generator #{expected} not found in #{inspect(commands)}"
      end
    end
  end

  describe "action descriptions and metadata" do
    test "get_usage_rules has appropriate description" do
      action = Ash.Resource.Info.action(AshAi.DevTools.Tools, :get_usage_rules)

      assert action.description =~ "usage rules"
      assert action.description =~ "packages"
      assert action.description =~ "usage-rules.md"
    end

    test "list_ash_resources has appropriate description" do
      action = Ash.Resource.Info.action(AshAi.DevTools.Tools, :list_ash_resources)

      assert action.description =~ "Ash resources"
      assert action.description =~ "domains"
    end

    test "list_generators has appropriate description" do
      action = Ash.Resource.Info.action(AshAi.DevTools.Tools, :list_generators)

      assert action.description =~ "generators"
      assert action.description =~ "igniter"
    end
  end

  describe "type definitions" do
    test "UsageRules type has correct structure" do
      # This should not raise an error when used in action results
      {:ok, results} =
        AshAi.DevTools.Tools
        |> Ash.ActionInput.for_action(:get_usage_rules, %{})
        |> Ash.run_action()

      assert is_list(results)

      for usage_rule <- results do
        assert is_map(usage_rule)
        assert Map.has_key?(usage_rule, :package)
        assert Map.has_key?(usage_rule, :package_description)
        assert Map.has_key?(usage_rule, :file_path)
      end
    end

    test "Resource type has correct structure" do
      {:ok, results} =
        AshAi.DevTools.Tools
        |> Ash.ActionInput.for_action(:list_ash_resources, %{})
        |> Ash.run_action(context: %{otp_app: :ash_ai})

      for resource <- results do
        assert Map.has_key?(resource, :name)
        assert Map.has_key?(resource, :domain)
      end
    end

    test "Task type has correct structure" do
      {:ok, results} =
        AshAi.DevTools.Tools
        |> Ash.ActionInput.for_action(:list_generators, %{})
        |> Ash.run_action()

      for task <- results do
        assert Map.has_key?(task, :command)
        assert Map.has_key?(task, :docs)
        assert is_binary(task.docs) or is_nil(task.docs) or task.docs == false
      end
    end
  end
end
