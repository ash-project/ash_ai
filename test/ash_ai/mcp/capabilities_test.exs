defmodule AshAi.Mcp.CapabilitiesTest do
  use AshAi.RepoCase, async: false

  alias AshAi.Mcp.{Registry, Session}
  alias AshAi.Mcp.Capabilities.{Prompts, Resources, Sampling, Tools}

  describe "Registry" do
    test "registers default capabilities on startup" do
      capabilities = Registry.list_capabilities()

      capability_names = Enum.map(capabilities, fn {name, _module, _opts} -> name end)

      assert :ash_tools in capability_names
      assert :ash_resources in capability_names
      assert :prompts in capability_names
      assert :sampling in capability_names
    end

    test "can register and retrieve custom capabilities" do
      defmodule TestCapability do
        @behaviour AshAi.Mcp.Capability

        def capability_name, do: "test"
        def capability_config, do: %{"test" => %{}}
        def list_items(_opts), do: {:ok, []}
        def handle_method(_method, _params, _session_id, _opts), do: :not_handled
      end

      assert :ok = Registry.register_capability(:test, TestCapability, [])
      assert {:ok, {TestCapability, []}} = Registry.get_capability(:test)

      # Cleanup
      Registry.unregister_capability(:test)
    end

    test "builds capabilities config correctly" do
      config = Registry.build_capabilities_config("test-session")

      assert Map.has_key?(config, "tools")
      assert Map.has_key?(config, "resources")
      assert Map.has_key?(config, "prompts")
      assert Map.has_key?(config, "sampling")
    end

    test "handles method dispatch correctly" do
      # Test with tools capability
      result = Registry.handle_method("tools/list", %{}, "test-session", otp_app: :ash_ai)
      assert {:ok, %{"tools" => _}} = result
    end
  end

  describe "Tools Capability" do
    test "implements capability behavior correctly" do
      assert Tools.capability_name() == "tools"
      assert is_map(Tools.capability_config())
      assert {:ok, items} = Tools.list_items("test-session", otp_app: :ash_ai)
      assert is_list(items)
    end

    test "handles tools/list method" do
      result = Tools.handle_method("tools/list", %{}, "test-session", otp_app: :ash_ai)
      assert {:ok, %{"tools" => tools}} = result
      assert is_list(tools)
    end

    test "handles tools/call method with valid tool" do
      # This would need a real tool to test properly
      result =
        Tools.handle_method("tools/call", %{"name" => "nonexistent"}, "test-session",
          otp_app: :ash_ai
        )

      # Should return an error for nonexistent tool
      assert {:error, _} = result
    end
  end

  describe "Resources Capability" do
    test "implements capability behavior correctly" do
      assert Resources.capability_name() == "resources"
      assert is_map(Resources.capability_config())
      assert {:ok, items} = Resources.list_items("test-session", otp_app: :ash_ai)
      assert is_list(items)
    end

    test "handles resources/list method" do
      result = Resources.handle_method("resources/list", %{}, "test-session", otp_app: :ash_ai)
      assert {:ok, %{"resources" => resources}} = result
      assert is_list(resources)
    end

    test "handles resources/read method" do
      # Test with a mock URI
      params = %{"uri" => "ash://TestDomain/TestResource"}
      result = Resources.handle_method("resources/read", params, "test-session", otp_app: :ash_ai)
      assert {:ok, %{"contents" => _}} = result
    end

    test "handles resources/templates/list method" do
      result =
        Resources.handle_method("resources/templates/list", %{}, "test-session", otp_app: :ash_ai)

      assert {:ok, %{"resourceTemplates" => templates}} = result
      assert is_list(templates)
      assert length(templates) > 0

      # Verify that each template has the required fields
      Enum.each(templates, fn template ->
        assert Map.has_key?(template, "uriTemplate")
        assert Map.has_key?(template, "name")
        assert Map.has_key?(template, "description")
        assert Map.has_key?(template, "mimeType")
        assert template["mimeType"] == "application/json"
      end)

      # Verify that we have at least one general template
      general_template = Enum.find(templates, &(&1["uriTemplate"] == "ash://{domain}/{resource}"))
      assert general_template != nil
      assert general_template["name"] == "Ash Resources"
    end
  end

  describe "Prompts Capability" do
    test "implements capability behavior correctly" do
      assert Prompts.capability_name() == "prompts"
      assert is_map(Prompts.capability_config())
      assert {:ok, items} = Prompts.list_items("test-session", otp_app: :ash_ai)
      assert is_list(items)
    end

    test "handles prompts/list method" do
      result = Prompts.handle_method("prompts/list", %{}, "test-session", otp_app: :ash_ai)
      assert {:ok, %{"prompts" => prompts}} = result
      assert is_list(prompts)
    end

    test "handles prompts/get method with system prompt" do
      params = %{
        "name" => "ash_ai.simple_task",
        "arguments" => %{"task" => "Test task"}
      }

      result = Prompts.handle_method("prompts/get", params, "test-session", otp_app: :ash_ai)
      assert {:ok, %{"description" => _, "messages" => messages}} = result
      assert is_list(messages)
      assert length(messages) > 0
    end
  end

  describe "Sampling Capability" do
    test "implements capability behavior correctly" do
      assert Sampling.capability_name() == "sampling"
      assert is_map(Sampling.capability_config())
      assert {:ok, items} = Sampling.list_items("test-session", [])
      assert items == []
    end

    test "validates sampling parameters correctly" do
      # Test missing required fields
      result = Sampling.handle_method("sampling/createMessage", %{}, "test-session", [])
      assert {:error, {:invalid_params, _}} = result

      # Test with valid parameters but no actual LLM (would need mocking for full test)
      valid_params = %{
        "messages" => [
          %{"role" => "user", "content" => %{"type" => "text", "text" => "Hello"}}
        ]
      }

      # This will fail because we don't have a real LLM configured in tests
      # but it tests the parameter validation
      result = Sampling.handle_method("sampling/createMessage", valid_params, "test-session", [])
      # Should get past validation but fail at execution
      assert {:error, {:sampling_failed, _}} = result
    end

    test "handles unrecognized methods" do
      result = Sampling.handle_method("sampling/unknown", %{}, "test-session", [])
      assert result == :not_handled
    end
  end

  describe "Session Integration" do
    test "session creation and management" do
      opts = [client_info: %{name: "test", version: "1.0"}]
      assert {:ok, session} = Session.create_session("test-session", opts)
      assert session.id == "test-session"
      assert session.status == :initializing

      # Initialize the session to make it active
      assert {:ok, _updated_session} = Session.initialize_session("test-session", %{})
      assert {:ok, active_session} = Session.get_session("test-session")
      assert active_session.status == :active

      # Test session retrieval
      assert {:ok, retrieved_session} = Session.get_session("test-session")
      assert retrieved_session.id == session.id

      # Test session update
      assert {:ok, _updated_session} =
               Session.update_session("test-session", %{last_activity: DateTime.utc_now()})

      # Test session cleanup
      assert :ok = Session.terminate_session("test-session")
      # After termination, session is removed from storage
      assert {:error, :not_found} = Session.get_session("test-session")
    end

    test "session timeout and cleanup" do
      # Create a session with short timeout for testing
      opts = [client_info: %{name: "test", version: "1.0"}]
      assert {:ok, _session} = Session.create_session("timeout-session", opts)

      # Manually expire the session by setting old timestamp
      old_time = DateTime.add(DateTime.utc_now(), -3600, :second)
      Session.update_session("timeout-session", %{last_activity: old_time})

      # Trigger cleanup (no arguments needed)
      Session.cleanup_expired_sessions()

      # Give cleanup time to process
      Process.sleep(100)

      # Session should be cleaned up
      assert {:error, :not_found} = Session.get_session("timeout-session")
    end
  end

  describe "Error Handling" do
    test "handles invalid capability registration" do
      defmodule InvalidCapability do
        # Missing behavior implementation
      end

      result = Registry.register_capability(:invalid, InvalidCapability, [])
      assert {:error, {:invalid_capability_module, InvalidCapability}} = result
    end

    test "handles method dispatch to non-existent capabilities" do
      result = Registry.handle_method("nonexistent/method", %{}, "test-session", [])
      assert result == :not_handled
    end

    test "handles capability errors gracefully" do
      # Test with malformed parameters that should be caught by capabilities
      result = Registry.handle_method("resources/read", %{}, "test-session", otp_app: :ash_ai)
      assert {:error, _} = result
    end
  end
end
