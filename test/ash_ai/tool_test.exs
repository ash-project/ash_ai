# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.ToolTest do
  use ExUnit.Case, async: true

  alias __MODULE__.{IdentityDomain, IdentityResource, TestDomain, TestResource}

  defmodule TestResource do
    use Ash.Resource, domain: TestDomain, data_layer: Ash.DataLayer.Ets

    attributes do
      uuid_v7_primary_key(:id, writable?: true)

      attribute :public_name, :string, public?: true
      attribute :public_email, :string, public?: true

      attribute :private_notes, :string
      attribute :internal_status, :string
    end

    actions do
      defaults([:read, :create])
      default_accept([:id, :public_name, :public_email, :private_notes, :internal_status])
    end
  end

  defmodule TestDomain do
    use Ash.Domain, extensions: [AshAi]

    resources do
      resource TestResource
    end

    tools do
      tool :read_test_resources, TestResource, :read, load: [:internal_status]

      tool :read_test_resources_full_filter, TestResource, :read, full_filter_schema?: true

      tool :read_test_resources_with_meta,
           TestResource,
           :read,
           description: "Read test resources with metadata",
           _meta: %{
             "openai/outputTemplate" => "ui://widget/test-resources.html",
             "openai/toolInvocation/invoking" => "Loading test resources…",
             "openai/toolInvocation/invoked" => "Test resources loaded."
           }
    end
  end

  defmodule IdentityResource do
    use Ash.Resource, domain: IdentityDomain, data_layer: Ash.DataLayer.Ets

    attributes do
      integer_primary_key :id, writable?: true
      attribute :public_id, :string, public?: true, allow_nil?: false
      attribute :name, :string, public?: true
    end

    identities do
      identity :public_id, [:public_id], pre_check_with: IdentityDomain
    end

    actions do
      defaults [:read, :create, :destroy]
      default_accept [:id, :public_id, :name]

      update :update do
        primary? true
        accept [:name]
      end
    end
  end

  defmodule IdentityDomain do
    use Ash.Domain, extensions: [AshAi]

    resources do
      resource IdentityResource
    end

    tools do
      # Default: addresses records by the primary key
      tool :update_by_pk, IdentityResource, :update

      # Custom identity: addresses records by the `public_id` unique identity
      tool :update_by_public_id, IdentityResource, :update, identity: :public_id

      # Disabled: no identifier in the schema at all
      tool :update_no_identity, IdentityResource, :update, identity: false
    end
  end

  describe "identity in update/destroy schemas" do
    defp identity_tool(name) do
      AshAi.list_tools(actions: [{IdentityResource, [:update]}], strict: false)
      |> Enum.find(&(&1.name == to_string(name)))
    end

    test "default (no identity:) includes the primary key" do
      props = identity_tool(:update_by_pk).parameter_schema["properties"]

      assert Map.has_key?(props, "id")
      refute Map.has_key?(props, "public_id")
    end

    test "identity: <non-pk identity> includes the identity key, not the primary key" do
      props = identity_tool(:update_by_public_id).parameter_schema["properties"]

      assert Map.has_key?(props, "public_id")
      refute Map.has_key?(props, "id")
    end

    test "identity: false includes neither the primary key nor an identity" do
      props = identity_tool(:update_no_identity).parameter_schema["properties"]

      refute Map.has_key?(props, "id")
      refute Map.has_key?(props, "public_id")
    end
  end

  describe "identity in update execution" do
    setup do
      records =
        for i <- 1..2 do
          IdentityResource
          |> Ash.Changeset.for_create(:create, %{
            id: i,
            public_id: "pub-#{i}",
            name: "Name #{i}"
          })
          |> Ash.create!(domain: IdentityDomain)
        end

      %{records: records}
    end

    test "update tool with identity: :public_id resolves and updates by public_id only" do
      {_tools, registry} =
        AshAi.build_tools_and_registry(
          actions: [{IdentityResource, [:update]}],
          strict: false
        )

      {:ok, _json, updated} =
        registry["update_by_public_id"].(
          %{"public_id" => "pub-2", "input" => %{"name" => "Renamed"}},
          context()
        )

      assert updated.id == 2
      assert updated.public_id == "pub-2"
      assert updated.name == "Renamed"

      # The other record is untouched
      other = Ash.get!(IdentityResource, 1, domain: IdentityDomain)
      assert other.name == "Name 1"
    end
  end

  describe "tool response" do
    setup do
      resource =
        TestResource
        |> Ash.Changeset.for_create(:create, %{
          id: "0197b375-4daa-7112-a9d8-7f0104485646",
          public_name: "John Doe",
          public_email: "john@example.com",
          private_notes: "Secret internal notes",
          internal_status: "classified"
        })
        |> Ash.create!(domain: TestDomain)

      %{resource: resource}
    end

    test "includes public and loaded fields", %{resource: resource} do
      {_tools, registry} =
        AshAi.build_tools_and_registry(actions: [{TestResource, :*}], strict: false)

      {:ok, json, [fetched]} = registry["read_test_resources"].(%{}, context())

      assert fetched.id == resource.id
      assert fetched.public_name == "John Doe"
      assert fetched.public_email == "john@example.com"
      assert fetched.internal_status == "classified"
      assert fetched.private_notes == "Secret internal notes"

      assert json ==
               "[{\"id\":\"0197b375-4daa-7112-a9d8-7f0104485646\",\"public_name\":\"John Doe\",\"public_email\":\"john@example.com\",\"internal_status\":\"classified\"}]"
    end

    test "handles nil arguments from clients" do
      {_tools, registry} =
        AshAi.build_tools_and_registry(actions: [{TestResource, :*}], strict: false)

      {:ok, json, _raw} = registry["read_test_resources"].(nil, context())
      assert is_binary(json)
    end
  end

  describe "tool parameter schema visibility" do
    test "compact filter description only includes public attributes" do
      tool = get_test_tool(strict: false)
      filter = tool.parameter_schema["properties"]["filter"]

      assert filter["type"] == "object"
      assert filter["description"] =~ "public_name"
      assert filter["description"] =~ "public_email"

      refute filter["description"] =~ "private_notes"
      refute filter["description"] =~ "internal_status"
    end

    test "full filter schema only includes public attributes" do
      tool =
        [actions: [{TestResource, [:read]}], tools: [:read_test_resources_full_filter]]
        |> AshAi.exposed_tools()
        |> hd()

      filter_properties =
        AshAi.Tools.parameter_schema(tool, strict: false)["properties"]["filter"]["properties"]

      assert Map.has_key?(filter_properties, "id")
      assert Map.has_key?(filter_properties, "public_name")
      assert Map.has_key?(filter_properties, "public_email")

      refute Map.has_key?(filter_properties, "private_notes")
      refute Map.has_key?(filter_properties, "internal_status")
    end

    test "sort field options only include public attributes" do
      tool = get_test_tool(strict: false)

      enum_values =
        tool.parameter_schema["properties"]["sort"]["items"]["properties"]["field"]["enum"]

      assert "id" in enum_values
      assert "public_name" in enum_values
      assert "public_email" in enum_values

      refute "private_notes" in enum_values
      refute "internal_status" in enum_values
    end

    test "aggregate field options only include public attributes" do
      tool = get_test_tool(strict: false)

      aggregate_option =
        tool.parameter_schema["properties"]["result_type"]["oneOf"]
        |> Enum.find(&Map.has_key?(&1, "properties"))

      aggregate_field_enum = aggregate_option["properties"]["field"]["enum"]

      assert "id" in aggregate_field_enum
      assert "public_name" in aggregate_field_enum
      assert "public_email" in aggregate_field_enum

      refute "private_notes" in aggregate_field_enum
      refute "internal_status" in aggregate_field_enum
    end
  end

  describe "tool _meta field" do
    test "tool without _meta has has_meta?/1 return false" do
      tools = AshAi.Info.tools(TestDomain)
      tool_without_meta = Enum.find(tools, &(&1.name == :read_test_resources))

      refute AshAi.Tool.has_meta?(tool_without_meta)
    end

    test "tool with _meta has has_meta?/1 return true" do
      tools = AshAi.Info.tools(TestDomain)
      tool_with_meta = Enum.find(tools, &(&1.name == :read_test_resources_with_meta))

      assert AshAi.Tool.has_meta?(tool_with_meta)
    end
  end

  defp context do
    %{actor: nil, tenant: nil, context: %{}, tool_callbacks: %{}}
  end

  defp get_test_tool(opts) do
    tools = AshAi.list_tools(Keyword.merge([actions: [{TestResource, [:read]}]], opts))
    Enum.at(tools, 0)
  end
end
