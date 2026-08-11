# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.ToolTest do
  use ExUnit.Case, async: true

  alias __MODULE__.{IdentityDomain, IdentityResource, TestDomain, TestResource}

  defmodule TestResource do
    use Ash.Resource, domain: TestDomain, data_layer: Ash.DataLayer.Ets

    ets do
      private? true
    end

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

      tool :get_test_resource_by_id, TestResource, :read,
        get_by: :id,
        load: [:internal_status]

      tool :get_test_resource_by_name_and_email, TestResource, :read,
        get_by: [:public_name, :public_email]

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

    ets do
      private? true
    end

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

    test "rejects a non-object input naming the type that arrived" do
      {_tools, registry} =
        AshAi.build_tools_and_registry(actions: [{TestResource, :*}], strict: false)

      for input <- [~s({"public_name": "John"}), [1, 2], true, 42] do
        {:error, error} = registry["read_test_resources"].(%{"input" => input}, context())

        assert error =~ "`input` must be a JSON object"
        assert error =~ "got #{Jason.encode!(input)}"
        refute error =~ "unexpected error occurred"
      end
    end

    test "truncates a long non-object input" do
      {_tools, registry} =
        AshAi.build_tools_and_registry(actions: [{TestResource, :*}], strict: false)

      {:error, error} =
        registry["read_test_resources"].(%{"input" => String.duplicate("a", 500)}, context())

      assert error =~ "`input` must be a JSON object"
      assert error =~ "..."
      assert String.length(error) < 300
    end
  end

  describe "get_by read tools" do
    setup do
      id = Ash.UUIDv7.generate()

      resource =
        TestResource
        |> Ash.Changeset.for_create(:create, %{
          id: id,
          public_name: "Jane #{id}",
          public_email: "jane-#{id}@example.com",
          private_notes: "Private lookup notes",
          internal_status: "reviewed"
        })
        |> Ash.create!(domain: TestDomain)

      %{resource: resource}
    end

    test "schema exposes lookup fields and not list-query controls" do
      tool =
        [actions: [{TestResource, [:read]}], tools: [:get_test_resource_by_id], strict: false]
        |> AshAi.list_tools()
        |> hd()

      props = tool.parameter_schema["properties"]

      assert Map.has_key?(props, "id")
      assert tool.parameter_schema["required"] == ["id"]

      refute Map.has_key?(props, "filter")
      refute Map.has_key?(props, "sort")
      refute Map.has_key?(props, "limit")
      refute Map.has_key?(props, "offset")
      refute Map.has_key?(props, "result_type")
    end

    test "executes by a single lookup field and returns one record", %{resource: resource} do
      {_tools, registry} =
        AshAi.build_tools_and_registry(
          actions: [{TestResource, [:read]}],
          tools: [:get_test_resource_by_id],
          strict: false
        )

      {:ok, json, fetched} =
        registry["get_test_resource_by_id"].(%{"id" => resource.id}, context())

      assert fetched.id == resource.id

      assert json ==
               "{\"id\":\"#{resource.id}\",\"public_name\":\"Jane #{resource.id}\",\"public_email\":\"jane-#{resource.id}@example.com\",\"internal_status\":\"reviewed\"}"
    end

    test "executes by a composite lookup", %{resource: resource} do
      {_tools, registry} =
        AshAi.build_tools_and_registry(
          actions: [{TestResource, [:read]}],
          tools: [:get_test_resource_by_name_and_email],
          strict: false
        )

      {:ok, _json, fetched} =
        registry["get_test_resource_by_name_and_email"].(
          %{
            "public_name" => resource.public_name,
            "public_email" => resource.public_email
          },
          context()
        )

      assert fetched.id == resource.id
    end

    test "returns a tool error when a lookup argument is missing" do
      {_tools, registry} =
        AshAi.build_tools_and_registry(
          actions: [{TestResource, [:read]}],
          tools: [:get_test_resource_by_id],
          strict: false
        )

      assert {:error, "Missing required get_by argument: id"} =
               registry["get_test_resource_by_id"].(%{}, context())
    end

    test "casts lookup values to the field type", %{resource: resource} do
      {_tools, registry} =
        AshAi.build_tools_and_registry(
          actions: [{TestResource, [:read]}],
          tools: [:get_test_resource_by_id],
          strict: false
        )

      assert {:ok, _json, fetched} =
               registry["get_test_resource_by_id"].(
                 %{"id" => String.upcase(resource.id)},
                 context()
               )

      assert fetched.id == resource.id
    end

    test "returns a tool error when a lookup value is not castable" do
      {_tools, registry} =
        AshAi.build_tools_and_registry(
          actions: [{TestResource, [:read]}],
          tools: [:get_test_resource_by_id],
          strict: false
        )

      assert {:error, message} =
               registry["get_test_resource_by_id"].(%{"id" => "not-a-uuid"}, context())

      assert message =~ "Invalid value for get_by argument id"
    end

    test "returns a tool error when no record matches" do
      {_tools, registry} =
        AshAi.build_tools_and_registry(
          actions: [{TestResource, [:read]}],
          tools: [:get_test_resource_by_id],
          strict: false
        )

      assert {:error, message} =
               registry["get_test_resource_by_id"].(
                 %{"id" => "0197b375-4daa-7112-a9d8-7f0104489999"},
                 context()
               )

      assert message =~ "could not be found"
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

  describe "get_by validation" do
    test "rejects non-filterable lookup fields at compile time", %{test: test} do
      domain = Module.concat([__MODULE__, test, Domain])
      resource = Module.concat([__MODULE__, test, Resource])

      assert_raise Spark.Error.DslError, ~r/not filterable/, fn ->
        Module.create(
          resource,
          quote do
            use Ash.Resource,
              domain: unquote(domain),
              extensions: [AshAi],
              data_layer: Ash.DataLayer.Ets,
              validate_domain_inclusion?: false

            attributes do
              uuid_v7_primary_key(:id, writable?: true)
              attribute(:name, :string, public?: true, filterable?: false)
            end

            actions do
              defaults([:read])
            end

            tools do
              tool(:get_by_name, :read, get_by: :name)
            end
          end,
          Macro.Env.location(__ENV__)
        )
      end
    end

    test "rejects relationship lookup fields at compile time", %{test: test} do
      domain = Module.concat([__MODULE__, test, Domain])
      resource = Module.concat([__MODULE__, test, Resource])
      related = Module.concat([__MODULE__, test, Related])

      Module.create(
        related,
        quote do
          use Ash.Resource,
            domain: unquote(domain),
            data_layer: Ash.DataLayer.Ets,
            validate_domain_inclusion?: false

          attributes do
            uuid_v7_primary_key(:id, writable?: true)
            attribute(:parent_id, :uuid, public?: true)
          end

          actions do
            defaults([:read])
          end
        end,
        Macro.Env.location(__ENV__)
      )

      assert_raise Spark.Error.DslError, ~r/cannot `get_by` on the relationship/, fn ->
        Module.create(
          resource,
          quote do
            use Ash.Resource,
              domain: unquote(domain),
              extensions: [AshAi],
              data_layer: Ash.DataLayer.Ets,
              validate_domain_inclusion?: false

            attributes do
              uuid_v7_primary_key(:id, writable?: true)
            end

            relationships do
              has_many(:children, unquote(related),
                public?: true,
                destination_attribute: :parent_id
              )
            end

            actions do
              defaults([:read])
            end

            tools do
              tool(:get_by_children, :read, get_by: :children)
            end
          end,
          Macro.Env.location(__ENV__)
        )
      end
    end

    test "rejects get_by on non-read tools at compile time", %{test: test} do
      domain = Module.concat([__MODULE__, test, Domain])
      resource = Module.concat([__MODULE__, test, Resource])

      assert_raise Spark.Error.DslError, ~r/only be used with read tools/, fn ->
        Module.create(
          resource,
          quote do
            use Ash.Resource,
              domain: unquote(domain),
              extensions: [AshAi],
              data_layer: Ash.DataLayer.Ets,
              validate_domain_inclusion?: false

            attributes do
              uuid_v7_primary_key(:id, writable?: true)
              attribute(:name, :string, public?: true)
            end

            actions do
              defaults([:read, :create])
              default_accept([:name])
            end

            tools do
              tool(:create_by_name, :create, get_by: :name)
            end
          end,
          Macro.Env.location(__ENV__)
        )
      end
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
