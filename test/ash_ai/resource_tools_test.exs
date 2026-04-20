# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.ResourceToolsTest do
  use ExUnit.Case, async: true

  alias __MODULE__.{
    DuplicateNameDomain,
    DuplicateNameResource,
    ResourceToolDomain,
    ResourceToolResource
  }

  defmodule ResourceToolResource do
    use Ash.Resource,
      domain: ResourceToolDomain,
      extensions: [AshAi],
      data_layer: Ash.DataLayer.Ets,
      validate_domain_inclusion?: false

    attributes do
      uuid_v7_primary_key(:id, writable?: true)
      attribute :name, :string, public?: true
    end

    actions do
      default_accept([:id, :name])
      defaults([:read, :create])
    end

    tools do
      tool(:resource_read, :read)
      tool(:resource_create, :create)
    end
  end

  defmodule ResourceToolDomain do
    use Ash.Domain, extensions: [AshAi], validate_config_inclusion?: false

    resources do
      resource ResourceToolResource
    end

    tools do
      tool :domain_create_alias, ResourceToolResource, :create
    end
  end

  defmodule DuplicateNameResource do
    use Ash.Resource,
      domain: DuplicateNameDomain,
      extensions: [AshAi],
      data_layer: Ash.DataLayer.Ets,
      validate_domain_inclusion?: false

    attributes do
      uuid_v7_primary_key(:id, writable?: true)
    end

    actions do
      defaults([:read])
    end

    tools do
      tool(:duplicate_name, :read)
    end
  end

  defmodule DuplicateNameDomain do
    use Ash.Domain, extensions: [AshAi], validate_config_inclusion?: false

    resources do
      resource DuplicateNameResource
    end

    tools do
      tool :duplicate_name, DuplicateNameResource, :read,
        description: "Domain-level tool description"
    end
  end

  describe "resource-level tools shorthand" do
    test "tool :name, :action populates resource and action metadata" do
      tool =
        ResourceToolResource
        |> AshAi.Info.tools()
        |> Enum.find(&(&1.name == :resource_read))

      assert tool.resource == ResourceToolResource
      assert tool.action == :read
    end

    test "resource-level tools reject explicit resource argument" do
      module =
        Module.concat(__MODULE__, :"InvalidResourceTool#{System.unique_integer([:positive])}")

      assert_raise Spark.Error.DslError, ~r/Resource-level tools cannot set `resource`/, fn ->
        Module.create(
          module,
          quote do
            use Ash.Resource,
              domain: ResourceToolDomain,
              extensions: [AshAi],
              data_layer: Ash.DataLayer.Ets,
              validate_domain_inclusion?: false

            attributes do
              uuid_v7_primary_key(:id, writable?: true)
            end

            actions do
              defaults([:read])
            end

            tools do
              tool :resource_read, ResourceToolResource, :read
            end
          end,
          Macro.Env.location(__ENV__)
        )
      end
    end
  end

  describe "domain-level tools requirements" do
    test "domain-level tools require resource argument" do
      module =
        Module.concat(__MODULE__, :"InvalidDomainTool#{System.unique_integer([:positive])}")

      assert_raise Spark.Error.DslError, ~r/is missing a resource/, fn ->
        Module.create(
          module,
          quote do
            use Ash.Domain, extensions: [AshAi], validate_config_inclusion?: false

            tools do
              tool(:missing_resource, :read)
            end
          end,
          Macro.Env.location(__ENV__)
        )
      end
    end
  end

  describe "AshAi.exposed_tools/1 discovery" do
    test "actions filter includes both domain-level and resource-level tools" do
      tools = AshAi.exposed_tools(actions: [{ResourceToolResource, :*}])

      assert tools
             |> Enum.map(& &1.name)
             |> MapSet.new() ==
               MapSet.new([:resource_read, :resource_create, :domain_create_alias])
    end

    test "actions filter by specific action keeps matching tools from both levels" do
      tools = AshAi.exposed_tools(actions: [{ResourceToolResource, [:create]}])

      assert tools
             |> Enum.map(& &1.name)
             |> MapSet.new() == MapSet.new([:resource_create, :domain_create_alias])
    end

    test "raises for duplicate tool names across domain and resource definitions" do
      assert_raise ArgumentError, ~r/Duplicate tool names found/, fn ->
        AshAi.exposed_tools(actions: [{DuplicateNameResource, :*}])
      end
    end
  end
end
