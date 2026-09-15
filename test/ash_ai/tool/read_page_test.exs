# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Tool.ReadPageTest do
  use ExUnit.Case, async: true

  alias __MODULE__.{BothResource, Domain, KeysetResource, OffsetResource, PlainResource}

  defmodule PlainResource do
    use Ash.Resource, domain: Domain, data_layer: Ash.DataLayer.Ets

    ets do
      private? true
    end

    attributes do
      uuid_v7_primary_key :id
      attribute :name, :string, public?: true
    end

    actions do
      defaults create: [:name]

      # `defaults [:read]` would configure offset and keyset pagination; this
      # action has none, so the tool returns a bare list.
      read :read do
        primary? true
      end
    end
  end

  defmodule OffsetResource do
    use Ash.Resource, domain: Domain, data_layer: Ash.DataLayer.Ets

    ets do
      private? true
    end

    attributes do
      uuid_v7_primary_key :id
      attribute :name, :string, public?: true
    end

    actions do
      defaults create: [:name]

      read :read do
        primary? true
        pagination offset?: true, default_limit: 2, max_page_size: 3, countable: :by_default
      end
    end
  end

  defmodule KeysetResource do
    use Ash.Resource, domain: Domain, data_layer: Ash.DataLayer.Ets

    ets do
      private? true
    end

    attributes do
      uuid_v7_primary_key :id
      attribute :name, :string, public?: true
    end

    actions do
      defaults create: [:name]

      read :read do
        primary? true
        pagination keyset?: true, default_limit: 2
      end
    end
  end

  defmodule BothResource do
    use Ash.Resource, domain: Domain, data_layer: Ash.DataLayer.Ets

    ets do
      private? true
    end

    attributes do
      uuid_v7_primary_key :id
      attribute :name, :string, public?: true
    end

    actions do
      defaults create: [:name]

      read :read do
        primary? true
        pagination offset?: true, keyset?: true, default_limit: 2
      end
    end
  end

  defmodule Domain do
    use Ash.Domain, extensions: [AshAi]

    resources do
      resource PlainResource
      resource OffsetResource
      resource KeysetResource
      resource BothResource
    end

    tools do
      tool :read_plain, PlainResource, :read
      tool :read_offset, OffsetResource, :read
      tool :read_keyset, KeysetResource, :read
      tool :read_both, BothResource, :read

      tool :read_both_restricted, BothResource, :read, action_parameters: [:filter, :limit]
      tool :read_plain_restricted, PlainResource, :read, action_parameters: [:filter, :limit]
    end
  end

  @resources [PlainResource, OffsetResource, KeysetResource, BothResource]
  @sort [%{"field" => "name", "direction" => "asc"}]

  setup do
    for resource <- @resources, name <- ["a", "b", "c"] do
      Ash.create!(resource, %{name: name}, domain: Domain)
    end

    {tools, registry} =
      AshAi.build_tools_and_registry(
        actions: Enum.map(@resources, &{&1, :*}),
        strict: false
      )

    %{registry: registry, tools: tools}
  end

  describe "non-paginated actions" do
    test "return a bare list and apply limit/offset directly", %{registry: registry} do
      {:ok, json, raw} = registry["read_plain"].(%{"sort" => @sort}, context())

      assert Enum.map(Jason.decode!(json), & &1["name"]) == ["a", "b", "c"]
      assert Enum.map(raw, & &1.name) == ["a", "b", "c"]

      {:ok, json, _raw} =
        registry["read_plain"].(%{"sort" => @sort, "limit" => 1, "offset" => 1}, context())

      assert Enum.map(Jason.decode!(json), & &1["name"]) == ["b"]
    end

    test "expose offset but no keyset cursors", %{tools: tools} do
      props = schema_properties(tools, "read_plain")

      assert Map.has_key?(props, "offset")
      refute Map.has_key?(props, "after")
      refute Map.has_key?(props, "before")
    end
  end

  describe "offset-paginated actions" do
    test "return a page with the action's default_limit and a count when countable by default",
         %{registry: registry} do
      {:ok, json, %Ash.Page.Offset{} = page} =
        registry["read_offset"].(%{"sort" => @sort}, context())

      assert Jason.decode!(json) == %{
               "results" => Enum.map(page.results, &%{"id" => &1.id, "name" => &1.name}),
               "limit" => 2,
               "offset" => 0,
               "has_more" => true,
               "next_offset" => 2,
               "count" => 3
             }

      assert Enum.map(page.results, & &1.name) == ["a", "b"]
    end

    test "next_offset fetches the following page", %{registry: registry} do
      {:ok, json, _page} =
        registry["read_offset"].(%{"sort" => @sort, "offset" => 2}, context())

      page = Jason.decode!(json)

      assert Enum.map(page["results"], & &1["name"]) == ["c"]
      assert page["offset"] == 2
      assert page["has_more"] == false
      assert page["next_offset"] == nil
    end

    test "count reflects the filter, not the page", %{registry: registry} do
      {:ok, json, _page} =
        registry["read_offset"].(
          %{
            "sort" => @sort,
            "limit" => 1,
            "filter" => [%{"field" => "name", "operator" => "in", "value" => ["a", "b"]}]
          },
          context()
        )

      page = Jason.decode!(json)

      assert Enum.map(page["results"], & &1["name"]) == ["a"]
      assert page["has_more"] == true
      assert page["count"] == 2
    end

    test "caps the requested limit at max_page_size", %{registry: registry} do
      {:ok, json, _page} =
        registry["read_offset"].(%{"sort" => @sort, "limit" => 50}, context())

      page = Jason.decode!(json)

      assert page["limit"] == 3
      assert length(page["results"]) == 3
      assert page["has_more"] == false
    end

    test "expose offset but no keyset cursors", %{tools: tools} do
      props = schema_properties(tools, "read_offset")

      assert props["limit"]["default"] == 2
      assert Map.has_key?(props, "offset")
      refute Map.has_key?(props, "after")
      refute Map.has_key?(props, "before")
    end
  end

  describe "keyset-paginated actions" do
    test "return a page with keyset cursors and no count unless countable by default",
         %{registry: registry} do
      {:ok, json, %Ash.Page.Keyset{} = page} =
        registry["read_keyset"].(%{"sort" => @sort}, context())

      decoded = Jason.decode!(json)

      assert Enum.map(decoded["results"], & &1["name"]) == ["a", "b"]
      assert decoded["limit"] == 2
      assert decoded["has_more"] == true
      assert decoded["start_keyset"] == List.first(page.results).__metadata__.keyset
      assert decoded["end_keyset"] == List.last(page.results).__metadata__.keyset
      refute Map.has_key?(decoded, "count")
      refute Map.has_key?(decoded, "offset")
    end

    test "end_keyset fetches the following page, start_keyset the preceding one",
         %{registry: registry} do
      {:ok, json, _page} = registry["read_keyset"].(%{"sort" => @sort}, context())
      first = Jason.decode!(json)

      {:ok, json, _page} =
        registry["read_keyset"].(%{"sort" => @sort, "after" => first["end_keyset"]}, context())

      second = Jason.decode!(json)

      assert Enum.map(second["results"], & &1["name"]) == ["c"]
      assert second["has_more"] == false

      {:ok, json, _page} =
        registry["read_keyset"].(
          %{"sort" => @sort, "before" => second["start_keyset"]},
          context()
        )

      assert Enum.map(Jason.decode!(json)["results"], & &1["name"]) == ["a", "b"]
    end

    test "returns a tool error for an invalid cursor", %{registry: registry} do
      {:error, error} = registry["read_keyset"].(%{"after" => "not-a-keyset"}, context())

      assert is_binary(error)
    end

    test "expose keyset cursors but no offset", %{tools: tools} do
      props = schema_properties(tools, "read_keyset")

      refute Map.has_key?(props, "offset")
      assert props["after"]["type"] == "string"
      assert props["before"]["type"] == "string"
    end
  end

  describe "actions supporting both offset and keyset pagination" do
    test "default to keyset pagination, even when offset 0 is passed", %{registry: registry} do
      {:ok, json, %Ash.Page.Keyset{}} = registry["read_both"].(%{"sort" => @sort}, context())
      first = Jason.decode!(json)
      assert first["has_more"] == true
      refute Map.has_key?(first, "next_offset")

      {:ok, _json, %Ash.Page.Keyset{}} =
        registry["read_both"].(%{"sort" => @sort, "offset" => 0}, context())

      {:ok, json, %Ash.Page.Keyset{}} =
        registry["read_both"].(%{"sort" => @sort, "after" => first["end_keyset"]}, context())

      assert Enum.map(Jason.decode!(json)["results"], & &1["name"]) == ["c"]
    end

    test "switch to offset pagination when a positive offset is passed", %{registry: registry} do
      {:ok, json, %Ash.Page.Offset{}} =
        registry["read_both"].(%{"sort" => @sort, "offset" => 1, "limit" => 1}, context())

      page = Jason.decode!(json)
      assert Enum.map(page["results"], & &1["name"]) == ["b"]
      assert page["next_offset"] == 2
    end

    test "expose offset and keyset cursors", %{tools: tools} do
      props = schema_properties(tools, "read_both")

      assert Map.has_key?(props, "offset")
      assert Map.has_key?(props, "after")
      assert Map.has_key?(props, "before")
    end

    test "action_parameters cannot hide the page controls of a paginated action",
         %{registry: registry, tools: tools} do
      props = schema_properties(tools, "read_both_restricted")

      refute Map.has_key?(props, "sort")
      assert Map.has_key?(props, "offset")
      assert Map.has_key?(props, "after")
      assert Map.has_key?(props, "before")

      {:ok, json, %Ash.Page.Keyset{}} =
        registry["read_both_restricted"].(%{"limit" => 2}, context())

      assert Jason.decode!(json)["has_more"] == true
    end

    test "action_parameters still hides offset on a non-paginated action", %{tools: tools} do
      props = schema_properties(tools, "read_plain_restricted")

      refute Map.has_key?(props, "offset")
      assert Map.has_key?(props, "limit")
    end
  end

  describe "conflicting or unsupported paging controls" do
    test "reject after together with before", %{registry: registry} do
      {:error, error} =
        registry["read_keyset"].(%{"after" => "abc", "before" => "def"}, context())

      assert error == "Pass either `after` or `before`, not both."
    end

    test "reject a cursor together with a positive offset", %{registry: registry} do
      {:error, error} = registry["read_both"].(%{"after" => "abc", "offset" => 5}, context())

      assert error =~ "not both"
    end

    test "allow a cursor together with the default offset of 0", %{registry: registry} do
      {:ok, json, %Ash.Page.Keyset{}} = registry["read_both"].(%{"sort" => @sort}, context())

      {:ok, _json, %Ash.Page.Keyset{}} =
        registry["read_both"].(
          %{"sort" => @sort, "after" => Jason.decode!(json)["end_keyset"], "offset" => 0},
          context()
        )
    end

    test "reject cursors on an offset-only action", %{registry: registry} do
      {:error, error} = registry["read_offset"].(%{"after" => "abc"}, context())

      assert error =~ "does not support keyset pagination"
    end

    test "reject a positive offset on a keyset-only action", %{registry: registry} do
      {:error, error} = registry["read_keyset"].(%{"offset" => 2}, context())

      assert error =~ "does not support offset pagination"
    end
  end

  test "other result types are returned directly", %{registry: registry} do
    {:ok, "3", 3} = registry["read_offset"].(%{"result_type" => "count"}, context())
    {:ok, "true", true} = registry["read_keyset"].(%{"result_type" => "exists"}, context())
  end

  test "pages are exposed as structured content when not encoded" do
    tool =
      Enum.find(AshAi.exposed_tools(actions: [{OffsetResource, :*}]), &(&1.name == :read_offset))

    {:ok, result, %Ash.Page.Offset{}} =
      AshAi.Tools.execute(tool, %{"limit" => 1}, context(), encode?: false)

    assert %{"results" => [_], "has_more" => true, "next_offset" => 1, "count" => 3} = result
  end

  defp schema_properties(tools, name) do
    tools
    |> Enum.find(&(&1.name == name))
    |> Map.fetch!(:parameter_schema)
    |> Map.fetch!("properties")
  end

  defp context, do: %{actor: nil, tenant: nil}
end
