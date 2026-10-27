# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.ToolQueryFieldsTest do
  use ExUnit.Case, async: true

  alias __MODULE__.{Domain, Widget}

  defmodule Widget do
    use Ash.Resource,
      domain: Domain,
      data_layer: Ash.DataLayer.Ets,
      validate_domain_inclusion?: false

    ets do
      private? true
    end

    attributes do
      uuid_primary_key :id
      attribute :name, :string, public?: true
      attribute :price, :integer, public?: true
      attribute :notes, :string, public?: true, filterable?: false
      attribute :secret, :string
    end

    actions do
      default_accept [:name, :price, :notes, :secret]
      defaults [:read, :create]
    end
  end

  defmodule Domain do
    use Ash.Domain, extensions: [AshAi], validate_config_inclusion?: false

    resources do
      resource Widget
    end

    tools do
      tool :read_widgets, Widget, :read

      tool :read_narrow, Widget, :read,
        filterable_fields: [:name],
        sortable_fields: [:price],
        aggregatable_fields: [:price]

      tool :filter_only, Widget, :read,
        filterable_fields: [:name],
        sortable_fields: [],
        aggregatable_fields: []

      tool :read_compact, Widget, :read, compact_field_list?: true

      tool :read_narrow_compact, Widget, :read,
        filterable_fields: [:name],
        sortable_fields: [:price],
        aggregatable_fields: [:price],
        compact_field_list?: true

      tool :sort_only_compact, Widget, :read,
        action_parameters: [:sort],
        compact_field_list?: true

      tool :filter_only_compact, Widget, :read,
        filterable_fields: [:name],
        sortable_fields: [],
        aggregatable_fields: [],
        compact_field_list?: true

      tool :read_narrow_full, Widget, :read,
        filterable_fields: [:name],
        sortable_fields: [:price],
        aggregatable_fields: [:price],
        full_filter_schema?: true,
        compact_field_list?: true
    end
  end

  describe "schema" do
    test "allow-lists narrow each list in the default schema" do
      schema = schema(:read_narrow)

      refute Map.has_key?(schema, "description")
      assert schema["properties"]["filter"]["description"] =~ "Fields: name."
      assert schema["properties"]["sort"]["items"]["properties"]["field"]["enum"] == ["price"]

      aggregate_option =
        Enum.find(schema["properties"]["result_type"]["oneOf"], &Map.has_key?(&1, "properties"))

      assert aggregate_option["properties"]["field"]["enum"] == ["price"]
    end

    test "empty allow-lists drop the parameters they would feed" do
      for name <- [:filter_only, :filter_only_compact] do
        schema = schema(name)

        refute Map.has_key?(schema["properties"], "sort")
        assert schema["properties"]["result_type"]["enum"] == ["run_query", "count", "exists"]
      end
    end

    test "compact schemas list every queryable field once, annotated only when its uses differ" do
      schema = schema(:read_compact)

      assert schema["description"] ==
               "Fields that can be used to filter, sort or aggregate: " <>
                 "id, name, price, notes (sort and aggregate only)."

      refute schema["description"] =~ "secret"
    end

    test "allow-lists narrow the compact field list" do
      assert schema(:read_narrow_compact)["description"] ==
               "Fields that can be used to filter, sort or aggregate: " <>
                 "name (filter only), price (sort and aggregate only)."

      assert schema(:filter_only_compact)["description"] ==
               "Fields that can be used to filter: name."
    end

    test "compact schemas only describe the uses the tool offers" do
      assert schema(:sort_only_compact)["description"] ==
               "Fields that can be used to sort: id, name, price, notes."
    end

    test "compact field parameters refer to the list instead of repeating it" do
      schema = schema(:read_narrow_compact)
      sort_field = schema["properties"]["sort"]["items"]["properties"]["field"]

      refute Map.has_key?(sort_field, "enum")
      assert sort_field["description"] =~ "field list"
      refute schema["properties"]["filter"]["description"] =~ "Fields: name"
    end

    test "the fully-specified schema keeps narrowed enums and no field list" do
      schema = schema(:read_narrow_full)

      refute Map.has_key?(schema, "description")
      assert Map.keys(schema["properties"]["filter"]["properties"]) == ["name"]

      assert schema["properties"]["sort"]["items"]["properties"]["field"]["enum"] == ["price"]

      aggregate_option =
        Enum.find(schema["properties"]["result_type"]["oneOf"], &Map.has_key?(&1, "properties"))

      assert aggregate_option["properties"]["field"]["enum"] == ["price"]
    end
  end

  describe "execution" do
    setup do
      Ash.create!(Widget, %{name: "a", price: 1})
      Ash.create!(Widget, %{name: "b", price: 2})
      :ok
    end

    test "fields in the allow-lists are accepted" do
      assert {:ok, json, _} =
               execute(:read_narrow, %{
                 "filter" => %{"field" => "name", "operator" => "eq", "value" => "b"},
                 "sort" => [%{"field" => "price", "direction" => "desc"}]
               })

      assert %{"results" => [%{"name" => "b"}]} = Jason.decode!(json)

      assert {:ok, "2", _} =
               execute(:read_narrow, %{
                 "result_type" => %{"aggregate" => "max", "field" => "price"}
               })
    end

    test "filters on other fields are refused, however they are nested" do
      for filter <- [
            %{"field" => "price", "operator" => "eq", "value" => 1},
            %{
              "and" => [
                %{"field" => "name", "operator" => "eq", "value" => "a"},
                %{"price" => %{"eq" => 1}}
              ]
            },
            [%{"or" => [%{"not" => %{"price" => %{"eq" => 1}}}]}]
          ] do
        assert {:error, "Cannot filter on `price`. Allowed fields: name"} =
                 execute(:read_narrow, %{"filter" => filter})
      end
    end

    test "sorts on other fields are refused" do
      assert {:error, "Cannot sort on `name`. Allowed fields: price"} =
               execute(:read_narrow, %{"sort" => [%{"field" => "name", "direction" => "asc"}]})
    end

    test "aggregates of other fields are refused" do
      assert {:error, "Cannot aggregate `name`. Allowed fields: price"} =
               execute(:read_narrow, %{
                 "result_type" => %{"aggregate" => "max", "field" => "name"}
               })
    end

    test "tools without allow-lists are unaffected" do
      assert {:ok, json, _} =
               execute(:read_widgets, %{
                 "filter" => %{"field" => "price", "operator" => "eq", "value" => 1},
                 "sort" => [%{"field" => "name", "direction" => "asc"}]
               })

      assert %{"results" => [%{"name" => "a"}]} = Jason.decode!(json)
    end
  end

  describe "compile-time validation" do
    test "rejects unknown fields" do
      assert_raise Spark.Error.DslError, ~r/`:nope` is not a valid attribute/, fn ->
        define_domain(quote(do: tool(:t, Widget, :read, filterable_fields: [:nope])))
      end
    end

    test "rejects private fields" do
      assert_raise Spark.Error.DslError, ~r/`:secret` is not public/, fn ->
        define_domain(quote(do: tool(:t, Widget, :read, sortable_fields: [:secret])))
      end
    end

    test "rejects fields that do not allow the use" do
      assert_raise Spark.Error.DslError, ~r/`:notes` cannot be filtered on/, fn ->
        define_domain(quote(do: tool(:t, Widget, :read, filterable_fields: [:notes])))
      end
    end

    test "rejects allow-lists on tools that are not query reads" do
      assert_raise Spark.Error.DslError, ~r/can only be used with read tools/, fn ->
        define_domain(quote(do: tool(:t, Widget, :create, sortable_fields: [:price])))
      end

      assert_raise Spark.Error.DslError, ~r/cannot be combined with `get_by`/, fn ->
        define_domain(quote(do: tool(:t, Widget, :read, get_by: :id, sortable_fields: [:price])))
      end
    end
  end

  defp tool(name) do
    [actions: [{Widget, :*}], tools: [name]]
    |> AshAi.exposed_tools()
    |> hd()
  end

  defp schema(name), do: name |> tool() |> AshAi.Tools.parameter_schema(strict: false)

  defp execute(name, arguments), do: name |> tool() |> AshAi.Tools.execute(arguments, %{})

  defp define_domain(tool) do
    Module.create(
      Module.concat(__MODULE__, :"Domain#{System.unique_integer([:positive])}"),
      quote do
        use Ash.Domain, extensions: [AshAi], validate_config_inclusion?: false

        resources do
          resource unquote(Widget)
        end

        tools do
          unquote(tool)
        end
      end,
      Macro.Env.location(__ENV__)
    )
  end
end
