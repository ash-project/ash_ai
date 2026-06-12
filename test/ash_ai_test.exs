# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAiTest do
  use ExUnit.Case, async: true

  alias __MODULE__.{Album, Artist, Music}

  defmodule Artist do
    use Ash.Resource, domain: Music, data_layer: Ash.DataLayer.Ets

    ets do
      private?(true)
    end

    attributes do
      uuid_v7_primary_key(:id, writable?: true)
      attribute(:name, :string, public?: true)
    end

    actions do
      default_accept([:*])
      defaults([:create, :read, :update, :destroy])

      action :say_hello, :string do
        description("Say hello")
        argument(:name, :string, allow_nil?: false)

        run(fn input, _ ->
          {:ok, "Hello, #{input.arguments.name}!"}
        end)
      end

      action :check_context, :map do
        run(fn _input, context ->
          {:ok, %{context: context.source_context}}
        end)
      end
    end

    relationships do
      has_many(:albums, Album)
    end

    aggregates do
      count(:albums_count, :albums, public?: true, sortable?: false)

      sum(:albums_copies_sold, :albums, :copies_sold,
        default: 0,
        public?: true,
        filterable?: false
      )
    end
  end

  defmodule Album do
    use Ash.Resource, domain: Music, data_layer: Ash.DataLayer.Ets

    ets do
      private?(true)
    end

    attributes do
      uuid_primary_key(:id, writable?: true)
      attribute(:title, :string)
      attribute(:copies_sold, :integer)
    end

    relationships do
      belongs_to(:artist, Artist)
    end

    actions do
      default_accept([:*])
      defaults([:create, :read, :update, :destroy])
    end
  end

  defmodule Music do
    use Ash.Domain, extensions: [AshAi]

    resources do
      resource(Artist)
      resource(Album)
    end

    @artist_load [:albums_count]
    tools do
      tool(:list_artists, Artist, :read, load: @artist_load, async: false)
      tool(:create_artist, Artist, :create, load: @artist_load, async: false)
      tool(:update_artist, Artist, :update, load: @artist_load, async: false)
      tool(:delete_artist, Artist, :destroy, load: @artist_load, async: false)
      tool(:say_hello, Artist, :say_hello, load: @artist_load, async: false)
      tool(:check_context, Artist, :check_context, async: false)
    end
  end

  describe "list_tools/1" do
    test "returns ReqLLM tools with expected schema" do
      tools = AshAi.list_tools(actions: [{Artist, :*}], strict: false)

      assert is_list(tools)
      assert Enum.all?(tools, &match?(%ReqLLM.Tool{}, &1))

      read_tool = Enum.find(tools, &(&1.name == "list_artists"))
      assert read_tool

      schema = read_tool.parameter_schema
      assert schema["type"] == "object"
      assert schema["properties"]["filter"]["type"] == "object"
      assert Map.has_key?(schema["properties"], "result_type")
      assert Map.has_key?(schema["properties"], "limit")
      assert Map.has_key?(schema["properties"], "offset")
      assert Map.has_key?(schema["properties"], "sort")
    end

    test "filter schema defaults to a compact described object in both modes" do
      strict_tools = AshAi.list_tools(actions: [{Artist, [:read]}], strict: true)
      relaxed_tools = AshAi.list_tools(actions: [{Artist, [:read]}], strict: false)

      strict_filter = hd(strict_tools).parameter_schema["properties"]["filter"]
      relaxed_filter = hd(relaxed_tools).parameter_schema["properties"]["filter"]

      # strict mode makes the optional filter nullable
      assert strict_filter["type"] == ["object", "null"]
      assert strict_filter["description"] =~ ~s({"and": [...]})
      refute Map.has_key?(strict_filter, "properties")

      assert relaxed_filter["type"] == "object"
      assert relaxed_filter["description"] =~ "Operators:"
    end

    test "action_parameters can restrict result types" do
      tool =
        [actions: [{Artist, [:read]}]]
        |> AshAi.exposed_tools()
        |> hd()
        |> struct(action_parameters: [:filter, :limit, result_type: [:count]])

      schema = AshAi.Tools.parameter_schema(tool, strict: true)

      # strict mode makes the optional result_type nullable, including in the enum
      result_type = schema["properties"]["result_type"]
      assert result_type["type"] == ["string", "null"]
      assert result_type["enum"] == ["run_query", "count", nil]
      refute Map.has_key?(schema["properties"], "sort")
      refute Map.has_key?(schema["properties"], "offset")
      assert Map.has_key?(schema["properties"], "filter")
      assert Map.has_key?(schema["properties"], "limit")
    end

    test "full_filter_schema? generates the full strict filter schema" do
      tool =
        [actions: [{Artist, [:read]}]]
        |> AshAi.exposed_tools()
        |> hd()
        |> struct(full_filter_schema?: true)

      filter = AshAi.Tools.parameter_schema(tool, strict: true)["properties"]["filter"]

      assert filter["type"] == ["array", "null"]
      condition = Enum.find(filter["items"]["anyOf"], & &1["properties"]["field"])
      assert condition["properties"]["operator"]["enum"] != []
    end
  end

  describe "build_tools_and_registry/1" do
    setup do
      artist =
        Artist
        |> Ash.Changeset.for_create(:create, %{name: "Chet Baker"})
        |> Ash.create!()

      %{artist: artist}
    end

    test "executes CRUD and generic action callbacks", %{artist: artist} do
      {_tools, registry} =
        AshAi.build_tools_and_registry(actions: [{Artist, :*}], strict: false)

      context = %{actor: nil, tenant: nil, context: %{}, tool_callbacks: %{}}

      {:ok, created_json, created_raw} =
        registry["create_artist"].(%{"input" => %{"name" => "Chat Faker"}}, context)

      assert created_raw.name == "Chat Faker"
      assert is_binary(created_json)

      {:ok, updated_json, updated_raw} =
        registry["update_artist"].(
          %{"id" => artist.id, "input" => %{"name" => "Updated"}},
          context
        )

      assert updated_raw.id == artist.id
      assert updated_raw.name == "Updated"
      assert is_binary(updated_json)

      {:ok, read_json, read_raw} =
        registry["list_artists"].(%{"filter" => %{"id" => %{"eq" => artist.id}}}, context)

      assert is_binary(read_json)
      assert is_list(read_raw)
      assert Enum.any?(read_raw, &(&1.id == artist.id))

      {:ok, say_hello_json, _} =
        registry["say_hello"].(%{"input" => %{"name" => "Ash"}}, context)

      assert say_hello_json == "\"Hello, Ash!\""

      {:ok, deleted_json, deleted_raw} = registry["delete_artist"].(%{"id" => artist.id}, context)
      assert deleted_raw.id == artist.id
      assert is_binary(deleted_json)
    end

    test "filters with condition objects and nested and/or groups", %{artist: artist} do
      {_tools, registry} =
        AshAi.build_tools_and_registry(actions: [{Artist, [:read]}], strict: false)

      context = %{actor: nil, tenant: nil, context: %{}, tool_callbacks: %{}}

      condition = %{"field" => "name", "operator" => "eq", "value" => artist.name}

      {:ok, _json, found} = registry["list_artists"].(%{"filter" => condition}, context)
      assert Enum.any?(found, &(&1.id == artist.id))

      grouped = %{
        "and" => [
          %{
            "or" => [
              condition,
              %{"field" => "name", "operator" => "eq", "value" => "nonexistent"}
            ]
          },
          %{"field" => "id", "operator" => "eq", "value" => artist.id}
        ]
      }

      {:ok, _json, found} = registry["list_artists"].(%{"filter" => grouped}, context)
      assert Enum.any?(found, &(&1.id == artist.id))

      excluded = %{
        "or" => [
          %{"field" => "name", "operator" => "eq", "value" => "nonexistent"},
          %{"field" => "name", "operator" => "eq", "value" => "also nonexistent"}
        ]
      }

      {:ok, _json, found} = registry["list_artists"].(%{"filter" => excluded}, context)
      refute Enum.any?(found, &(&1.id == artist.id))
    end

    test "passes source context to action execution" do
      custom_context = %{shared: %{conversation_id: "test-123", user_id: 42}}

      {_tools, registry} =
        AshAi.build_tools_and_registry(
          actions: [{Artist, [:check_context]}],
          context: custom_context
        )

      {:ok, json, raw} =
        registry["check_context"].(
          %{},
          %{actor: nil, tenant: nil, context: custom_context, tool_callbacks: %{}}
        )

      assert raw.context.shared == custom_context.shared
      assert is_binary(json)
    end
  end
end
