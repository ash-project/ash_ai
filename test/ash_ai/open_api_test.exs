# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.OpenApiTest do
  use ExUnit.Case, async: true

  alias __MODULE__.{Music, Artist, Album}

  defmodule Bio do
    use Ash.Resource, data_layer: :embedded

    attributes do
      attribute :birth, :date, allow_nil?: false, public?: true
    end
  end

  defmodule Artist do
    use Ash.Resource,
      domain: Music,
      data_layer: Ash.DataLayer.Ets

    ets do
      private? true
    end

    attributes do
      uuid_v7_primary_key :id, writable?: true
      attribute :name, :string, public?: true
      attribute :bio, Bio, allow_nil?: false, public?: true
    end

    actions do
      default_accept [:*]
      defaults [:create, :read, :update, :destroy]

      action :say_hello, :string do
        description "Say hello"
        argument :name, :string, allow_nil?: false

        run fn input, _ ->
          {:ok, "Hello, #{input.arguments.name}!"}
        end
      end
    end

    relationships do
      has_many :albums, Album
    end

    aggregates do
      count :albums_count, :albums, public?: true, sortable?: false

      sum :albums_copies_sold, :albums, :copies_sold,
        default: 0,
        public?: true,
        filterable?: false
    end
  end

  defmodule Album do
    use Ash.Resource,
      domain: Music,
      data_layer: Ash.DataLayer.Ets

    ets do
      private? true
    end

    attributes do
      uuid_primary_key :id, writable?: true
      attribute :title, :string
      attribute :copies_sold, :integer
    end

    relationships do
      belongs_to :artist, Artist
    end

    actions do
      default_accept [:*]
      defaults [:create, :read, :update, :destroy]
    end
  end

  defmodule FlexibleValue do
    use Ash.Type.NewType,
      subtype_of: :union,
      constraints: [
        types: [
          text: [type: :string],
          number: [type: :integer]
        ]
      ]
  end

  defmodule Widget do
    use Ash.Resource,
      domain: Music,
      data_layer: Ash.DataLayer.Ets

    ets do
      private? true
    end

    attributes do
      uuid_v7_primary_key :id, writable?: true
      attribute :name, :string, public?: true
      attribute :payload, FlexibleValue, public?: true

      attribute :raw_payload, :union,
        public?: true,
        constraints: [types: [text: [type: :string], number: [type: :integer]]]

      attribute :payloads, {:array, FlexibleValue}, public?: true
    end

    actions do
      default_accept [:*]
      defaults [:create, :read]
    end
  end

  defmodule Music do
    use Ash.Domain,
      extensions: [AshAi]

    tools do
      tool :list_widgets, Widget, :read
    end

    resources do
      resource Artist
      resource Album
      resource Widget
    end
  end

  defmodule Sentiment do
    use Ash.Resource, data_layer: :embedded

    attributes do
      attribute :sentiment, :string, public?: true
      attribute :confidence, :float, public?: true
      attribute :keywords, {:array, :string}, public?: true
    end

    actions do
      default_accept [:*]
      defaults [:create, :read]
    end
  end

  defmodule TestResource do
    use Ash.Resource,
      domain: TestDomain,
      data_layer: Ash.DataLayer.Ets,
      extensions: [AshAi]

    ets do
      private? true
    end

    attributes do
      uuid_v7_primary_key :id, writable?: true
      attribute :name, :string, public?: true, description: "The name of the test resource"
    end

    actions do
      default_accept [:*]

      action :analyze_sentiment, Sentiment do
        description "Analyze the sentiment of a given text"
        argument :text, :string, allow_nil?: false

        run prompt("openai:gpt-4o",
              req_llm: AshAi.OpenApiTest.FakeReqLLM
            )
      end
    end
  end

  defmodule FakeReqLLM do
    def generate_object(_model, _context, _schema, _opts \\ []) do
      {:ok,
       %{
         object: %{
           "result" => %{
             "sentiment" => "positive",
             "confidence" => 0.92,
             "keywords" => ["excellent", "wonderful", "fantastic"]
           }
         }
       }}
    end
  end

  defmodule TestDomain do
    use Ash.Domain,
      extensions: [AshAi],
      validate_config_inclusion?: false

    resources do
      resource TestResource
    end
  end

  describe "resource_write_attribute_type/3" do
    test "with TestResource" do
      resource = TestResource

      action = resource |> Ash.Resource.Info.action(:analyze_sentiment)

      assert get_parameter_schema_properties(
               action,
               resource,
               &AshAi.OpenApi.resource_write_attribute_type/3
             ) == %{text: %{type: :string}}
    end

    test "with Artist" do
      resource = Artist

      create_action = resource |> Ash.Resource.Info.action(:create)

      assert get_parameter_schema_properties(
               create_action,
               resource,
               &AshAi.OpenApi.resource_write_attribute_type/3
             ) == %{
               id: %{type: :string, format: :uuid},
               name: %{type: :string},
               bio: %{
                 type: :object,
                 properties: %{birth: %{type: :string, format: :date}},
                 required: [:birth],
                 additionalProperties: false
               }
             }

      update_action = resource |> Ash.Resource.Info.action(:update)

      assert get_parameter_schema_properties(
               update_action,
               resource,
               &AshAi.OpenApi.resource_write_attribute_type/3
             ) == %{
               id: %{type: :string, format: :uuid},
               name: %{type: :string},
               bio: %{
                 type: :object,
                 properties: %{
                   birth: %{"anyOf" => [%{type: :string, format: :date}, %{"type" => "null"}]}
                 },
                 required: [:birth],
                 additionalProperties: false
               }
             }

      destroy_action = resource |> Ash.Resource.Info.action(:destroy)

      assert get_parameter_schema_properties(
               destroy_action,
               resource,
               &AshAi.OpenApi.resource_write_attribute_type/3
             ) == %{}

      read_action = resource |> Ash.Resource.Info.action(:read)

      assert get_parameter_schema_properties(
               read_action,
               resource,
               &AshAi.OpenApi.resource_write_attribute_type/3
             ) == %{}

      say_hello_action = resource |> Ash.Resource.Info.action(:say_hello)

      assert get_parameter_schema_properties(
               say_hello_action,
               resource,
               &AshAi.OpenApi.resource_write_attribute_type/3
             ) == %{name: %{type: :string}}
    end

    test "with Album" do
      resource = Album

      create_action = resource |> Ash.Resource.Info.action(:create)

      assert get_parameter_schema_properties(
               create_action,
               resource,
               &AshAi.OpenApi.resource_write_attribute_type/3
             ) == %{id: %{type: :string, format: :uuid}}

      update_action = resource |> Ash.Resource.Info.action(:update)

      assert get_parameter_schema_properties(
               update_action,
               resource,
               &AshAi.OpenApi.resource_write_attribute_type/3
             ) == %{id: %{type: :string, format: :uuid}}

      destroy_action = resource |> Ash.Resource.Info.action(:destroy)

      assert get_parameter_schema_properties(
               destroy_action,
               resource,
               &AshAi.OpenApi.resource_write_attribute_type/3
             ) == %{}

      read_action = resource |> Ash.Resource.Info.action(:read)

      assert get_parameter_schema_properties(
               read_action,
               resource,
               &AshAi.OpenApi.resource_write_attribute_type/3
             ) == %{}
    end
  end

  describe "raw_filter_type/2" do
    test "with Artist" do
      resource = Artist

      read_action = resource |> Ash.Resource.Info.action(:read)

      actual =
        get_action_specific_properties(
          read_action,
          resource,
          AshAi.OpenApi
        )

      # One filter object is generated per public, filterable field.
      assert Map.keys(actual) |> Enum.sort() == [:albums_count, :bio, :id, :name]

      # Every filter object is a closed object exposing an `is_nil` boolean.
      for {_field, schema} <- actual do
        assert schema.type == :object
        assert schema.additionalProperties == false
        assert schema.properties.is_nil == %{type: :boolean}
      end

      # UUID attribute: `eq`/`in` carry the uuid format.
      assert actual.id.properties.eq == %{type: :string, format: :uuid}
      assert actual.id.properties.in == %{type: :array, items: %{type: :string, format: :uuid}}

      # String attribute: plain string type, plus string-only operators.
      assert actual.name.properties.eq == %{type: :string}
      assert actual.name.properties.contains == %{type: :string}

      # Aggregate (count): integer type.
      assert actual.albums_count.properties.eq == %{type: :integer}
      assert actual.albums_count.properties.in == %{type: :array, items: %{type: :integer}}

      # Embedded type attribute: `eq` is itself an object schema.
      assert %{
               type: :object,
               required: [:birth],
               properties: %{birth: %{type: :string, format: :date}}
             } = actual.bio.properties.eq
    end

    test "with Album" do
      resource = Album

      read_action = resource |> Ash.Resource.Info.action(:read)

      actual =
        get_action_specific_properties(
          read_action,
          resource,
          AshAi.OpenApi
        )

      assert Map.keys(actual) == [:id]
      assert actual.id.type == :object
      assert actual.id.additionalProperties == false
      assert actual.id.properties.eq == %{type: :string, format: :uuid}
      assert actual.id.properties.in == %{type: :array, items: %{type: :string, format: :uuid}}
    end
  end

  describe "union attributes in filter schemas" do
    test "unions are excluded from generated filters instead of crashing" do
      tool =
        [actions: [{Widget, [:read]}]]
        |> AshAi.exposed_tools()
        |> hd()

      relaxed = AshAi.Tools.parameter_schema(tool, strict: false)
      assert relaxed["properties"]["filter"]["description"] =~ "name"
      refute relaxed["properties"]["filter"]["description"] =~ "payload"

      full =
        tool
        |> struct(full_filter_schema?: true)
        |> AshAi.Tools.parameter_schema(strict: false)

      properties = full["properties"]["filter"]["properties"]
      assert Map.has_key?(properties, "name")
      refute Map.has_key?(properties, "payload")
      refute Map.has_key?(properties, "raw_payload")
      refute Map.has_key?(properties, "payloads")
    end
  end

  defp get_action_specific_properties(%{type: :read}, resource, module) do
    Ash.Resource.Info.fields(resource, [:attributes, :aggregates, :calculations])
    |> Enum.filter(&(&1.public? && &1.filterable?))
    |> Map.new(fn field ->
      value = apply(module, :raw_filter_type, [field, resource])

      {field.name, value}
    end)
  end

  defp get_parameter_schema_properties(action, resource, fun) do
    attributes =
      if action.type in [:action, :read] do
        %{}
      else
        resource
        |> Ash.Resource.Info.attributes()
        |> Enum.filter(&(&1.name in action.accept && &1.writable?))
        |> Map.new(fn attribute ->
          value =
            fun.(
              attribute,
              resource,
              action.type
            )

          {attribute.name, value}
        end)
      end

    action.arguments
    |> Enum.filter(& &1.public?)
    |> Enum.reduce(attributes, fn argument, attributes ->
      value =
        fun.(argument, resource, :create)

      Map.put(
        attributes,
        argument.name,
        value
      )
    end)
  end
end
