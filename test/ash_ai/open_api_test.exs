defmodule AshAi.OpenApiTest do
  use ExUnit.Case, async: true
  alias AshAi.ChatFaker

  alias __MODULE__.{Music, Artist, Album, Schema}

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

  defmodule Music do
    use Ash.Domain,
      extensions: [AshAi]

    resources do
      resource Artist
      resource Album
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
      defaults [:create, :read, :update, :destroy]

      action :analyze_sentiment, Sentiment do
        description "Analyze the sentiment of a given text"
        argument :text, :string, allow_nil?: false

        run prompt(
              fn _input, _context ->
                ChatFaker.new!(%{
                  expect_fun: fn _model, _messages, tools ->
                    completion_tool = Enum.find(tools, &(&1.name == "complete_request"))

                    tool_call = %LangChain.Message.ToolCall{
                      status: :complete,
                      type: :function,
                      call_id: "call_123",
                      name: "complete_request",
                      arguments: %{
                        "result" => %{
                          "sentiment" => "positive",
                          "confidence" => 0.92,
                          "keywords" => ["excellent", "wonderful", "fantastic"]
                        }
                      },
                      index: 0
                    }

                    {:ok,
                     LangChain.Message.new_assistant!(%{
                       status: :complete,
                       tool_calls: [tool_call]
                     })}
                  end
                })
              end,
              adapter: {AshAi.Actions.Prompt.Adapter.CompletionTool, [max_runs: 10]}
            )
      end
    end
  end

  defmodule RandomString do
    use Ash.TypedStruct
    
    typed_struct do
      field :random_string, :string, 
        description: "Produce a random string between 1 and 100.", 
        allow_nil?: true, 
        default: nil, 
        constraints: [min_length: 1]
      
      field :count, :integer,
        allow_nil?: false,
        constraints: [min: 0, max: 100]
        
      field :score, :float,
        allow_nil?: true,
        constraints: [greater_than: 0.0, less_than: 1.0]
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

  describe "AshJsonApi.OpenApi vendoring regression tests" do
    setup do
      resources =
        [TestResource, Artist, Album]
        |> Enum.map(fn resource ->
          actions = Ash.Resource.Info.actions(resource)

          {resource, actions}
        end)

      {:ok, resources: resources}
    end

    test "for parameter_schema input properties", %{resources: resources} do
      for {resource, actions} <- resources do
        for action <- actions do
          vendored_schema =
            get_parameter_schema_properties(
              action,
              resource,
              &AshAi.OpenApi.resource_write_attribute_type/3
            )
            |> JSON.encode!()
            |> JSON.decode!()

          old_schema =
            get_parameter_schema_properties(
              action,
              resource,
              &AshJsonApi.OpenApi.resource_write_attribute_type/3
            )
            |> Schema.to_map()

          assert vendored_schema == old_schema
        end
      end
    end

    test "for action specific properties", %{resources: resources} do
      for {resource, actions} <- resources do
        for action <- actions do
          vendored_schema =
            get_action_specific_properties(action, resource, AshAi.OpenApi)
            |> JSON.encode!()
            |> JSON.decode!()

          old_schema =
            get_action_specific_properties(
              action,
              resource,
              AshJsonApi.OpenApi
            )
            |> Schema.to_map()

          assert vendored_schema == old_schema
        end
      end
    end
  end

  describe "Constraint and nullable field handling" do
    test "TypedStruct with constraints and nullable fields" do
      # Test that our TypedStruct generates the expected schema
      attr = %{
        type: RandomString,
        constraints: [],
        allow_nil?: false,
        description: nil
      }
      
      schema = AshAi.OpenApi.resource_write_attribute_type(attr, TestResource, :create)
      
      # Should be an object with the correct structure  
      assert schema[:type] == :object
      assert schema[:additionalProperties] == false
      
      # All fields should be required (including nullable ones)
      assert Enum.sort(schema[:required]) == [:count, :random_string, :score]
      
      # random_string should use anyOf pattern with constraints
      random_string_schema = schema[:properties][:random_string]
      assert %{anyOf: any_of_options} = random_string_schema
      assert %{type: nil} in any_of_options
      
      string_option = Enum.find(any_of_options, &(&1[:type] == :string))
      assert string_option[:minLength] == 1
      assert random_string_schema[:description] == "Produce a random string between 1 and 100."
      
      # count should have min/max constraints and no anyOf (not nullable)
      count_schema = schema[:properties][:count]
      assert count_schema[:type] == :integer
      assert count_schema[:minimum] == 0
      assert count_schema[:maximum] == 100
      refute Map.has_key?(count_schema, :anyOf)
      
      # score should use anyOf pattern with float constraints
      score_schema = schema[:properties][:score]
      assert %{anyOf: score_any_of} = score_schema
      assert %{type: nil} in score_any_of
      
      float_option = Enum.find(score_any_of, &(&1[:type] == :number))
      assert float_option[:format] == :float
      assert float_option[:exclusiveMinimum] == 0.0
      assert float_option[:exclusiveMaximum] == 1.0
    end

    test "String field with constraints via write attribute type" do
      # Create an attribute with constraints
      attr = %Ash.Resource.Attribute{
        name: :test_string,
        type: Ash.Type.String,
        constraints: [min_length: 5, max_length: 50, match: ~r/^[a-z]+$/],
        allow_nil?: false,
        description: nil,
        public?: true,
        writable?: true,
        generated?: false,
        primary_key?: false,
        always_select?: false,
        select_by_default?: true,
        default: nil,
        update_default: nil,
        source: :test_string,
        match_other_defaults?: false,
        sensitive?: false,
        filterable?: true,
        sortable?: true
      }
      
      schema = AshAi.OpenApi.resource_write_attribute_type(attr, TestResource, :create)
      
      assert schema[:type] == :string
      assert schema[:minLength] == 5
      assert schema[:maxLength] == 50
      assert schema[:pattern] == "^[a-z]+$"
    end

    test "Integer field with constraints via write attribute type" do
      attr = %Ash.Resource.Attribute{
        name: :test_integer,
        type: Ash.Type.Integer,
        constraints: [min: 10, max: 100],
        allow_nil?: false,
        description: nil,
        public?: true,
        writable?: true,
        generated?: false,
        primary_key?: false,
        always_select?: false,
        select_by_default?: true,
        default: nil,
        update_default: nil,
        source: :test_integer,
        match_other_defaults?: false,
        sensitive?: false,
        filterable?: true,
        sortable?: true
      }
      
      schema = AshAi.OpenApi.resource_write_attribute_type(attr, TestResource, :create)
      
      assert schema[:type] == :integer
      assert schema[:minimum] == 10
      assert schema[:maximum] == 100
    end

    test "Array field with constraints via write attribute type" do
      attr = %Ash.Resource.Attribute{
        name: :test_array,
        type: {:array, Ash.Type.String},
        constraints: [min_length: 2, max_length: 5, items: [min_length: 3]],
        allow_nil?: false,
        description: nil,
        public?: true,
        writable?: true,
        generated?: false,
        primary_key?: false,
        always_select?: false,
        select_by_default?: true,
        default: nil,
        update_default: nil,
        source: :test_array,
        match_other_defaults?: false,
        sensitive?: false,
        filterable?: true,
        sortable?: true
      }
      
      schema = AshAi.OpenApi.resource_write_attribute_type(attr, TestResource, :create)
      
      assert schema[:type] == :array
      assert schema[:minItems] == 2
      assert schema[:maxItems] == 5
      assert schema[:items][:type] == :string
      assert schema[:items][:minLength] == 3
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

  defp get_action_specific_properties(%{type: type}, resource, module)
       when type in [:update, :destroy] do
    Map.new(Ash.Resource.Info.primary_key(resource), fn key ->
      attribute = Ash.Resource.Info.attribute(resource, key)
      value = apply(module, :resource_write_attribute_type, [attribute, resource, key])

      {key, value}
    end)
  end

  defp get_action_specific_properties(_action, _resource, _module) do
    %{}
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

  defmodule Schema do
    alias OpenApiSpex.Extendable

    @vendor_extensions ~w(
      x-struct
      x-validate
      x-parameter-content-parsers
    )

    def to_map(value), do: to_map(value, [])
    def to_map(%Regex{source: source}, _opts), do: source

    def to_map(%object{} = value, opts) when object in [MediaType, Schema, Example] do
      value
      |> Extendable.to_map()
      |> Stream.map(fn
        {:value, v} when object == Example -> {"value", to_map_example(v, opts)}
        {:example, v} -> {"example", to_map_example(v, opts)}
        {k, v} -> {to_string(k), to_map(v, opts)}
      end)
      |> Stream.filter(fn
        {k, _} when k in @vendor_extensions -> opts[:vendor_extensions]
        {_, nil} -> false
        _ -> true
      end)
      |> Enum.into(%{})
    end

    def to_map(%{__struct__: _} = value, opts) do
      value
      |> Extendable.to_map()
      |> to_map(opts)
    end

    def to_map(value, opts) when is_map(value) do
      value
      |> Stream.map(fn {k, v} -> {to_string(k), to_map(v, opts)} end)
      |> Stream.filter(fn
        {_, nil} -> false
        _ -> true
      end)
      |> Enum.into(%{})
    end

    def to_map(value, opts) when is_list(value) do
      Enum.map(value, &to_map(&1, opts))
    end

    def to_map(nil, _opts), do: nil
    def to_map(true, _opts), do: true
    def to_map(false, _opts), do: false
    def to_map(value, _opts) when is_atom(value), do: to_string(value)
    def to_map(value, _opts), do: value

    defp to_map_example(%{__struct__: _} = value, opts) do
      value
      |> Extendable.to_map()
      |> to_map_example(opts)
    end

    defp to_map_example(value, opts) when is_map(value) do
      value
      |> Stream.map(fn {k, v} -> {to_string(k), to_map_example(v, opts)} end)
      |> Enum.into(%{})
    end

    defp to_map_example(value, opts) when is_list(value) do
      Enum.map(value, &to_map_example(&1, opts))
    end

    defp to_map_example(value, opts), do: to_map(value, opts)
  end
end
