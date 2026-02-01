# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.OpenApiTest do
  use ExUnit.Case, async: true
  alias AshAi.ChatFaker

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

      assert get_action_specific_properties(
               read_action,
               resource,
               AshAi.OpenApi
             ) == %{
               id: %{
                 type: :object,
                 properties: %{
                   in: %{type: :array, items: %{type: :string, format: :uuid}},
                   eq: %{type: :string, format: :uuid},
                   is_nil: %{type: :boolean},
                   less_than: %{type: :string, format: :uuid},
                   greater_than: %{type: :string, format: :uuid},
                   not_eq: %{type: :string, format: :uuid},
                   less_than_or_equal: %{type: :string, format: :uuid},
                   greater_than_or_equal: %{type: :string, format: :uuid}
                 },
                 additionalProperties: false
               },
               name: %{
                 type: :object,
                 properties: %{
                   in: %{type: :array, items: %{type: :string}},
                   eq: %{type: :string},
                   is_nil: %{type: :boolean},
                   less_than: %{type: :string},
                   greater_than: %{type: :string},
                   not_eq: %{type: :string},
                   less_than_or_equal: %{type: :string},
                   greater_than_or_equal: %{type: :string},
                   contains: %{type: :string}
                 },
                 additionalProperties: false
               },
               bio: %{
                 type: :object,
                 properties: %{
                   eq: %{
                     type: :object,
                     required: [:birth],
                     properties: %{
                       birth: %{
                         :type => :string,
                         :format => :date,
                         "description" => "Field included by default."
                       }
                     },
                     additionalProperties: false
                   },
                   is_nil: %{type: :boolean},
                   less_than: %{
                     type: :object,
                     required: [:birth],
                     properties: %{
                       birth: %{
                         :type => :string,
                         :format => :date,
                         "description" => "Field included by default."
                       }
                     },
                     additionalProperties: false
                   },
                   greater_than: %{
                     type: :object,
                     required: [:birth],
                     properties: %{
                       birth: %{
                         :type => :string,
                         :format => :date,
                         "description" => "Field included by default."
                       }
                     },
                     additionalProperties: false
                   },
                   not_eq: %{
                     type: :object,
                     required: [:birth],
                     properties: %{
                       birth: %{
                         :type => :string,
                         :format => :date,
                         "description" => "Field included by default."
                       }
                     },
                     additionalProperties: false
                   },
                   less_than_or_equal: %{
                     type: :object,
                     required: [:birth],
                     properties: %{
                       birth: %{
                         :type => :string,
                         :format => :date,
                         "description" => "Field included by default."
                       }
                     },
                     additionalProperties: false
                   },
                   greater_than_or_equal: %{
                     type: :object,
                     required: [:birth],
                     properties: %{
                       birth: %{
                         :type => :string,
                         :format => :date,
                         "description" => "Field included by default."
                       }
                     },
                     additionalProperties: false
                   }
                 },
                 additionalProperties: false
               },
               albums_count: %{
                 type: :object,
                 properties: %{
                   in: %{type: :array, items: %{type: :integer}},
                   eq: %{type: :integer},
                   is_nil: %{type: :boolean},
                   less_than: %{type: :integer},
                   greater_than: %{type: :integer},
                   not_eq: %{type: :integer},
                   less_than_or_equal: %{type: :integer},
                   greater_than_or_equal: %{type: :integer}
                 },
                 additionalProperties: false
               }
             }
    end

    test "with Album" do
      resource = Album

      read_action = resource |> Ash.Resource.Info.action(:read)

      assert get_action_specific_properties(
               read_action,
               resource,
               AshAi.OpenApi
             ) == %{
               id: %{
                 type: :object,
                 properties: %{
                   in: %{type: :array, items: %{type: :string, format: :uuid}},
                   eq: %{type: :string, format: :uuid},
                   is_nil: %{type: :boolean},
                   less_than: %{type: :string, format: :uuid},
                   greater_than: %{type: :string, format: :uuid},
                   not_eq: %{type: :string, format: :uuid},
                   less_than_or_equal: %{type: :string, format: :uuid},
                   greater_than_or_equal: %{type: :string, format: :uuid}
                 },
                 additionalProperties: false
               }
             }
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
