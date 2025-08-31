defmodule AshAiTest do
  use ExUnit.Case, async: true
  alias AshAi.ChatFaker
  alias LangChain.Chains.LLMChain
  alias LangChain.Message
  alias __MODULE__.{Music, Artist, Album}

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
        description("Check if context is available")

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

  describe "setup_ash_ai" do
    setup do
      artist =
        Artist
        |> Ash.Changeset.for_create(:create, %{name: "Chet Baker"})
        |> Ash.create!()

      %{artist: artist}
    end

    test "with read action", %{artist: artist} do
      tool_name = "list_artists"
      chain = chain()

      assert %LangChain.Function{} = function = chain.tools |> Enum.find(&(&1.name == tool_name))

      assert function.description == "Call the read action on the AshAiTest.Artist resource"

      assert function.parameters_schema["additionalProperties"] == false

      assert function.parameters_schema["properties"]["filter"] == %{
               "type" => "object",
               "description" => "Filter results",
               "properties" => %{
                 "id" => %{
                   "type" => "object",
                   "properties" => %{
                     "eq" => %{"format" => "uuid", "type" => "string"},
                     "greater_than" => %{"format" => "uuid", "type" => "string"},
                     "greater_than_or_equal" => %{
                       "format" => "uuid",
                       "type" => "string"
                     },
                     "in" => %{
                       "items" => %{"format" => "uuid", "type" => "string"},
                       "type" => "array"
                     },
                     "is_nil" => %{"type" => "boolean"},
                     "less_than" => %{"format" => "uuid", "type" => "string"},
                     "less_than_or_equal" => %{
                       "format" => "uuid",
                       "type" => "string"
                     },
                     "not_eq" => %{"format" => "uuid", "type" => "string"}
                   },
                   "additionalProperties" => false
                 },
                 "name" => %{
                   "type" => "object",
                   "properties" => %{
                     "contains" => %{"type" => "string"},
                     "eq" => %{"type" => "string"},
                     "greater_than" => %{"type" => "string"},
                     "greater_than_or_equal" => %{"type" => "string"},
                     "in" => %{"type" => "array", "items" => %{"type" => "string"}},
                     "is_nil" => %{"type" => "boolean"},
                     "less_than" => %{"type" => "string"},
                     "less_than_or_equal" => %{"type" => "string"},
                     "not_eq" => %{"type" => "string"}
                   },
                   "additionalProperties" => false
                 },
                 "albums_count" => %{
                   "type" => "object",
                   "additionalProperties" => false,
                   "properties" => %{
                     "eq" => %{"type" => "integer"},
                     "greater_than" => %{"type" => "integer"},
                     "greater_than_or_equal" => %{"type" => "integer"},
                     "in" => %{"items" => %{"type" => "integer"}, "type" => "array"},
                     "is_nil" => %{"type" => "boolean"},
                     "less_than" => %{"type" => "integer"},
                     "less_than_or_equal" => %{"type" => "integer"},
                     "not_eq" => %{"type" => "integer"}
                   }
                 }
               }
             }

      assert function.parameters_schema["properties"]["input"] == %{
               "type" => "object",
               "properties" => %{},
               "required" => []
             }

      assert function.parameters_schema["properties"]["limit"] == %{
               "type" => "integer",
               "description" => "The maximum number of records to return",
               "default" => 25
             }

      assert function.parameters_schema["properties"]["offset"] == %{
               "type" => "integer",
               "description" => "The number of records to skip",
               "default" => 0
             }

      assert function.parameters_schema["properties"]["sort"] == %{
               "type" => "array",
               "items" => %{
                 "type" => "object",
                 "properties" => %{
                   "direction" => %{
                     "type" => "string",
                     "description" => "The direction to sort by",
                     "enum" => ["asc", "desc"]
                   },
                   "field" => %{
                     "type" => "string",
                     "description" => "The field to sort by",
                     "enum" => ["id", "name", "albums_copies_sold"]
                   }
                 }
               }
             }

      tool_call =
        tool_call(tool_name, %{"filter" => %{"name" => %{"eq" => artist.name}}})

      assert {:ok, new_chain} = chain |> run_chain(tool_call)

      assert [fetched_artist] = new_chain.last_message.processed_content
      assert fetched_artist.id == artist.id
      assert fetched_artist.albums_count == 0
      assert %Ash.NotLoaded{} = fetched_artist.albums_copies_sold
    end

    test "with create action" do
      tool_name = "create_artist"
      chain = chain()

      assert %LangChain.Function{} = function = chain.tools |> Enum.find(&(&1.name == tool_name))

      assert function.description == "Call the create action on the AshAiTest.Artist resource"

      assert function.parameters_schema["additionalProperties"] == false

      assert function.parameters_schema["properties"]["input"] == %{
               "type" => "object",
               "properties" => %{
                 "id" => %{"type" => "string", "format" => "uuid"},
                 "name" => %{"type" => "string"}
               },
               "required" => []
             }

      tool_call = tool_call(tool_name, %{"input" => %{"name" => "Chat Faker"}})

      assert {:ok, new_chain} = chain |> run_chain(tool_call)

      assert created_artist = new_chain.last_message.processed_content
      assert created_artist.name == "Chat Faker"
      assert created_artist.albums_count == 0
      assert %Ash.NotLoaded{} = created_artist.albums_copies_sold
    end

    test "with update action", %{artist: artist} do
      tool_name = "update_artist"
      chain = chain()

      assert %LangChain.Function{} = function = chain.tools |> Enum.find(&(&1.name == tool_name))

      assert function.description == "Call the update action on the AshAiTest.Artist resource"

      assert function.parameters_schema["additionalProperties"] == false

      assert function.parameters_schema["properties"]["id"] == %{
               "type" => "string",
               "format" => "uuid"
             }

      assert function.parameters_schema["properties"]["input"] == %{
               "type" => "object",
               "properties" => %{
                 "id" => %{"type" => "string", "format" => "uuid"},
                 "name" => %{"type" => "string"}
               },
               "required" => []
             }

      tool_call =
        tool_call(tool_name, %{"id" => artist.id, "input" => %{"name" => "Chat Faker"}})

      assert {:ok, new_chain} = chain() |> run_chain(tool_call)

      assert updated_artist = new_chain.last_message.processed_content
      assert updated_artist.id == artist.id
      assert updated_artist.name == "Chat Faker"
      assert updated_artist.albums_count == 0
      assert %Ash.NotLoaded{} = updated_artist.albums_copies_sold
    end

    test "with destroy action", %{artist: artist} do
      tool_name = "delete_artist"
      chain = chain()

      assert %LangChain.Function{} = function = chain.tools |> Enum.find(&(&1.name == tool_name))

      assert function.description == "Call the destroy action on the AshAiTest.Artist resource"

      assert function.parameters_schema["additionalProperties"] == false

      assert function.parameters_schema["properties"]["id"] == %{
               "type" => "string",
               "format" => "uuid"
             }

      assert function.parameters_schema["properties"]["input"] == %{
               "type" => "object",
               "properties" => %{},
               "required" => []
             }

      tool_call = tool_call(tool_name, %{"id" => artist.id})

      assert {:ok, new_chain} = chain() |> run_chain(tool_call)

      assert destroyed_artist = new_chain.last_message.processed_content
      assert destroyed_artist.id == artist.id
      assert destroyed_artist.name == "Chet Baker"
      assert %Ash.NotLoaded{} = destroyed_artist.albums_copies_sold
    end

    test "with generic action" do
      tool_name = "say_hello"
      chain = chain()

      assert %LangChain.Function{} = function = chain.tools |> Enum.find(&(&1.name == tool_name))

      assert function.description == "Say hello"

      assert function.parameters_schema["additionalProperties"] == false

      assert function.parameters_schema["properties"]["input"] == %{
               "type" => "object",
               "properties" => %{"name" => %{"type" => "string"}},
               "required" => ["name"]
             }

      tool_call = tool_call(tool_name, %{"input" => %{"name" => "Chat Faker"}})

      assert {:ok, new_chain} = chain() |> run_chain(tool_call)

      assert "Hello, Chat Faker!" = new_chain.last_message.processed_content
    end

    test "passes context through setup_ash_ai" do
      custom_context = %{shared: %{conversation_id: "test-123"}}

      chain =
        %{llm: ChatFaker.new!(%{expect_fun: expect_fun()})}
        |> LLMChain.new!()
        |> AshAi.setup_ash_ai(
          actions: [],
          context: custom_context
        )

      assert chain.custom_context.context == custom_context
    end

    test "context is accessible in tool execution" do
      custom_context = %{shared: %{conversation_id: "test-123", user_id: 42}}

      actions =
        AshAi.Info.tools(Music)
        |> Enum.group_by(& &1.resource, & &1.action)
        |> Map.to_list()

      chain =
        %{llm: ChatFaker.new!(%{expect_fun: expect_fun()})}
        |> LLMChain.new!()
        |> AshAi.setup_ash_ai(
          actions: actions,
          context: custom_context
        )

      tool_call = tool_call("check_context", %{})

      assert {:ok, new_chain} = chain |> run_chain(tool_call)

      result = new_chain.last_message.processed_content

      assert result.context.shared == custom_context.shared
      assert result.context.conversation_id == "test-123"
      assert result.context.user_id == 42
    end
  end

  defp tool_call(name, arguments) do
    %LangChain.Message.ToolCall{
      status: :complete,
      type: :function,
      call_id: "call_id",
      name: name,
      arguments: arguments,
      index: 0
    }
  end

  defp chain do
    actions =
      AshAi.Info.tools(Music)
      |> Enum.group_by(& &1.resource, & &1.action)
      |> Map.to_list()

    %{llm: ChatFaker.new!(%{expect_fun: expect_fun()})}
    |> LLMChain.new!()
    |> AshAi.setup_ash_ai(actions: actions)
  end

  defp expect_fun do
    fn _chat_model, messages, _tools ->
      Message.new_assistant(%{processed_content: last_processed_content(messages)})
    end
  end

  defp run_chain(chain, tool_call) do
    chain
    |> LLMChain.add_message(Message.new_assistant!(%{status: :complete, tool_calls: [tool_call]}))
    |> LLMChain.run(mode: :while_needs_response)
  end

  defp last_processed_content(messages) do
    messages
    |> List.last()
    |> Map.get(:tool_results)
    |> List.first()
    |> Map.get(:processed_content)
  end
end
