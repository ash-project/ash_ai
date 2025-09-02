defmodule AshAi do
  @moduledoc """
  Documentation for `AshAi`.
  """

  alias LangChain.Chains.LLMChain

  defstruct []

  require Logger
  require Ash.Expr

  @full_text %Spark.Dsl.Section{
    name: :full_text,
    imports: [Ash.Expr],
    schema: [
      name: [
        type: :atom,
        default: :full_text_vector,
        doc: "The name of the attribute to store the text vector in"
      ],
      used_attributes: [
        type: {:list, :atom},
        doc: "If set, a vector is only regenerated when these attributes are changed"
      ],
      text: [
        type: {:fun, 1},
        required: true,
        doc:
          "A function or expr that takes a list of records and computes a full text string that will be vectorized. If given an expr, use `atomic_ref` to refer to new values, as this is set as an atomic update."
      ]
    ]
  }

  @vectorize %Spark.Dsl.Section{
    name: :vectorize,
    sections: [
      @full_text
    ],
    schema: [
      attributes: [
        type: :keyword_list,
        doc:
          "A keyword list of attributes to vectorize, and the name of the attribute to store the vector in",
        default: []
      ],
      strategy: [
        type: {:one_of, [:after_action, :manual, :ash_oban, :ash_oban_manual]},
        default: :after_action,
        doc:
          "How to compute the vector. Currently supported strategies are `:after_action`, `:manual`, and `:ash_oban`."
      ],
      define_update_action_for_manual_strategy?: [
        type: :boolean,
        default: true,
        doc:
          "If true, an `ash_ai_update_embeddings` update action will be defined, which will automatically update the embeddings when run."
      ],
      ash_oban_trigger_name: [
        type: :atom,
        default: :ash_ai_update_embeddings,
        doc:
          "The name of the AshOban-trigger that will be run in order to update the record's embeddings. Defaults to `:ash_ai_update_embeddings`."
      ],
      embedding_model: [
        type: {:spark_behaviour, AshAi.EmbeddingModel},
        required: true
      ]
    ]
  }

  defmodule Tool do
    @moduledoc "An action exposed to LLM agents"
    defstruct [
      :name,
      :resource,
      :action,
      :load,
      :async,
      :domain,
      :identity,
      :description,
      :action_parameters
    ]
  end

  defmodule ToolStartEvent do
    @moduledoc """
    Event data passed to the `on_tool_start` callback passed to `AshAi.setup_ash_ai/2`.

    Contains information about the tool execution that is about to begin.
    """
    @type t :: %__MODULE__{
            tool_name: String.t(),
            action: atom(),
            resource: module(),
            arguments: map(),
            actor: any() | nil,
            tenant: any() | nil
          }

    defstruct [:tool_name, :action, :resource, :arguments, :actor, :tenant]
  end

  defmodule ToolEndEvent do
    @moduledoc """
    Event data passed to the `on_tool_end` callback passed to `AshAi.setup_ash_ai/2`.

    Contains the tool name and execution result.
    """
    @type t :: %__MODULE__{
            tool_name: String.t(),
            result: {:ok, String.t(), any()} | {:error, String.t()}
          }

    defstruct [:tool_name, :result]
  end

  @tool %Spark.Dsl.Entity{
    name: :tool,
    target: Tool,
    describe: """
    Expose an Ash action as a tool that can be called by LLMs.

    Tools allow LLMs to interact with your application by calling specific actions on resources.
    Only public attributes can be used for filtering, sorting, and aggregation, but the `load`
    option allows including private attributes in the response data.
    """,
    schema: [
      name: [type: :atom, required: true],
      resource: [type: {:spark, Ash.Resource}, required: true],
      action: [type: :atom, required: true],
      action_parameters: [
        type: {:list, :atom},
        required: false,
        doc:
          "A list of action specific parameters to allow for the underlying action. Only relevant for reads, and defaults to allowing `[:sort, :offset, :limit, :result_type, :filter]`"
      ],
      load: [
        type: :any,
        default: [],
        doc:
          "A list of relationships and calculations to load on the returned records. Note that loaded fields can include private attributes, which will then be included in the tool's response. However, private attributes cannot be used for filtering, sorting, or aggregation."
      ],
      async: [type: :boolean, default: true],
      description: [
        type: :string,
        doc: "A description for the tool. Defaults to the action's description."
      ],
      identity: [
        type: :atom,
        default: nil,
        doc:
          "The identity to use for update/destroy actions. Defaults to the primary key. Set to `false` to disable entirely."
      ]
    ],
    args: [:name, :resource, :action]
  }

  @tools %Spark.Dsl.Section{
    name: :tools,
    entities: [
      @tool
    ]
  }

  use Spark.Dsl.Extension,
    sections: [@tools, @vectorize],
    imports: [AshAi.Actions],
    transformers: [AshAi.Transformers.Vectorize]

  defmodule Options do
    @moduledoc false
    use Spark.Options.Validator,
      schema: [
        actions: [
          type:
            {:wrap_list,
             {:tuple, [{:spark, Ash.Resource}, {:or, [{:list, :atom}, {:literal, :*}]}]}},
          doc: """
          A set of {Resource, [:action]} pairs, or `{Resource, :*}` for all actions. Defaults to everything. If `tools` is also set, both are applied as filters.
          """
        ],
        tools: [
          type: {:wrap_list, :atom},
          doc: """
           A list of tool names. If not set. Defaults to everything. If `actions` is also set, both are applied as filters.
          """
        ],
        exclude_actions: [
          type: {:wrap_list, {:tuple, [{:spark, Ash.Resource}, :atom]}},
          doc: """
          A set of {Resource, :action} pairs, or `{Resource, :*}` to be excluded from the added actions.
          """
        ],
        actor: [
          type: :any,
          doc: "The actor performing any actions."
        ],
        tenant: [
          type: {:protocol, Ash.ToTenant},
          doc: "The tenant to use for the action."
        ],
        messages: [
          type: {:list, :map},
          default: [],
          doc: """
          Used to provide conversation history.
          """
        ],
        context: [
          type: :map,
          default: %{},
          doc: """
          Context passed to each action invocation.
          """
        ],
        otp_app: [
          type: :atom,
          doc: "If present, allows discovering resource actions automatically."
        ],
        system_prompt: [
          type: {:or, [{:fun, 1}, {:literal, :none}]},
          doc: """
          A system prompt that takes the provided options and returns a system prompt.

          You will want to include something like the actor's id if you are chatting as an
          actor.
          """
        ],
        on_tool_start: [
          type: {:fun, 1},
          required: false,
          doc: """
          A callback function that is called when a tool execution starts.

          Receives an `AshAi.ToolStartEvent` struct with the following fields:
          - `:tool_name` - The name of the tool being called
          - `:action` - The action being performed
          - `:resource` - The resource the action is on
          - `:arguments` - The arguments passed to the tool
          - `:actor` - The actor performing the action
          - `:tenant` - The tenant context

          Example:
          ```
          on_tool_start: fn %AshAi.ToolStartEvent{} = event ->
            IO.puts("Starting tool: \#{event.tool_name}")
          end
          ```
          """
        ],
        on_tool_end: [
          type: {:fun, 1},
          required: false,
          doc: """
          A callback function that is called when a tool execution completes.

          Receives an `AshAi.ToolEndEvent` struct with the following fields:
          - `:tool_name` - The name of the tool
          - `:result` - The result of the tool execution (either {:ok, ...} or {:error, ...})

          Example:
          ```
          on_tool_end: fn %AshAi.ToolEndEvent{} = event ->
            IO.puts("Completed tool: \#{event.tool_name}")
          end
          ```
          """
        ]
      ]
  end

  def functions(opts) do
    opts
    |> exposed_tools()
    |> Enum.map(&function/1)
  end

  def iex_chat(lang_chain, opts \\ []) do
    opts = Options.validate!(opts)

    messages =
      case opts.system_prompt do
        :none ->
          []

        nil ->
          [
            LangChain.Message.new_system!("""
            You are a helpful assistant.
            Your purpose is to operate the application on behalf of the user.
            """)
          ]

        system_prompt ->
          [LangChain.Message.new_system!(system_prompt.(opts))]
      end

    handler = %{
      on_llm_new_delta: fn _model, data ->
        # we received a piece of data
        IO.write(data.content)
      end,
      on_message_processed: fn _chain, _data ->
        # the message was assembled and is processed
        IO.write("\n--\n")
      end
    }

    lang_chain
    |> LLMChain.add_messages(messages)
    |> setup_ash_ai(opts)
    |> LLMChain.add_callback(handler)
    |> run_loop(true)
  end

  @doc """
  Adds the requisite context and tool calls to allow an agent to interact with your app.
  """
  def setup_ash_ai(lang_chain, opts \\ [])

  def setup_ash_ai(lang_chain, opts) when is_list(opts) do
    opts = Options.validate!(opts)
    setup_ash_ai(lang_chain, opts)
  end

  def setup_ash_ai(lang_chain, opts) do
    tools = functions(opts)

    lang_chain
    |> LLMChain.add_tools(tools)
    |> LLMChain.update_custom_context(%{
      actor: opts.actor,
      tenant: opts.tenant,
      context: opts.context,
      tool_callbacks: %{
        on_tool_start: opts.on_tool_start,
        on_tool_end: opts.on_tool_end
      }
    })
  end

  defp run_loop(chain, first? \\ false) do
    chain
    |> LLMChain.run(mode: :while_needs_response)
    |> case do
      {:ok,
       %LangChain.Chains.LLMChain{
         last_message: %{content: content}
       } = new_chain} ->
        if !first? && !Map.get(new_chain.llm, :stream) do
          IO.puts(content)
        end

        user_message = get_user_message()

        new_chain
        |> LLMChain.add_messages([LangChain.Message.new_user!(user_message)])
        |> run_loop()

      {:error, _new_chain, error} ->
        raise "Something went wrong:\n #{Exception.format(:error, error)}"
    end
  end

  defp get_user_message do
    case Mix.shell().prompt("> ") do
      nil -> get_user_message()
      "" -> get_user_message()
      "\n" -> get_user_message()
      message -> message
    end
  end

  defp parameter_schema(_domain, resource, action, action_parameters) do
    attributes =
      if action.type in [:action, :read] do
        %{}
      else
        resource
        |> Ash.Resource.Info.attributes()
        |> Enum.filter(&(&1.name in action.accept && &1.writable?))
        |> Map.new(fn attribute ->
          value =
            AshAi.OpenApi.resource_write_attribute_type(
              attribute,
              resource,
              action.type
            )

          {attribute.name, value}
        end)
      end

    properties =
      action.arguments
      |> Enum.filter(& &1.public?)
      |> Enum.reduce(attributes, fn argument, attributes ->
        value =
          AshAi.OpenApi.resource_write_attribute_type(argument, resource, :create)

        Map.put(
          attributes,
          argument.name,
          value
        )
      end)

    props_with_input =
      if Enum.empty?(properties) do
        %{}
      else
        %{
          input: %{
            type: :object,
            properties: properties,
            required: AshAi.OpenApi.required_write_attributes(resource, action.arguments, action)
          }
        }
      end

    %{
      type: :object,
      properties:
        add_action_specific_properties(props_with_input, resource, action, action_parameters),
      required: Map.keys(props_with_input),
      additionalProperties: false
    }
    |> Jason.encode!()
    |> Jason.decode!()
  end

  defp function(%Tool{
         name: name,
         domain: domain,
         resource: resource,
         action: action,
         load: load,
         identity: identity,
         async: async,
         description: description,
         action_parameters: action_parameters
       }) do
    name = to_string(name)

    description =
      String.trim(
        description || action.description ||
          "Call the #{action.name} action on the #{inspect(resource)} resource"
      )

    parameter_schema = parameter_schema(domain, resource, action, action_parameters)

    LangChain.Function.new!(%{
      name: name,
      description: description,
      parameters_schema: parameter_schema,
      strict: true,
      async: async,
      function: fn arguments, context ->
        # Handle nil arguments from LangChain/MCP clients
        arguments = arguments || %{}
        
        actor = context[:actor]
        tenant = context[:tenant]
        input = arguments["input"] || %{}
        opts = [domain: domain, actor: actor, tenant: tenant, context: context[:context] || %{}]

        callbacks = context[:tool_callbacks] || %{}

        if on_start = callbacks[:on_tool_start] do
          on_start.(%ToolStartEvent{
            tool_name: name,
            action: action.name,
            resource: resource,
            arguments: arguments,
            actor: actor,
            tenant: tenant
          })
        end

        result =
          try do
            case action.type do
              :read ->
                sort =
                  case arguments["sort"] do
                    sort when is_list(sort) ->
                      Enum.map(sort, fn map ->
                        case map["direction"] || "asc" do
                          "asc" -> map["field"]
                          "desc" -> "-#{map["field"]}"
                        end
                      end)

                    nil ->
                      []
                  end
                  |> Enum.join(",")

                limit =
                  case {arguments["limit"], action.pagination} do
                    {limit, false} when is_integer(limit) ->
                      limit

                    {limit,
                     %Ash.Resource.Actions.Read.Pagination{
                       default_limit: default,
                       max_page_size: max
                     }} ->
                      cond do
                        is_integer(limit) and is_integer(max) -> min(limit, max)
                        is_nil(limit) and is_integer(default) -> default
                        true -> 25
                      end

                    _ ->
                      25
                  end

                resource
                |> Ash.Query.limit(limit)
                |> Ash.Query.offset(arguments["offset"])
                |> then(fn query ->
                  if sort != "" do
                    Ash.Query.sort_input(query, sort)
                  else
                    query
                  end
                end)
                |> then(fn query ->
                  if arguments && Map.has_key?(arguments, "filter") do
                    Ash.Query.filter_input(query, arguments["filter"])
                  else
                    query
                  end
                end)
                |> Ash.Query.for_read(action.name, input, opts)
                |> then(fn query ->
                  result_type = (arguments && arguments["result_type"]) || "run_query"

                  case result_type do
                    "run_query" ->
                      query
                      |> Ash.Actions.Read.unpaginated_read(action, load: load)
                      |> case do
                        {:ok, value} ->
                          value

                        {:error, error} ->
                          raise Ash.Error.to_error_class(error)
                      end
                      |> then(fn result ->
                        result
                        |> AshAi.Serializer.serialize_value({:array, resource}, [], domain,
                          load: load
                        )
                        |> Jason.encode!()
                        |> then(&{:ok, &1, result})
                      end)

                    "count" ->
                      query
                      |> Ash.Query.unset([:limit, :offset])
                      |> Ash.count()
                      |> case do
                        {:ok, value} ->
                          value

                        {:error, error} ->
                          raise Ash.Error.to_error_class(error)
                      end
                      |> then(fn result ->
                        result
                        |> AshAi.Serializer.serialize_value(Ash.Type.Integer, [], domain)
                        |> Jason.encode!()
                        |> then(&{:ok, &1, result})
                      end)

                    "exists" ->
                      query
                      |> Ash.exists()
                      |> case do
                        {:ok, value} ->
                          value

                        {:error, error} ->
                          raise Ash.Error.to_error_class(error)
                      end
                      |> then(fn result ->
                        result
                        |> AshAi.Serializer.serialize_value(Ash.Type.Boolean, [], domain)
                        |> Jason.encode!()
                        |> then(&{:ok, &1, result})
                      end)

                    %{"aggregate" => aggregate_kind} = aggregate ->
                      if aggregate_kind not in ["min", "max", "sum", "avg", "count"] do
                        raise "invalid aggregate function"
                      end

                      if !aggregate["field"] do
                        raise "missing field argument"
                      end

                      field = Ash.Resource.Info.field(resource, aggregate["field"])

                      if !field || !field.public? do
                        raise "no such field"
                      end

                      aggregate_kind = String.to_existing_atom(aggregate_kind)

                      aggregate =
                        Ash.Query.Aggregate.new!(resource, :aggregate_result, aggregate_kind,
                          field: field.name
                        )

                      query
                      |> Ash.aggregate(aggregate)
                      |> case do
                        {:ok, value} ->
                          value

                        {:error, error} ->
                          raise Ash.Error.to_error_class(error)
                      end
                      |> then(fn result ->
                        result
                        |> AshAi.Serializer.serialize_value(
                          aggregate.type,
                          aggregate.constraints,
                          domain
                        )
                        |> Jason.encode!()
                        |> then(&{:ok, &1, result})
                      end)
                  end
                end)

              :update ->
                filter = identity_filter(identity, resource, arguments)

                resource
                |> Ash.Query.do_filter(filter)
                |> Ash.Query.limit(1)
                |> Ash.bulk_update!(
                  action.name,
                  input,
                  Keyword.merge(opts,
                    return_errors?: true,
                    notify?: true,
                    strategy: [:atomic, :stream, :atomic_batches],
                    load: load,
                    allow_stream_with: :full_read,
                    return_records?: true
                  )
                )
                |> case do
                  %Ash.BulkResult{status: :success, records: [result]} ->
                    result
                    |> AshAi.Serializer.serialize_value(resource, [], domain, load: load)
                    |> Jason.encode!()
                    |> then(&{:ok, &1, result})

                  %Ash.BulkResult{status: :success, records: []} ->
                    raise Ash.Error.to_error_class(
                            Ash.Error.Query.NotFound.exception(primary_key: filter)
                          )
                end

              :destroy ->
                filter = identity_filter(identity, resource, arguments)

                resource
                |> Ash.Query.do_filter(filter)
                |> Ash.Query.limit(1)
                |> Ash.bulk_destroy!(
                  action.name,
                  input,
                  Keyword.merge(opts,
                    return_errors?: true,
                    notify?: true,
                    load: load,
                    strategy: [:atomic, :stream, :atomic_batches],
                    allow_stream_with: :full_read,
                    return_records?: true
                  )
                )
                |> case do
                  %Ash.BulkResult{status: :success, records: [result]} ->
                    result
                    |> AshAi.Serializer.serialize_value(resource, [], domain, load: load)
                    |> Jason.encode!()
                    |> then(&{:ok, &1, result})

                  %Ash.BulkResult{status: :success, records: []} ->
                    raise Ash.Error.to_error_class(
                            Ash.Error.Query.NotFound.exception(primary_key: filter)
                          )
                end

              :create ->
                resource
                |> Ash.Changeset.for_create(action.name, input, opts)
                |> Ash.create!(load: load)
                |> then(fn result ->
                  result
                  |> AshAi.Serializer.serialize_value(resource, [], domain, load: load)
                  |> Jason.encode!()
                  |> then(&{:ok, &1, result})
                end)

              :action ->
                resource
                |> Ash.ActionInput.for_action(action.name, input, opts)
                |> Ash.run_action!()
                |> then(fn result ->
                  if action.returns do
                    result
                    |> AshAi.Serializer.serialize_value(action.returns, [], domain, load: load)
                    |> Jason.encode!()
                  else
                    "success"
                  end
                  |> then(&{:ok, &1, result})
                end)
            end
          rescue
            error ->
              error = Ash.Error.to_error_class(error)

              {:error,
               domain
               |> AshJsonApi.Error.to_json_api_errors(resource, error, action.type)
               |> serialize_errors()
               |> Jason.encode!()}
          end

        if on_end = callbacks[:on_tool_end] do
          on_end.(%ToolEndEvent{
            tool_name: name,
            result: result
          })
        end

        result
      end
    })
  end

  defp identity_filter(false, _resource, _arguments) do
    nil
  end

  defp identity_filter(nil, resource, arguments) do
    resource
    |> Ash.Resource.Info.primary_key()
    |> Enum.reduce(nil, fn key, expr ->
      value = Map.get(arguments, to_string(key))

      if expr do
        Ash.Expr.expr(^expr and ^Ash.Expr.ref(key) == ^value)
      else
        Ash.Expr.expr(^Ash.Expr.ref(key) == ^value)
      end
    end)
  end

  defp identity_filter(identity, resource, arguments) do
    resource
    |> Ash.Resource.Info.identities()
    |> Enum.find(&(&1.name == identity))
    |> Map.get(:keys)
    |> Enum.map(fn key ->
      {key, Map.get(arguments, to_string(key))}
    end)
  end

  def to_json_api_errors(domain, resource, errors, type) when is_list(errors) do
    Enum.flat_map(errors, &to_json_api_errors(domain, resource, &1, type))
  end

  def to_json_api_errors(domain, resource, %mod{errors: errors}, type)
      when mod in [Forbidden, Framework, Invalid, Unknown] do
    Enum.flat_map(errors, &to_json_api_errors(domain, resource, &1, type))
  end

  def to_json_api_errors(_domain, _resource, %AshJsonApi.Error{} = error, _type) do
    [error]
  end

  def to_json_api_errors(domain, _resource, %{class: :invalid} = error, _type) do
    if AshJsonApi.ToJsonApiError.impl_for(error) do
      error
      |> AshJsonApi.ToJsonApiError.to_json_api_error()
      |> List.wrap()
      |> Enum.flat_map(&with_source_pointer(&1, error))
    else
      uuid = Ash.UUID.generate()

      stacktrace =
        case error do
          %{stacktrace: %{stacktrace: v}} ->
            v

          _ ->
            nil
        end

      Logger.warning(
        "`#{uuid}`: AshJsonApi.Error not implemented for error:\n\n#{Exception.format(:error, error, stacktrace)}"
      )

      if AshJsonApi.Domain.Info.show_raised_errors?(domain) do
        [
          %AshJsonApi.Error{
            id: uuid,
            status_code: class_to_status(error.class),
            code: "something_went_wrong",
            title: "SomethingWentWrong",
            detail: """
            Raised error: #{uuid}

            #{Exception.format(:error, error, stacktrace)}"
            """
          }
        ]
      else
        [
          %AshJsonApi.Error{
            id: uuid,
            status_code: class_to_status(error.class),
            code: "something_went_wrong",
            title: "SomethingWentWrong",
            detail: "Something went wrong. Error id: #{uuid}"
          }
        ]
      end
    end
  end

  def to_json_api_errors(_domain, _resource, %{class: :forbidden} = error, _type) do
    [
      %AshJsonApi.Error{
        id: Ash.UUID.generate(),
        status_code: class_to_status(error.class),
        code: "forbidden",
        title: "Forbidden",
        detail: "forbidden"
      }
    ]
  end

  def to_json_api_errors(_domain, _resource, error, _type) do
    uuid = Ash.UUID.generate()

    stacktrace =
      case error do
        %{stacktrace: %{stacktrace: v}} ->
          v

        _ ->
          nil
      end

    Logger.warning(
      "`#{uuid}`: AshJsonApi.Error not implemented for error:\n\n#{Exception.format(:error, error, stacktrace)}"
    )

    [
      %AshJsonApi.Error{
        id: uuid,
        status_code: class_to_status(error.class),
        code: "something_went_wrong",
        title: "SomethingWentWrong",
        detail: "Something went wrong. Error id: #{uuid}"
      }
    ]
  end

  @doc "Turns an error class into an HTTP status code"
  def class_to_status(:forbidden), do: 403
  def class_to_status(:invalid), do: 400
  def class_to_status(_), do: 500

  defp serialize_errors(errors) do
    errors
    |> List.wrap()
    |> Enum.map(fn error ->
      %{}
      |> add_if_defined(:id, error.id)
      |> add_if_defined(:status, to_string(error.status_code))
      |> add_if_defined(:code, error.code)
      |> add_if_defined(:title, error.title)
      |> add_if_defined(:detail, error.detail)
      |> add_if_defined([:source, :pointer], error.source_pointer)
      |> add_if_defined([:source, :parameter], error.source_parameter)
      |> add_if_defined(:meta, parse_error(error.meta))
    end)
  end

  def with_source_pointer(%{source_pointer: source_pointer} = built_error, _)
      when source_pointer not in [nil, :undefined] do
    [built_error]
  end

  def with_source_pointer(built_error, %{fields: fields, path: path})
      when is_list(fields) and fields != [] do
    Enum.map(fields, fn field ->
      %{built_error | source_pointer: source_pointer(field, path)}
    end)
  end

  def with_source_pointer(built_error, %{field: field, path: path})
      when not is_nil(field) do
    [
      %{built_error | source_pointer: source_pointer(field, path)}
    ]
  end

  def with_source_pointer(built_error, _) do
    [built_error]
  end

  defp source_pointer(field, path) do
    "/input/#{Enum.join(List.wrap(path) ++ [field], "/")}"
  end

  defp add_if_defined(params, _, :undefined) do
    params
  end

  defp add_if_defined(params, [key1, key2], value) do
    params
    |> Map.put_new(key1, %{})
    |> Map.update!(key1, &Map.put(&1, key2, value))
  end

  defp add_if_defined(params, key, value) do
    Map.put(params, key, value)
  end

  defp parse_error(%{match: %Regex{} = match} = error) do
    %{error | match: Regex.source(match)}
  end

  defp parse_error(error), do: error

  defp add_action_specific_properties(
         properties,
         resource,
         %{type: :read, pagination: pagination},
         action_parameters
       ) do
    Map.merge(properties, %{
      filter: %{
        type: :object,
        description: "Filter results",
        # querying is complex, will likely need to be a two step process
        # i.e first decide to query, and then provide it with a function to call
        # that has all the options Then the filter object can be big & expressive.
        properties:
          Ash.Resource.Info.fields(resource, [:attributes, :aggregates, :calculations])
          |> Enum.filter(&(&1.public? && &1.filterable?))
          |> Map.new(fn field ->
            value =
              AshAi.OpenApi.raw_filter_type(field, resource)

            {field.name, value}
          end)
      },
      result_type: %{
        default: "run_query",
        description: "The type of result to return",
        oneOf: [
          %{
            description:
              "Run the query returning all results, or return a count of results, or check if any results exist",
            enum: [
              "run_query",
              "count",
              "exists"
            ]
          },
          %{
            properties: %{
              aggregate: %{
                type: :string,
                description: "The aggregate function to use",
                enum: [:max, :min, :sum, :avg, :count]
              },
              field: %{
                type: :string,
                description: "The field to aggregate",
                enum:
                  Ash.Resource.Info.fields(resource, [
                    :attributes,
                    :aggregates,
                    :calculations
                  ])
                  |> Enum.filter(& &1.public?)
                  |> Enum.map(& &1.name)
              }
            }
          }
        ]
      },
      limit: %{
        type: :integer,
        description: "The maximum number of records to return",
        default:
          case pagination do
            %Ash.Resource.Actions.Read.Pagination{default_limit: limit} when is_integer(limit) ->
              limit

            _ ->
              25
          end
      },
      offset: %{
        type: :integer,
        description: "The number of records to skip",
        default: 0
      },
      sort: %{
        type: :array,
        items: %{
          type: :object,
          properties:
            %{
              field: %{
                type: :string,
                description: "The field to sort by",
                enum:
                  Ash.Resource.Info.fields(resource, [
                    :attributes,
                    :calculations,
                    :aggregates
                  ])
                  |> Enum.filter(&(&1.public? && &1.sortable?))
                  |> Enum.map(& &1.name)
              },
              direction: %{
                type: :string,
                description: "The direction to sort by",
                enum: ["asc", "desc"]
              }
            }
            |> add_input_for_fields(resource)
        }
      }
    })
    |> then(fn map ->
      if action_parameters do
        Map.take(map, action_parameters)
      else
        map
      end
    end)
  end

  defp add_action_specific_properties(properties, resource, %{type: type}, _action_parameters)
       when type in [:update, :destroy] do
    pkey =
      Map.new(Ash.Resource.Info.primary_key(resource), fn key ->
        value =
          Ash.Resource.Info.attribute(resource, key)
          |> AshAi.OpenApi.resource_write_attribute_type(resource, type)

        {key, value}
      end)

    Map.merge(properties, pkey)
  end

  defp add_action_specific_properties(properties, _resource, _action, _tool), do: properties

  defp add_input_for_fields(sort_obj, resource) do
    resource
    |> Ash.Resource.Info.fields([
      :calculations
    ])
    |> Enum.filter(&(&1.public? && &1.sortable? && !Enum.empty?(&1.arguments)))
    |> case do
      [] ->
        sort_obj

      fields ->
        input_for_fields =
          %{
            type: :object,
            additonalProperties: false,
            properties:
              Map.new(fields, fn field ->
                inputs =
                  Enum.map(field.arguments, fn argument ->
                    value =
                      AshAi.OpenApi.resource_write_attribute_type(
                        argument,
                        resource,
                        :create
                      )

                    {argument.name, value}
                  end)

                required =
                  Enum.flat_map(field.arguments, fn argument ->
                    if argument.allow_nil? do
                      []
                    else
                      [argument.name]
                    end
                  end)

                {field.name,
                 %{
                   type: :object,
                   properties: Map.new(inputs),
                   required: required,
                   additionalProperties: false
                 }}
              end)
          }

        Map.put(sort_obj, :input_for_fields, input_for_fields)
    end
  end

  @doc false

  def exposed_tools(opts) when is_list(opts) do
    exposed_tools(Options.validate!(opts))
  end

  def exposed_tools(opts) do
    if opts.actions do
      Enum.flat_map(opts.actions, fn
        {resource, actions} ->
          domain = Ash.Resource.Info.domain(resource)

          if !domain do
            raise "Cannot use an ash resource that does not have a domain"
          end

          tools = AshAi.Info.tools(domain)

          if !Enum.any?(tools, fn tool ->
               tool.resource == resource && (actions == :* || tool.action in actions)
             end) do
            raise "Cannot use an action that is not exposed as a tool"
          end

          if actions == :* do
            tools
            |> Enum.filter(&(&1.resource == resource))
            |> Enum.map(fn tool ->
              %{tool | domain: domain, action: Ash.Resource.Info.action(resource, tool.action)}
            end)
          else
            tools
            |> Enum.filter(&(&1.resource == resource && &1.action in actions))
            |> Enum.map(fn tool ->
              %{tool | domain: domain, action: Ash.Resource.Info.action(resource, tool.action)}
            end)
          end
      end)
    else
      if !opts.otp_app do
        raise "Must specify `otp_app` if you do not specify `actions`"
      end

      for domain <- Application.get_env(opts.otp_app, :ash_domains) || [],
          tool <- AshAi.Info.tools(domain) do
        %{tool | domain: domain, action: Ash.Resource.Info.action(tool.resource, tool.action)}
      end
    end
    |> Enum.uniq()
    |> then(fn tools ->
      if is_list(opts.exclude_actions) do
        Enum.reject(tools, fn tool ->
          {tool.resource, tool.action.name} in opts.exclude_actions
        end)
      else
        tools
      end
    end)
    |> then(fn tools ->
      if allowed_tools = opts.tools do
        Enum.filter(tools, fn tool ->
          tool.name in List.wrap(allowed_tools)
        end)
      else
        tools
      end
    end)
    |> Enum.filter(
      &can?(
        opts.actor,
        &1.domain,
        &1.resource,
        &1.action,
        opts.tenant
      )
    )
  end

  def has_vectorize_change?(%Ash.Changeset{} = changeset) do
    full_text_attrs =
      case AshAi.Info.vectorize_full_text_used_attributes(changeset.resource) do
        {:ok, used_attrs} -> used_attrs
        :error -> []
      end

    vectorized_attrs =
      AshAi.Info.vectorize_attributes!(changeset.resource)
      |> Enum.map(fn {attr, _} -> attr end)

    Enum.any?(vectorized_attrs ++ full_text_attrs, fn attr ->
      Ash.Changeset.changing_attribute?(changeset, attr)
    end)
  end

  defp can?(actor, domain, resource, action, tenant) do
    if Enum.empty?(Ash.Resource.Info.authorizers(resource)) do
      true
    else
      Ash.can?({resource, action}, actor,
        tenant: tenant,
        domain: domain,
        maybe_is: true,
        run_queries?: false,
        pre_flight?: false
      )
    end
  rescue
    e ->
      Logger.error(
        """
        Error raised while checking permissions for #{inspect(resource)}.#{action.name}

        When checking permissions, we check the action using an empty input.
        Your action should be prepared for this.

        For create/update/destroy actions, you may need to add `only_when_valid?: true`
        to the changes, for other things, you may want to check validity of the changeset,
        query or action input.

        #{Exception.format(:error, e, __STACKTRACE__)}
        """,
        __STACKTRACE__
      )

      false
  end
end
