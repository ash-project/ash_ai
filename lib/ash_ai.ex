defmodule AshAi do
  @moduledoc """
  Documentation for `AshAi`.
  """

  defimpl Jason.Encoder, for: OpenApiSpex.Schema do
    def encode(value, opts) do
      OpenApiSpex.OpenApi.to_map(value) |> Jason.Encoder.Map.encode(opts)
    end
  end

  defmodule Options do
    use Spark.Options.Validator,
      schema: [
        actions: [
          type: {:wrap_list, {:tuple, [{:spark, Ash.Resource}, :atom]}},
          doc: """
          A set of {Resource, :action} pairs, or `{Resource, :*}` for all actions.

          By default, the first 32 actions that we find are used.
          """
        ],
        actor: [
          type: :any,
          doc: "The actor performing any actions."
        ],
        messages: [
          type: {:list, :map},
          default: [],
          doc: """
          Used to provide conversation history.
          """
        ],
        otp_app: [
          type: :atom,
          doc: "If present, allows discovering resource actions automatically."
        ],
        system_prompt: [
          type: {:fun, 1},
          doc: """
          A system prompt that takes the provided options and returns a system prompt.

          You will want to include something like the actor's id if you are chatting as an
          actor.
          """
        ]
      ]
  end

  @doc """
  Chat with the AI in IEx.

  See `instruct/2` for available options.
  """
  def iex_chat(prompt, opts \\ []) do
    {prompt, opts} =
      if Keyword.keyword?(prompt) do
        {nil, prompt}
      else
        {prompt, opts}
      end

    opts = Options.validate!(opts)

    if is_nil(prompt) do
      IO.puts("Hello!")

      case String.trim(Mix.shell().prompt("❯ ")) do
        "" ->
          iex_chat("", opts)

        quit when quit in ["quit", "exit", "stop", "n"] ->
          :done

        message ->
          instruct(message, opts)
      end
    else
      case instruct(prompt, opts) do
        {:ok, response, messages} ->
          IO.puts(String.trim(response))

          case String.trim(Mix.shell().prompt("❯ ")) do
            "" ->
              iex_chat("", %{opts | messages: messages})

            quit when quit in ["quit", "exit", "stop", "n"] ->
              :done

            message ->
              instruct(message, %{opts | messages: messages})
          end
      end
    end
    |> case do
      :done ->
        :done

      {:ok, last_message, messages} ->
        IO.puts(String.trim(last_message))

        case String.trim(Mix.shell().prompt("❯ ")) do
          quit when quit in ["quit", "exit", "stop", "n"] ->
            :done

          message ->
            iex_chat(
              message,
              %{opts | messages: messages ++ [OpenaiEx.ChatMessage.system(last_message)]}
            )
        end
    end
  end

  def instruct!(prompt, opts \\ []) do
    {:ok, res, _} = instruct(prompt, opts)
    res
  end

  def instruct(prompt, opts \\ []) do
    opts = Options.validate!(opts)

    functions = functions(opts)

    apikey = System.fetch_env!("OPEN_AI_API_KEY")
    openai = OpenaiEx.new(apikey)

    system =
      if opts.system_prompt do
        opts.system_prompt.(opts)
      else
        if opts.actor do
          """
          Your job is to operate the application on behalf of the following actor:

          #{inspect(opts.actor)}

          Do not make assumptions about what they can or cannot do. All actions are secure,
          and will forbid any unauthorized actions.
          """
        else
          """
          Your job is to operate the application. The user has not identified themself.
          If you need to know the user, say something like "an actor must be provided to fulfill this request".

          Do not make assumptions about what you can or cannot do. All actions are secure,
          and will forbid any unauthorized actions.
          """
        end
      end

    messages =
      opts.messages ++
        [
          OpenaiEx.ChatMessage.system(system),
          OpenaiEx.ChatMessage.user(prompt)
        ]

    fn_req =
      OpenaiEx.Chat.Completions.new(
        model: "gpt-4o-mini",
        messages: messages,
        tools: functions,
        tool_choice: "auto"
      )

    openai
    |> OpenaiEx.Chat.Completions.create!(fn_req)
    |> call_until_complete(opts.actor, openai, functions, messages)
  end

  defp call_until_complete(
         %{
           "choices" => [
             %{
               "message" =>
                 %{
                   "tool_calls" => [
                     %{
                       "function" => %{
                         "name" => "complete",
                         "arguments" => arguments
                       }
                     }
                     | _
                   ]
                 } = message
             }
             | _
           ]
         },
         _actor,
         _openai,
         _functions,
         messages
       ) do
    arguments = Jason.decode!(arguments)
    {:ok, arguments["message"], messages ++ [message]}
  end

  defp call_until_complete(
         %{"choices" => [%{"finish_reason" => "stop", "message" => %{"content" => content}}]},
         _actor,
         _openai,
         _functions,
         messages
       ) do
    {:ok, content, messages}
  end

  defp call_until_complete(%{"choices" => choices}, actor, openai, functions, messages) do
    choice = Enum.at(choices, 0)["message"]

    if Enum.empty?(choice["tool_calls"] || []) do
      raise "no tool calls"
    end

    tool_call_results =
      Enum.flat_map(choice["tool_calls"], fn
        %{"function" => %{"name" => "complete"}} ->
          []

        %{"function" => %{"name" => name, "arguments" => arguments}, "id" => id} ->
          try do
            arguments = Jason.decode!(arguments)

            [domain, resource, action] = String.split(name, "-")

            domain = Module.concat([String.replace(domain, "_", ".")])
            resource = Module.concat([String.replace(resource, "_", ".")])

            action =
              Ash.Resource.Info.actions(resource)
              |> Enum.find(fn action_struct ->
                to_string(action_struct.name) == action
              end)

            # make this JSON!
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

                resource
                |> Ash.Query.limit(arguments["limit"])
                |> Ash.Query.offset(arguments["offset"])
                |> Ash.Query.load(arguments["load"])
                |> then(fn query ->
                  if sort != "" do
                    Ash.Query.sort_input(query, sort)
                  else
                    query
                  end
                end)
                |> then(fn query ->
                  if Map.has_key?(arguments, "filter") do
                    Ash.Query.filter_input(query, arguments["filter"])
                  else
                    query
                  end
                end)
                |> Ash.Query.for_read(action.name, arguments["input"] || %{},
                  domain: domain,
                  actor: actor
                )
                |> Ash.read!()
                |> inspect(limit: :infinity)
                |> tool_call_result(id, name)
                |> List.wrap()

              :update ->
                pkey =
                  Map.new(Ash.Resource.Info.primary_key(resource), fn key ->
                    {key, arguments[to_string(key)]}
                  end)

                resource
                |> Ash.get!(pkey)
                |> Ash.Changeset.for_update(action.name, arguments["input"],
                  domain: domain,
                  actor: actor
                )
                |> Ash.update!()
                |> inspect(limit: :infinity)
                |> tool_call_result(id, name)
                |> List.wrap()

              :destroy ->
                pkey =
                  Map.new(Ash.Resource.Info.primary_key(resource), fn key ->
                    {key, arguments[to_string(key)]}
                  end)

                resource
                |> Ash.get!(pkey)
                |> Ash.Changeset.for_destroy(action.name, arguments["input"],
                  domain: domain,
                  actor: actor
                )
                |> Ash.destroy!()
                |> inspect(limit: :infinity)
                |> tool_call_result(id, name)

              :create ->
                resource
                |> Ash.Changeset.for_create(action.name, arguments["input"],
                  domain: domain,
                  actor: actor
                )
                |> Ash.create!()
                |> inspect(limit: :infinity)
                |> tool_call_result(id, name)
                |> List.wrap()
            end
          rescue
            e ->
              inspect(Exception.format(:error, e, __STACKTRACE__))
              |> tool_call_result(id, name)
              |> List.wrap()
          end
      end)

    messages = messages ++ [choice | tool_call_results]

    fn_req =
      OpenaiEx.Chat.Completions.new(
        model: "gpt-4o-mini",
        messages: messages,
        tools: functions,
        tool_choice: "auto"
      )

    openai
    |> OpenaiEx.Chat.Completions.create!(fn_req)
    |> call_until_complete(actor, openai, functions, messages)
  end

  defp tool_call_result(result, id, name) do
    OpenaiEx.ChatMessage.tool(id, name, result)
  end

  defp functions(opts) do
    opts
    |> actions()
    |> Enum.map(fn {domain, resource, action} ->
      inputs =
        AshJsonApi.OpenApi.write_attributes(
          resource,
          action.arguments,
          action,
          %{type: :action, route: "/"},
          :json
        )
        |> then(fn attrs ->
          %{
            type: :object,
            properties:
              %{
                input: %{
                  type: :object,
                  properties: attrs
                }
              }
              |> add_action_specific_properties(resource, action)
          }
        end)
        |> Jason.encode!()

      name =
        "#{String.replace(inspect(domain), ".", "_")}-#{String.replace(inspect(resource), ".", "_")}-#{action.name}"

      %{
        type: :function,
        function: %{
          name: name,
          description:
            action.description ||
              "Call the #{action.name} action on the #{inspect(resource)} resource",
          parameters: inputs |> Jason.decode!()
        }
      }
    end)
    |> Enum.concat([
      %{
        type: :function,
        function: %{
          name: "complete",
          description: "Call this when the users original request has been fulfilled",
          parameters: %{
            type: :object,
            properties: %{
              message: %{
                type: :string,
                description: "The message to explain why the tool is complete."
              }
            }
          }
        }
      }
    ])
  end

  defp add_action_specific_properties(properties, resource, %{type: :read}) do
    Map.merge(properties, %{
      filter: %{
        type: :object,
        # querying is complex, will likely need to be a two step process
        # i.e first decide to query, and then provide it with a function to call
        # that has all the options Then the filter object can be big & expressive.
        properties:
          Ash.Resource.Info.fields(resource, [:attributes])
          |> Enum.filter(& &1.public?)
          |> Enum.map(fn field ->
            {field.name, AshJsonApi.OpenApi.raw_filter_type(field, resource)}
          end)
          |> Enum.into(%{})
      },
      load: %{
        type: :array,
        items: %{
          type: :string,
          enum:
            Ash.Resource.Info.fields(resource, [
              :relationships,
              :calculations,
              :aggregates
            ])
            |> Enum.filter(& &1.public?)
            |> Enum.map(& &1.name)
        }
      },
      limit: %{
        type: :integer,
        description: "The maximum number of records to return",
        default: 10
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
          properties: %{
            field: %{
              type: :string,
              description: "The field to sort by",
              enum:
                Ash.Resource.Info.fields(resource, [
                  :attributes,
                  :calculations,
                  :aggregates
                ])
                |> Enum.filter(& &1.public?)
                |> Enum.map(& &1.name)
            },
            direction: %{
              type: :string,
              description: "The direction to sort by",
              enum: ["asc", "desc"]
            }
          }
        }
      }
    })
  end

  defp add_action_specific_properties(properties, resource, %{type: type})
       when type in [:update, :destroy] do
    pkey = Map.new(Ash.Resource.Info.primary_key(resource), fn key -> {key, %{type: :string}} end)

    Map.merge(properties, pkey)
  end

  defp add_action_specific_properties(properties, _resource, _action), do: properties

  defp actions(opts) do
    if opts.actions do
      Enum.flat_map(opts.actions, fn {resource, actions} ->
        if !Ash.Resource.Info.domain(resource) do
          raise "Cannot use an ash resource that does not have a domain"
        end

        if actions == :* do
          Enum.map(Ash.Resource.Info.actions(resource), fn action ->
            {Ash.Resource.Info.domain(resource), resource, action}
          end)
        else
          Enum.map(List.wrap(actions), fn action ->
            action_struct = Ash.Resource.Info.action(resource, action)

            unless action_struct do
              raise "Action #{inspect(action)} does not exist on resource #{inspect(resource)}"
            end

            {Ash.Resource.Info.domain(resource), resource, action_struct}
          end)
        end
      end)
    else
      if !opts.otp_app do
        raise "Must specify `otp_app` if you do not specify `actions`"
      end

      for domain <- Application.get_env(opts.otp_app, :ash_domains) || [],
          resource <- Ash.Domain.Info.resources(domain),
          action <- Ash.Resource.Info.actions(resource) do
        {domain, resource, action}
      end
      |> Enum.uniq_by(fn {_domain, resource, action} ->
        {resource, action}
      end)
      |> Enum.filter(fn {_domain, resource, action} ->
        if opts.actions do
          Enum.any?(opts.actions, fn {allowed_resource, allowed_actions} ->
            allowed_resource == resource and (allowed_actions == :* or action in allowed_actions)
          end)
        else
          true
        end
      end)
      |> Enum.take(32)
    end
  end
end
