# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs.contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Tools do
  @moduledoc """
  Utilities for interacting with AshAi tools.
  """

  require Ash.Expr

  alias AshAi.{Tool, ToolEndEvent, ToolStartEvent}

  @doc """
  Converts a AshAi.Tool into a LangChain.Function
  """
  def to_function(
        %Tool{
          name: name,
          domain: domain,
          resource: resource,
          action: action,
          async: async,
          description: description,
          action_parameters: action_parameters
        } = tool
      ) do
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
      function: &execute(tool, &1, &2)
    })
  end

  def execute(
        %Tool{
          name: name,
          domain: domain,
          resource: resource,
          action: action,
          load: load,
          identity: identity
        },
        arguments,
        context
      ) do
    tool_name = to_string(name)
    # Handle nil arguments from LangChain/MCP clients
    arguments = arguments || %{}

    actor = context[:actor]
    tenant = context[:tenant]
    input = arguments["input"] || %{}
    opts = [domain: domain, actor: actor, tenant: tenant, context: context[:context] || %{}]

    callbacks = context[:tool_callbacks] || %{}

    if on_start = callbacks[:on_tool_start] do
      on_start.(%ToolStartEvent{
        tool_name: tool_name,
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
              if Map.has_key?(arguments, "filter") do
                Ash.Query.filter_input(query, arguments["filter"])
              else
                query
              end
            end)
            |> Ash.Query.for_read(action.name, input, opts)
            |> then(fn query ->
              result_type = arguments["result_type"] || "run_query"

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
        tool_name: tool_name,
        result: result
      })
    end

    result
  end

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
            additionalProperties: false,
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
end
