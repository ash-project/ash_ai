# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Tool.Schema do
  @moduledoc """
  Generates JSON schemas for tool parameters.

  Supports both strict and non-strict modes:
  - strict mode transforms schemas for OpenAI-compatible strict tool calling
  - non-strict mode strips `additionalProperties` for providers like Gemini
  """

  @doc """
  Generates a JSON schema for the given tool definition.
  """
  def for_tool(
        %AshAi.Tool{
          domain: domain,
          resource: resource,
          action: action,
          action_parameters: action_parameters,
          arguments: tool_arguments
        },
        opts \\ []
      ) do
    strict? = Keyword.get(opts, :strict?, true)
    for_action(domain, resource, action, action_parameters, tool_arguments, strict?: strict?)
  end

  @doc """
  Generates a JSON schema for a given action.
  """
  def for_action(
        _domain,
        resource,
        action,
        action_parameters \\ nil,
        tool_arguments \\ [],
        opts \\ []
      ) do
    strict? = Keyword.get(opts, :strict?, true)

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
      |> Enum.reduce(attributes, fn argument, attrs ->
        value = AshAi.OpenApi.resource_write_attribute_type(argument, resource, :create)
        Map.put(attrs, argument.name, value)
      end)

    properties =
      Enum.reduce(tool_arguments, properties, fn argument, props ->
        tool_argument = %{
          name: argument.name,
          type: argument.type,
          constraints: argument.constraints,
          allow_nil?: argument.allow_nil?,
          default: argument.default,
          description: argument.description
        }

        Map.put(
          props,
          argument.name,
          AshAi.OpenApi.resource_write_attribute_type(tool_argument, resource, :create)
        )
      end)

    required_tool_arguments =
      tool_arguments
      |> Enum.filter(&(not &1.allow_nil?))
      |> Enum.map(& &1.name)

    required_action_arguments =
      AshAi.OpenApi.required_write_attributes(resource, action.arguments, action)

    props_with_input =
      if Enum.empty?(properties) do
        %{}
      else
        %{
          input: %{
            type: :object,
            properties: properties,
            additionalProperties: false,
            required: Enum.uniq(required_action_arguments ++ required_tool_arguments)
          }
        }
      end

    %{
      type: :object,
      properties:
        add_action_specific_properties(props_with_input, resource, action, action_parameters,
          strict?: strict?
        ),
      required: Map.keys(props_with_input),
      additionalProperties: false
    }
    |> Jason.encode!()
    |> Jason.decode!()
    |> then(fn schema ->
      if strict? do
        make_strict_schema(schema)
      else
        strip_additional_properties(schema)
      end
    end)
  end

  # Recursively transforms a JSON schema to be OpenAI strict-mode compliant:
  # - Every object gets `additionalProperties: false`
  # - Every non-required property is wrapped in `anyOf: [null, ...]`
  defp make_strict_schema(schema) when is_map(schema) do
    schema =
      if schema["type"] == "object" && is_map(schema["properties"]) do
        already_required = MapSet.new(schema["required"] || [])

        updated_props =
          Map.new(schema["properties"], fn {k, v} ->
            if MapSet.member?(already_required, k) do
              {k, make_strict_schema(v)}
            else
              {k, %{"anyOf" => [%{"type" => "null"}, make_strict_schema(v)]}}
            end
          end)

        schema
        |> Map.put("properties", updated_props)
        |> Map.put("required", Map.keys(schema["properties"]))
        |> Map.put("additionalProperties", false)
      else
        schema
      end

    schema
    |> then(fn s ->
      case s["anyOf"] do
        nil -> s
        types -> Map.put(s, "anyOf", Enum.map(types, &make_strict_schema/1))
      end
    end)
    |> then(fn s ->
      case s["items"] do
        nil -> s
        items -> Map.put(s, "items", make_strict_schema(items))
      end
    end)
  end

  defp make_strict_schema(schema) when is_list(schema),
    do: Enum.map(schema, &make_strict_schema/1)

  defp make_strict_schema(schema), do: schema

  # Recursively removes `additionalProperties` from a schema map.
  defp strip_additional_properties(schema) when is_map(schema) do
    schema
    |> Map.delete("additionalProperties")
    |> Map.new(fn {k, v} -> {k, strip_additional_properties(v)} end)
  end

  defp strip_additional_properties(schema) when is_list(schema) do
    Enum.map(schema, &strip_additional_properties/1)
  end

  defp strip_additional_properties(schema), do: schema

  defp add_action_specific_properties(properties, resource, action, action_parameters, opts)

  defp add_action_specific_properties(
         properties,
         resource,
         %{type: :read, pagination: pagination},
         action_parameters,
         opts
       ) do
    strict? = Keyword.get(opts, :strict?, true)

    aggregate_fields =
      Ash.Resource.Info.fields(resource, [
        :attributes,
        :aggregates,
        :calculations
      ])
      |> Enum.filter(& &1.public?)
      |> Enum.map(& &1.name)

    result_type_schema =
      if strict? do
        %{
          default: "run_query",
          description: "The type of result to return",
          anyOf: [
            %{
              type: :string,
              description:
                "Run the query returning all results, or return a count of results, or check if any results exist",
              enum: ["run_query", "count", "exists"]
            },
            %{
              type: :object,
              description: "Aggregate a field across all results",
              additionalProperties: false,
              required: [:aggregate, :field],
              properties: %{
                aggregate: %{
                  type: :string,
                  description: "The aggregate function to use",
                  enum: [:max, :min, :sum, :avg, :count]
                },
                field: %{
                  type: :string,
                  description: "The field to aggregate",
                  enum: aggregate_fields
                }
              }
            }
          ]
        }
      else
        %{
          default: "run_query",
          description: "The type of result to return",
          oneOf: [
            %{
              description:
                "Run the query returning all results, or return a count of results, or check if any results exist",
              enum: ["run_query", "count", "exists"]
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
                  enum: aggregate_fields
                }
              }
            }
          ]
        }
      end

    filter_schema =
      if strict? do
        {filterable_fields, available_operators} =
          Ash.Resource.Info.fields(resource, [:attributes, :aggregates, :calculations])
          |> Enum.filter(&(&1.public? && &1.filterable?))
          |> Enum.reduce({[], MapSet.new()}, fn field, {fields, ops} ->
            case AshAi.OpenApi.raw_filter_type(field, resource) do
              nil ->
                {fields, ops}

              %{properties: props} ->
                field_ops = props |> Map.keys() |> Enum.map(&to_string/1) |> MapSet.new()
                {[field.name | fields], MapSet.union(ops, field_ops)}

              _ ->
                {fields, ops}
            end
          end)
          |> then(fn {fields, ops} ->
            {Enum.reverse(fields), ops |> MapSet.to_list() |> Enum.sort()}
          end)

        condition_schema = %{
          type: :object,
          additionalProperties: false,
          required: [:field, :operator, :value],
          properties: %{
            field: %{
              type: :string,
              description: "The field to filter on",
              enum: filterable_fields
            },
            operator: %{
              type: :string,
              description:
                "The comparison operator. Use 'is_nil' with true/false to check for null values.",
              enum: available_operators
            },
            value: %{
              description:
                "The comparison value. For 'is_nil' use true or false. For 'in'/'not_in' use an array of values.",
              anyOf: [
                %{type: :string},
                %{type: :number},
                %{type: :boolean},
                %{type: :null},
                %{
                  type: :array,
                  items: %{anyOf: [%{type: :string}, %{type: :number}, %{type: :boolean}]}
                }
              ]
            }
          }
        }

        %{
          type: :array,
          description:
            "Filter conditions. Top-level entries are ANDed together. Use an {\"or\": [...]} entry to OR multiple conditions.",
          items: %{
            anyOf: [
              condition_schema,
              %{
                type: :object,
                additionalProperties: false,
                required: [:or],
                properties: %{
                  or: %{
                    type: :array,
                    description: "A list of conditions where any one must match.",
                    items: condition_schema
                  }
                }
              }
            ]
          }
        }
      else
        %{
          type: :object,
          description: "Filter results",
          properties:
            Ash.Resource.Info.fields(resource, [:attributes, :aggregates, :calculations])
            |> Enum.filter(&(&1.public? && &1.filterable?))
            |> Map.new(fn field ->
              {field.name, AshAi.OpenApi.raw_filter_type(field, resource)}
            end)
        }
      end

    Map.merge(properties, %{
      filter: filter_schema,
      result_type: result_type_schema,
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

  defp add_action_specific_properties(
         properties,
         resource,
         %{type: type},
         _action_parameters,
         _opts
       )
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

  defp add_action_specific_properties(properties, _resource, _action, _action_parameters, _opts),
    do: properties

  defp add_input_for_fields(sort_obj, resource) do
    resource
    |> Ash.Resource.Info.fields([:calculations])
    |> Enum.filter(&(&1.public? && &1.sortable? && !Enum.empty?(&1.arguments)))
    |> case do
      [] ->
        sort_obj

      fields ->
        input_for_fields = %{
          type: :object,
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
                 required: required
               }}
            end)
        }

        Map.put(sort_obj, :input_for_fields, input_for_fields)
    end
  end
end
