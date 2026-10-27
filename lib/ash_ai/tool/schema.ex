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
          arguments: tool_arguments,
          identity: identity,
          get_by: get_by
        } = tool,
        opts \\ []
      ) do
    strict? = Keyword.get(opts, :strict?, true)

    for_action(domain, resource, action, action_parameters, tool_arguments,
      strict?: strict?,
      identity: identity,
      get_by: get_by,
      full_filter_schema?: Map.get(tool, :full_filter_schema?, false),
      compact_field_list?: Map.get(tool, :compact_field_list?, false),
      filterable_fields: tool.filterable_fields,
      sortable_fields: tool.sortable_fields,
      aggregatable_fields: tool.aggregatable_fields
    )
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
    identity = Keyword.get(opts, :identity, nil)
    get_by = Keyword.get(opts, :get_by, nil)

    get_by_fields =
      if action.type == :read do
        AshAi.Tool.get_by_fields(resource, get_by)
      else
        []
      end

    # Mirror `AshAi.Tool.Execution.identity_filter/3`: address records by the
    # configured identity (or the primary key by default, or nothing when `false`).
    identity_keys =
      if action.type in [:update, :destroy] do
        AshAi.Tool.identity_keys(resource, identity)
      else
        []
      end

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

    {properties, fields_description} =
      add_action_specific_properties(props_with_input, resource, action, action_parameters,
        strict?: strict?,
        identity_keys: identity_keys,
        get_by_fields: get_by_fields,
        full_filter_schema?: Keyword.get(opts, :full_filter_schema?, false),
        compact_field_list?: Keyword.get(opts, :compact_field_list?, false),
        filterable_fields: Keyword.get(opts, :filterable_fields),
        sortable_fields: Keyword.get(opts, :sortable_fields),
        aggregatable_fields: Keyword.get(opts, :aggregatable_fields)
      )

    %{
      type: :object,
      properties: properties,
      required: Map.keys(props_with_input) ++ Enum.map(get_by_fields, & &1.name) ++ identity_keys,
      additionalProperties: false
    }
    |> then(fn schema ->
      if fields_description do
        Map.put(schema, :description, fields_description)
      else
        schema
      end
    end)
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
  # - Every non-required property is made nullable
  # - Unsupported validation keywords (like `minLength` and `maxLength`) are stripped
  defp make_strict_schema(schema) when is_map(schema) do
    schema =
      schema
      |> Map.drop(["minLength", "maxLength", :minLength, :maxLength])

    schema =
      if schema["type"] == "object" && is_map(schema["properties"]) do
        already_required = MapSet.new(schema["required"] || [])

        updated_props =
          Map.new(schema["properties"], fn {k, v} ->
            if MapSet.member?(already_required, k) do
              {k, make_strict_schema(v)}
            else
              {k, make_nullable(make_strict_schema(v))}
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

  # Makes a schema accept null, preferring the compact `"type": [..., "null"]`
  # form over an `anyOf` wrapper. `enum` validates independently of `type`, so
  # null is appended there too.
  defp make_nullable(%{"type" => type} = schema) when is_binary(type) or is_list(type) do
    types = List.wrap(type)

    if "null" in types do
      schema
    else
      schema
      |> Map.put("type", types ++ ["null"])
      |> then(fn s ->
        case s["enum"] do
          enum when is_list(enum) -> Map.put(s, "enum", enum ++ [nil])
          _ -> s
        end
      end)
    end
  end

  defp make_nullable(schema), do: %{"anyOf" => [%{"type" => "null"}, schema]}

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

  @all_result_types [:run_query, :count, :exists, :aggregate]

  # `action_parameters` may contain a `result_type: [...]` entry restricting which
  # result types are offered. `:run_query` is always included.
  defp extract_result_types(nil), do: {@all_result_types, nil}

  defp extract_result_types(action_parameters) do
    case List.keyfind(action_parameters, :result_type, 0) do
      {:result_type, types} ->
        {Enum.uniq([:run_query | types]),
         Enum.map(action_parameters, fn
           {:result_type, _types} -> :result_type
           other -> other
         end)}

      nil ->
        {@all_result_types, action_parameters}
    end
  end

  defp add_action_specific_properties(properties, resource, action, action_parameters, opts)

  defp add_action_specific_properties(
         properties,
         resource,
         %{type: :read, pagination: pagination},
         action_parameters,
         opts
       ) do
    case Keyword.get(opts, :get_by_fields, []) do
      [_ | _] = get_by_fields ->
        get_by_fields
        |> Map.new(fn field ->
          {field.name, AshAi.OpenApi.resource_write_attribute_type(field, resource, :create)}
        end)
        |> then(&{Map.merge(properties, &1), nil})

      [] ->
        strict? = Keyword.get(opts, :strict?, true)
        {allowed_result_types, action_parameters} = extract_result_types(action_parameters)

        read_query_properties(
          properties,
          resource,
          pagination,
          action_parameters,
          strict?,
          allowed_result_types,
          opts
        )
    end
  end

  defp add_action_specific_properties(
         properties,
         resource,
         %{type: type},
         _action_parameters,
         opts
       )
       when type in [:update, :destroy] do
    identity_properties =
      opts
      |> Keyword.get(:identity_keys, [])
      |> Map.new(fn key ->
        value =
          Ash.Resource.Info.attribute(resource, key)
          |> AshAi.OpenApi.resource_write_attribute_type(resource, type)

        {key, value}
      end)

    {Map.merge(properties, identity_properties), nil}
  end

  defp add_action_specific_properties(properties, _resource, _action, _action_parameters, _opts),
    do: {properties, nil}

  defp read_query_properties(
         properties,
         resource,
         pagination,
         action_parameters,
         strict?,
         allowed_result_types,
         opts
       ) do
    full_schema? = Keyword.get(opts, :full_filter_schema?, false)
    compact? = Keyword.get(opts, :compact_field_list?, false) and not full_schema?

    aggregate_fields =
      resource
      |> AshAi.Tool.query_fields(:aggregatable_fields, opts[:aggregatable_fields])
      |> Enum.map(& &1.name)

    sortable_candidates =
      AshAi.Tool.query_fields(resource, :sortable_fields, opts[:sortable_fields])

    sortable_fields = Enum.map(sortable_candidates, & &1.name)

    filterable_candidates =
      AshAi.Tool.query_fields(resource, :filterable_fields, opts[:filterable_fields])

    # An explicitly empty allow-list leaves nothing to aggregate
    allowed_result_types =
      if opts[:aggregatable_fields] == [],
        do: List.delete(allowed_result_types, :aggregate),
        else: allowed_result_types

    paginated? = match?(%Ash.Resource.Actions.Read.Pagination{}, pagination)

    scalar_result_types =
      for type <- ["run_query", "count", "exists"],
          String.to_existing_atom(type) in allowed_result_types,
          do: type

    scalar_result_type_schema = %{
      type: :string,
      description:
        scalar_result_types
        |> Enum.map_join(", or ", fn
          "run_query" when paginated? ->
            "run the query returning a page of results (check `has_more` to see whether further pages exist)"

          "run_query" ->
            "run the query returning the matching records (up to `limit`)"

          "count" ->
            "return a count of results"

          "exists" ->
            "check if any results exist"
        end)
        |> String.capitalize(),
      enum: scalar_result_types
    }

    aggregate_result_type_schema = %{
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
        field: field_name_schema("The field to aggregate", aggregate_fields, compact?)
      }
    }

    result_type_schema =
      cond do
        :aggregate not in allowed_result_types ->
          Map.merge(scalar_result_type_schema, %{default: "run_query"})

        strict? ->
          %{
            default: "run_query",
            description: "The type of result to return",
            anyOf: [scalar_result_type_schema, aggregate_result_type_schema]
          }

        true ->
          %{
            default: "run_query",
            description: "The type of result to return",
            oneOf: [
              scalar_result_type_schema,
              aggregate_result_type_schema
              |> Map.delete(:description)
              |> Map.delete(:additionalProperties)
            ]
          }
      end

    {filterable_fields, available_operators} =
      filterable_candidates
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

    filter_schema =
      cond do
        !full_schema? ->
          %{
            type: :object,
            description: """
            A filter to apply to the query: either a condition \
            {"field": ..., "operator": ..., "value": ...} or an \
            {"and": [...]} / {"or": [...]} group of conditions and groups (nestable). \
            Operators: #{Enum.join(available_operators, ", ")}. \
            For 'is_nil' the value is true or false; for 'in' the value is an array. \
            Fields: #{if compact?, do: "those listed for filtering in the input schema's description", else: Enum.join(filterable_fields, ", ")}.\
            """
          }

        strict? ->
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

        true ->
          %{
            type: :object,
            description: "Filter results",
            properties:
              Map.new(filterable_candidates, fn field ->
                {field.name, AshAi.OpenApi.raw_filter_type(field, resource)}
              end)
          }
      end

    properties
    |> Map.merge(%{
      filter: filter_schema,
      result_type: result_type_schema,
      limit: %{
        type: :integer,
        description:
          if(paginated?,
            do: "The maximum number of records to return in one page",
            else: "The maximum number of records to return"
          ),
        default:
          case pagination do
            %Ash.Resource.Actions.Read.Pagination{default_limit: limit} when is_integer(limit) ->
              limit

            _ ->
              25
          end
      },
      sort: %{
        type: :array,
        items: %{
          type: :object,
          required: [:field, :direction],
          properties:
            %{
              field: field_name_schema("The field to sort by", sortable_fields, compact?),
              direction: %{
                type: :string,
                description: "The direction to sort by",
                enum: ["asc", "desc"]
              }
            }
            |> add_input_for_fields(sortable_candidates, resource)
        }
      }
    })
    |> Map.merge(query_offset_property(pagination))
    # An explicitly empty allow-list removes the parameter it would feed
    |> Map.drop(
      for {key, option} <- [filter: :filterable_fields, sort: :sortable_fields],
          opts[option] == [],
          do: key
    )
    |> then(fn map ->
      if action_parameters do
        Map.take(map, action_parameters ++ [:input])
      else
        map
      end
    end)
    |> then(fn map ->
      uses =
        Enum.filter(
          [
            {"filter", :filter, filterable_fields},
            {"sort", :sort, sortable_fields},
            {"aggregate", :result_type, aggregate_fields}
          ],
          fn
            {"aggregate", key, _fields} ->
              Map.has_key?(map, key) and :aggregate in allowed_result_types

            {_use, key, _fields} ->
              Map.has_key?(map, key)
          end
        )

      description = if compact?, do: fields_description(resource, uses)

      {Map.merge(map, pagination_properties(pagination)), description}
    end)
  end

  # With `compact_field_list?` the field names are listed once, in the schema
  # description, rather than in every parameter that takes one
  defp field_name_schema(description, _fields, true = _compact?) do
    %{
      type: :string,
      description: "#{description}, from the field list in the input schema's description"
    }
  end

  defp field_name_schema(description, fields, false = _compact?),
    do: %{type: :string, description: description, enum: fields}

  # Each field appears once, annotated only when it can't be used for everything offered
  defp fields_description(_resource, []), do: nil

  defp fields_description(resource, uses) do
    entries =
      resource
      |> Ash.Resource.Info.fields([:attributes, :aggregates, :calculations])
      |> Enum.flat_map(fn %{name: name} ->
        case for({use, _key, fields} <- uses, name in fields, do: use) do
          [] -> []
          supported when length(supported) == length(uses) -> [to_string(name)]
          supported -> ["#{name} (#{Enum.join(supported, " and ")} only)"]
        end
      end)

    if entries != [] do
      uses = Enum.map(uses, &elem(&1, 0))
      "Fields that can be used to #{join_uses(uses)}: #{Enum.join(entries, ", ")}."
    end
  end

  defp join_uses([use]), do: use

  defp join_uses(uses) do
    {rest, [last]} = Enum.split(uses, -1)
    Enum.join(rest, ", ") <> " or " <> last
  end

  # Non-paginated actions accept an `offset` applied directly to the query; it is
  # an ordinary query control, so `action_parameters` may hide it.
  defp query_offset_property(%Ash.Resource.Actions.Read.Pagination{}), do: %{}

  defp query_offset_property(_pagination) do
    %{
      offset: %{
        type: :integer,
        description: "The number of records to skip",
        default: 0
      }
    }
  end

  # Paginated actions always expose the controls their pagination supports, even
  # when `action_parameters` narrows the other query controls: the page they
  # return carries the value to pass for the next page, so the LLM must be able
  # to pass it. Keyset is the default when available. Mirrors
  # `AshAi.Tool.Execution` page option selection.
  defp pagination_properties(%Ash.Resource.Actions.Read.Pagination{} = pagination) do
    offset =
      if pagination.offset? do
        %{
          offset: %{
            type: :integer,
            description:
              if(pagination.keyset?,
                do:
                  "The number of records to skip. Pages use keyset cursors by default; pass a positive offset to page by position instead, then pass the `next_offset` from that page for the following one.",
                else:
                  "The number of records to skip. Pass the `next_offset` from a previous page to fetch the following page."
              ),
            default: 0
          }
        }
      else
        %{}
      end

    keyset =
      if pagination.keyset? do
        %{
          after: %{
            type: :string,
            description:
              "Fetch the page after this keyset cursor. Pass the `end_keyset` from a previous page to fetch the following page."
          },
          before: %{
            type: :string,
            description:
              "Fetch the page before this keyset cursor. Pass the `start_keyset` from a previous page to fetch the preceding page."
          }
        }
      else
        %{}
      end

    Map.merge(offset, keyset)
  end

  defp pagination_properties(_pagination), do: %{}

  defp add_input_for_fields(sort_obj, sortable_fields, resource) do
    sortable_fields
    |> Enum.filter(&match?(%Ash.Resource.Calculation{arguments: [_ | _]}, &1))
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
