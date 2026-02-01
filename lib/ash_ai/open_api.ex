# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.OpenApi do
  @moduledoc false
  @spec resource_write_attribute_type(
          term(),
          resource :: Ash.Resource.t(),
          action_type :: atom
        ) :: map()
  @doc false
  def resource_write_attribute_type(attribute, resource, action_type)

  def resource_write_attribute_type(
        %Ash.Resource.Aggregate{type: nil} = agg,
        resource,
        action_type
      ) do
    {type, constraints} = field_type(agg, resource)

    resource_write_attribute_type(
      Map.merge(agg, %{type: type, constraints: constraints}),
      resource,
      action_type
    )
  end

  def resource_write_attribute_type(
        %{type: {:array, type}} = attr,
        resource,
        action_type
      ) do
    %{
      type: :array,
      items:
        resource_write_attribute_type(
          %{
            attr
            | type: type,
              constraints: attr.constraints[:items] || []
          },
          resource,
          action_type
        )
    }
    |> with_attribute_description(attr)
  end

  def resource_write_attribute_type(
        %{type: Ash.Type.Map, constraints: constraints} = attr,
        resource,
        action_type
      ) do
    if constraints[:fields] && constraints[:fields] != [] do
      %{
        type: :object,
        additionalProperties: false,
        properties:
          Map.new(constraints[:fields], fn {key, config} ->
            {key,
             resource_write_attribute_type(
               %{
                 attr
                 | type: config[:type],
                   constraints: config[:constraints] || []
               }
               |> Map.put(:description, config[:description] || nil),
               resource,
               action_type
             )}
          end),
        required:
          constraints[:fields]
          |> Enum.filter(fn {_, config} -> !config[:allow_nil?] end)
          |> Enum.map(&elem(&1, 0))
      }
      |> add_null_for_non_required()
      |> make_all_required()
    else
      %{type: :object}
    end
    |> with_attribute_description(attr)
  end

  def resource_write_attribute_type(
        %{type: Ash.Type.Union, constraints: constraints} = attr,
        resource,
        action_type
      ) do
    subtypes =
      Enum.map(constraints[:types], fn {_name, config} ->
        fake_attr =
          %{
            attr
            | type: Ash.Type.get_type(config[:type]),
              constraints: config[:constraints]
          }
          |> Map.put(:description, config[:description] || nil)

        resource_write_attribute_type(fake_attr, resource, action_type)
      end)

    %{
      "anyOf" => subtypes
    }
    |> unwrap_any_of()
    |> with_attribute_description(attr)
  end

  def resource_write_attribute_type(
        %{type: Ash.Type.Struct, constraints: constraints} = attr,
        resource,
        action_type
      ) do
    if instance_of = constraints[:instance_of] do
      if embedded?(instance_of) && !constraints[:fields] do
        embedded_type_input(attr, action_type)
      else
        resource_write_attribute_type(
          %{attr | type: Ash.Type.Map},
          resource,
          action_type
        )
      end
    else
      %{}
    end
    |> with_attribute_description(attr)
  end

  def resource_write_attribute_type(%{type: type} = attr, resource, action_type) do
    cond do
      embedded?(type) ->
        embedded_type_input(attr, action_type)

      Ash.Type.NewType.new_type?(type) ->
        new_constraints = Ash.Type.NewType.constraints(type, attr.constraints)
        new_type = Ash.Type.NewType.subtype_of(type)

        resource_write_attribute_type(
          Map.merge(attr, %{type: Ash.Type.get_type(new_type), constraints: new_constraints}),
          resource,
          action_type
        )

      true ->
        resource_attribute_type(attr, resource)
    end
    |> with_attribute_description(attr)
  end

  defp add_null_for_non_required(%{required: required} = schema)
       when is_list(required) do
    Map.update!(schema, :properties, fn
      properties when is_map(properties) ->
        Enum.reduce(properties, %{}, fn {key, value}, acc ->
          if Enum.member?(required, key) do
            Map.put(acc, key, value)
          else
            description = value |> Map.get(:description)
            value = value |> Map.delete(:description)

            new_value =
              %{
                "anyOf" => [
                  %{
                    "type" => "null"
                  },
                  value
                ]
              }
              |> then(fn new_value ->
                case description do
                  nil -> new_value
                  description -> Map.put(new_value, "description", description)
                end
              end)
              |> unwrap_any_of()

            Map.put(
              acc,
              key,
              new_value
            )
          end
        end)

      properties ->
        properties
    end)
  end

  @spec with_attribute_description(
          map(),
          Ash.Resource.Attribute.t() | Ash.Resource.Actions.Argument.t() | any
        ) :: map()
  defp with_attribute_description(schema, %{"description" => nil}) do
    schema
  end

  defp with_attribute_description(schema, %{description: nil}) do
    schema
  end

  defp with_attribute_description(schema, %{description: description}) do
    Map.merge(schema, %{"description" => description})
  end

  defp with_attribute_description(schema, %{"description" => description}) do
    Map.merge(schema, %{"description" => description})
  end

  defp with_attribute_description(schema, _) do
    schema
  end

  defp field_type(%Ash.Resource.Attribute{type: type, constraints: constraints}, _resource),
    do: {type, constraints}

  defp field_type(%Ash.Resource.Calculation{type: type, constraints: constraints}, _resource),
    do: {type, constraints}

  defp field_type(%Ash.Resource.Aggregate{type: type, constraints: constraints}, _resource)
       when not is_nil(type),
       do: {type, constraints}

  defp field_type(
         %Ash.Resource.Aggregate{
           kind: kind,
           field: field,
           relationship_path: relationship_path
         },
         resource
       ) do
    field_type =
      with field when not is_nil(field) <- field,
           related when not is_nil(related) <-
             Ash.Resource.Info.related(resource, relationship_path),
           attr when not is_nil(attr) <- Ash.Resource.Info.field(related, field) do
        attr.type
      end

    {:ok, aggregate_type, constraints} =
      Ash.Query.Aggregate.kind_to_type(kind, field_type, [])

    {aggregate_type, constraints}
  end

  defp unwrap_any_of(%{"anyOf" => options} = schema) do
    {options_remaining, options_to_add} =
      Enum.reduce(options, {[], []}, fn schema, {options, to_add} ->
        case schema do
          %{"anyOf" => _} = schema ->
            case unwrap_any_of(schema) do
              %{"anyOf" => nested_options} ->
                {options, nested_options ++ to_add}

              schema ->
                {options, [schema | to_add]}
            end

          _ ->
            {[schema | to_add], options}
        end
      end)

    case Enum.uniq(options_remaining ++ options_to_add) do
      [] ->
        %{"type" => "any"}

      [one] ->
        one

      many ->
        %{"anyOf" => many}
    end
    |> then(fn result ->
      case schema["description"] || schema[:description] do
        nil -> result
        description -> Map.put(result, "description", description)
      end
    end)
  end

  defp embedded_type_input(%{type: resource} = attribute, action_type) do
    attribute = %{
      attribute
      | constraints: Ash.Type.NewType.constraints(resource, attribute.constraints)
    }

    resource =
      case attribute.constraints[:instance_of] do
        nil -> Ash.Type.NewType.subtype_of(resource)
        type -> type
      end

    create_action =
      case attribute.constraints[:create_action] do
        nil ->
          Ash.Resource.Info.primary_action(resource, :create)

        name ->
          Ash.Resource.Info.action(resource, name)
      end

    update_action =
      case attribute.constraints[:update_action] do
        nil ->
          Ash.Resource.Info.primary_action(resource, :update)

        name ->
          Ash.Resource.Info.action(resource, name)
      end

    create_write_attributes =
      if create_action do
        write_attributes(resource, create_action.arguments, create_action, nil)
      else
        %{}
      end

    update_write_attributes =
      if update_action do
        write_attributes(resource, update_action.arguments, update_action, nil)
      else
        %{}
      end

    create_required_attributes =
      if create_action do
        required_write_attributes(resource, create_action.arguments, create_action)
      else
        []
      end

    update_required_attributes =
      if update_action do
        required_write_attributes(resource, update_action.arguments, update_action)
      else
        []
      end

    required =
      if action_type == :create do
        create_required_attributes
      else
        create_required_attributes
        |> MapSet.new()
        |> MapSet.intersection(MapSet.new(update_required_attributes))
        |> Enum.to_list()
      end

    %{
      type: :object,
      additionalProperties: false,
      properties:
        Map.merge(create_write_attributes, update_write_attributes, fn _k, l, r ->
          %{
            "anyOf" => [
              l,
              r
            ]
          }
          |> unwrap_any_of()
        end),
      required: required
    }
    |> add_null_for_non_required()
    |> make_all_required()
  end

  # this is kind of a hack, specifically because open ai requires that all fields
  # be required. But the value can be `null`
  defp make_all_required(map) do
    Map.put(map, :required, Map.keys(map.properties))
  end

  @doc false
  def required_write_attributes(resource, arguments, action, _route \\ nil) do
    arguments =
      arguments
      |> Enum.filter(& &1.public?)

    attributes =
      case action.type do
        type when type in [:action, :read] ->
          []

        :update ->
          action.require_attributes

        _ ->
          resource
          |> Ash.Resource.Info.attributes()
          |> Enum.filter(&(&1.name in action.accept && &1.writable?))
          |> Enum.reject(
            &(&1.name in arguments || &1.allow_nil? || not is_nil(&1.default) || &1.generated? ||
                &1.name in Map.get(action, :allow_nil_input, []))
          )
          |> Enum.map(& &1.name)
      end

    arguments =
      arguments
      |> Enum.reject(& &1.allow_nil?)
      |> Enum.map(& &1.name)

    Enum.uniq(attributes ++ arguments ++ Map.get(action, :require_attributes, []))
  end

  @spec write_attributes(
          resource :: module,
          [Ash.Resource.Actions.Argument.t()],
          action :: term(),
          route :: term()
        ) :: %{atom => map()}
  defp write_attributes(resource, arguments, action, _route) do
    attributes =
      if action.type in [:action, :read] do
        %{}
      else
        resource
        |> Ash.Resource.Info.attributes()
        |> Enum.filter(&(&1.name in action.accept && &1.writable?))
        |> Map.new(fn attribute ->
          {attribute.name, resource_write_attribute_type(attribute, resource, action.type)}
        end)
      end

    arguments
    |> Enum.filter(& &1.public?)
    |> Enum.reduce(attributes, fn argument, attributes ->
      Map.put(
        attributes,
        argument.name,
        resource_write_attribute_type(argument, resource, :create)
      )
    end)
  end

  @spec resource_attribute_type(
          term(),
          resource :: Ash.Resource.t()
        ) :: map()
  defp resource_attribute_type(type, resource)

  defp resource_attribute_type(%Ash.Resource.Aggregate{type: nil} = agg, resource) do
    {type, constraints} = field_type(agg, resource)

    resource_attribute_type(
      Map.merge(agg, %{type: type, constraints: constraints}),
      resource
    )
  end

  defp resource_attribute_type(%{type: Ash.Type.String}, _resource) do
    %{type: :string}
  end

  defp resource_attribute_type(%{type: Ash.Type.CiString}, _resource) do
    %{type: :string}
  end

  defp resource_attribute_type(%{type: Ash.Type.Boolean}, _resource) do
    %{type: :boolean}
  end

  defp resource_attribute_type(%{type: Ash.Type.Decimal}, _resource) do
    %{type: :string}
  end

  defp resource_attribute_type(%{type: Ash.Type.Integer, constraints: constraints}, _resource) do
    %{type: :integer}
    |> add_number_constraints(constraints)
  end

  defp resource_attribute_type(
         %{type: Ash.Type.Map, constraints: constraints} = attr,
         resource
       ) do
    if constraints[:fields] && constraints[:fields] != [] do
      %{
        type: :object,
        properties:
          Map.new(constraints[:fields], fn {key, config} ->
            {key,
             resource_attribute_type(
               %{
                 attr
                 | type: Ash.Type.get_type(config[:type]),
                   constraints: config[:constraints] || []
               }
               |> Map.put(:description, config[:description] || nil),
               resource
             )}
          end),
        additionalProperties: false,
        required:
          constraints[:fields]
          |> Enum.filter(fn {_, config} -> !config[:allow_nil?] end)
          |> Enum.map(&elem(&1, 0))
      }
      |> add_null_for_non_required()
      |> make_all_required()
    else
      %{type: :object}
    end
  end

  defp resource_attribute_type(%{type: Ash.Type.Float, constraints: constraints}, _resource) do
    %{type: :number, format: :float}
    |> add_number_constraints(constraints)
  end

  defp resource_attribute_type(%{type: Ash.Type.Date}, _resource) do
    %{type: :string, format: :date}
  end

  defp resource_attribute_type(%{type: Ash.Type.UtcDatetime}, _resource) do
    %{type: :string, format: :"date-time"}
  end

  defp resource_attribute_type(%{type: Ash.Type.NaiveDatetime}, _resource) do
    %{type: :string, format: :"date-time"}
  end

  defp resource_attribute_type(%{type: Ash.Type.Time}, _resource) do
    %{type: :string, format: :time}
  end

  defp resource_attribute_type(%{type: Ash.Type.UUID}, _resource) do
    %{type: :string, format: :uuid}
  end

  defp resource_attribute_type(%{type: Ash.Type.UUIDv7}, _resource) do
    %{type: :string, format: :uuid}
  end

  defp resource_attribute_type(
         %{type: Ash.Type.Atom, constraints: constraints},
         _resource
       ) do
    if one_of = constraints[:one_of] do
      %{
        type: :string,
        enum: Enum.map(one_of, &to_string/1)
      }
    else
      %{
        type: :string
      }
    end
  end

  defp resource_attribute_type(%{type: Ash.Type.DurationName}, _resource) do
    %{
      type: :string,
      enum: Enum.map(Ash.Type.DurationName.values(), &to_string/1)
    }
  end

  defp resource_attribute_type(%{type: Ash.Type.File}, _resource),
    do: %{"type" => :string, "format" => :byte, "description" => "Base64 encoded file content"}

  defp resource_attribute_type(
         %{type: Ash.Type.Union, constraints: constraints} = attr,
         resource
       ) do
    subtypes =
      Enum.map(constraints[:types], fn {_name, config} ->
        fake_attr =
          %{
            attr
            | type: Ash.Type.get_type(config[:type]),
              constraints: config[:constraints]
          }
          |> Map.put(:description, config[:description] || nil)

        resource_attribute_type(fake_attr, resource)
      end)

    %{
      "anyOf" => subtypes
    }
    |> unwrap_any_of()
    |> with_attribute_description(attr)
  end

  defp resource_attribute_type(%{type: {:array, type}} = attr, resource) do
    %{
      type: :array,
      items:
        resource_attribute_type(
          %{
            attr
            | type: type,
              constraints: attr.constraints[:items] || []
          },
          resource
        )
    }
  end

  defp resource_attribute_type(
         %{type: Ash.Type.Struct, constraints: constraints} = attr,
         resource
       ) do
    if instance_of = constraints[:instance_of] do
      if embedded?(instance_of) && !constraints[:fields] do
        %{
          type: :object,
          additionalProperties: false,
          properties: resource_attributes(instance_of, false),
          required: required_attributes(instance_of)
        }
        |> add_null_for_non_required()
        |> make_all_required()
      else
        resource_attribute_type(%{attr | type: Ash.Type.Map}, resource)
      end
    else
      %{}
    end
  end

  defp resource_attribute_type(%{type: type} = attr, resource) do
    constraints = attr.constraints

    cond do
      embedded?(type) ->
        %{
          type: :object,
          additionalProperties: false,
          properties: resource_attributes(type, false),
          required: required_attributes(type)
        }
        |> add_null_for_non_required()
        |> make_all_required()

      Ash.Type.NewType.new_type?(type) ->
        new_constraints = Ash.Type.NewType.constraints(type, constraints)
        new_type = Ash.Type.NewType.subtype_of(type)

        resource_attribute_type(
          Map.merge(attr, %{type: Ash.Type.get_type(new_type), constraints: new_constraints}),
          resource
        )

      Spark.implements_behaviour?(type, Ash.Type.Enum) ->
        %{
          type: :string,
          enum: Enum.map(type.values(), &to_string/1)
        }

      true ->
        %{}
    end
  end

  @spec resource_attributes(
          resource :: module,
          hide_pkeys? :: boolean()
        ) :: %{
          atom => map()
        }
  defp resource_attributes(resource, hide_pkeys?) do
    resource
    |> Ash.Resource.Info.public_attributes()
    |> Enum.concat(Ash.Resource.Info.public_calculations(resource))
    |> Enum.concat(
      Ash.Resource.Info.public_aggregates(resource)
      |> set_aggregate_constraints(resource)
    )
    |> Enum.map(fn
      %Ash.Resource.Aggregate{} = agg ->
        field =
          if agg.field do
            related = Ash.Resource.Info.related(resource, agg.relationship_path)
            Ash.Resource.Info.field(related, agg.field)
          end

        field_type =
          if field do
            field.type
          end

        field_constraints =
          if field do
            field.constraints
          end

        {:ok, type, constraints} =
          Ash.Query.Aggregate.kind_to_type(agg.kind, field_type, field_constraints)

        type = Ash.Type.get_type(type)

        allow_nil? =
          is_nil(Ash.Query.Aggregate.default_value(agg.kind))

        %{
          name: agg.name,
          description: agg.description,
          type: type,
          constraints: constraints,
          allow_nil?: allow_nil?
        }

      other ->
        other
    end)
    |> then(fn keys ->
      if hide_pkeys? do
        Enum.reject(keys, &only_primary_key?(resource, &1.name))
      else
        keys
      end
    end)
    |> Map.new(fn attr ->
      {attr.name,
       resource_attribute_type(attr, resource)
       |> with_attribute_description(attr)
       |> with_attribute_nullability(attr)
       |> with_comment_on_included()}
    end)
  end

  defp add_number_constraints(schema, constraints) do
    constraints
    |> Keyword.take([:min, :max, :greater_than, :less_than])
    |> Enum.reduce(schema, fn
      {:min, min}, schema ->
        Map.put(schema, :minimum, min)

      {:max, max}, schema ->
        Map.put(schema, :maximum, max)

      {:greater_than, exclusive_min}, schema ->
        Map.put(schema, :exclusiveMinimum, exclusive_min)

      {:less_than, exclusive_max}, schema ->
        Map.put(schema, :exclusiveMaximum, exclusive_max)
    end)
  end

  defp required_attributes(resource) do
    resource
    |> Ash.Resource.Info.public_attributes()
    |> Enum.reject(&(&1.allow_nil? || only_primary_key?(resource, &1.name)))
    |> Enum.map(& &1.name)
  end

  @spec with_comment_on_included(map()) :: map()
  defp with_comment_on_included(schema) do
    key = if Map.has_key?(schema, :description), do: :description, else: "description"

    new_description =
      case Map.get(schema, key) do
        nil ->
          "Field included by default."

        description ->
          if String.ends_with?(description, ["!", "."]) do
            description <> " Field included by default."
          else
            description <> ". Field included by default."
          end
      end

    Map.put(schema, key, new_description)
  end

  defp with_attribute_nullability(%{type: nil} = schema, _), do: schema

  defp with_attribute_nullability(%{} = schema, attr) do
    cond do
      schema.type == "any" || schema.type == :any ->
        schema

      attr.allow_nil? ->
        Map.put(schema, :nullable, true)

      true ->
        schema
    end
  end

  def raw_filter_type(%Ash.Resource.Calculation{} = calculation, resource) do
    {type, _constraints} = field_type(calculation, resource)

    input =
      if Enum.empty?(calculation.arguments) do
        []
      else
        inputs =
          Enum.map(calculation.arguments, fn argument ->
            {argument.name, resource_write_attribute_type(argument, resource, :create)}
          end)

        required =
          Enum.flat_map(calculation.arguments, fn argument ->
            if argument.allow_nil? do
              []
            else
              [argument.name]
            end
          end)

        schema =
          %{
            type: :object,
            properties: Map.new(inputs),
            required: required,
            additionalProperties: false
          }

        [
          {:input, schema}
        ]
      end

    array_type? = match?({:array, _}, type)

    fields =
      Ash.Filter.builtin_operators()
      |> Enum.concat(Ash.Filter.builtin_functions())
      |> Enum.concat(Ash.DataLayer.functions(resource))
      |> Enum.filter(& &1.predicate?())
      |> restrict_for_lists(type)
      |> Enum.flat_map(fn operator ->
        filter_fields(operator, type, array_type?, calculation, resource)
      end)

    input_required = Enum.any?(calculation.arguments, &(!&1.allow_nil?))

    fields_with_input =
      Enum.concat(fields, input)

    required =
      if input_required do
        [:input]
      else
        []
      end

    if fields == [] do
      nil
    else
      %{
        type: :object,
        required: required,
        properties: Map.new(fields_with_input),
        additionalProperties: false
      }
      |> with_attribute_description(calculation)
    end
  end

  def raw_filter_type(attribute_or_aggregate, resource) do
    {type, _constraints} = field_type(attribute_or_aggregate, resource)
    array_type? = match?({:array, _}, type)

    fields =
      Ash.Filter.builtin_operators()
      |> Enum.concat(Ash.Filter.builtin_functions())
      |> Enum.concat(Ash.DataLayer.functions(resource))
      |> Enum.filter(& &1.predicate?())
      |> restrict_for_lists(type)
      |> Enum.flat_map(fn operator ->
        filter_fields(operator, type, array_type?, attribute_or_aggregate, resource)
      end)

    if fields == [] do
      nil
    else
      %{
        type: :object,
        properties: Map.new(fields),
        additionalProperties: false
        # required: required Missing?
      }
      |> with_attribute_description(attribute_or_aggregate)
    end
  end

  defp restrict_for_lists(operators, {:array, _}) do
    list_predicates = [Ash.Query.Operator.IsNil, Ash.Query.Operator.Has]
    Enum.filter(operators, &(&1 in list_predicates))
  end

  defp restrict_for_lists(operators, _), do: operators

  defp filter_fields(
         operator,
         type,
         array_type?,
         attribute_or_aggregate,
         resource
       ) do
    expressable_types = get_expressable_types(operator, type, array_type?)

    if Enum.any?(expressable_types, &(&1 == :same)) do
      [
        {operator.name(), resource_attribute_type(attribute_or_aggregate, resource)}
      ]
    else
      type =
        case Enum.at(expressable_types, 0) do
          [{:array, :any}, :same] ->
            {:unwrap, type}

          [_, {:array, :same}] ->
            {:array, type}

          [_, :same] ->
            type

          [_, :any] ->
            Ash.Type.String

          [_, type] when is_atom(type) ->
            Ash.Type.get_type(type)

          _ ->
            nil
        end

      if type do
        {type, attribute_or_aggregate} =
          case type do
            {:unwrap, type} ->
              {:array, type} = type
              {type, %{attribute_or_aggregate | type: type, constraints: []}}

            type ->
              {type, %{attribute_or_aggregate | type: type, constraints: []}}
          end

        if embedded?(type) do
          []
        else
          attribute_or_aggregate = constraints_to_item_constraints(type, attribute_or_aggregate)

          [
            {operator.name(), resource_attribute_type(attribute_or_aggregate, resource)}
          ]
        end
      else
        []
      end
    end
  end

  defp get_expressable_types(operator_or_function, field_type, array_type?) do
    if :attributes
       |> operator_or_function.__info__()
       |> Keyword.get_values(:behaviour)
       |> List.flatten()
       |> Enum.any?(&(&1 == Ash.Query.Operator)) do
      do_get_expressable_types(operator_or_function.types(), field_type, array_type?)
    else
      do_get_expressable_types(operator_or_function.args(), field_type, array_type?)
    end
  end

  defp do_get_expressable_types(operator_types, field_type, array_type?) do
    field_type_short_name =
      case Ash.Type.short_names()
           |> Enum.find(fn {_, type} -> type == field_type end) do
        nil -> nil
        {short_name, _} -> short_name
      end

    operator_types
    |> Enum.filter(fn
      [:any, {:array, type}] when is_atom(type) ->
        true

      [{:array, inner_type}, :same] when is_atom(inner_type) and array_type? ->
        true

      :same ->
        true

      :any ->
        true

      [:any, type] when is_atom(type) ->
        true

      [^field_type_short_name, type] when is_atom(type) and not is_nil(field_type_short_name) ->
        true

      _ ->
        false
    end)
  end

  defp constraints_to_item_constraints(
         {:array, _},
         %Ash.Resource.Attribute{
           constraints: constraints,
           allow_nil?: allow_nil?
         } = attribute
       ) do
    %{
      attribute
      | constraints: [
          items: constraints,
          nil_items?: allow_nil? || embedded?(attribute.type)
        ]
    }
  end

  defp constraints_to_item_constraints(_, attribute_or_aggregate), do: attribute_or_aggregate

  defp embedded?({:array, resource_or_type}) do
    embedded?(resource_or_type)
  end

  defp embedded?(resource_or_type) do
    if Ash.Resource.Info.resource?(resource_or_type) do
      true
    else
      Ash.Type.embedded_type?(resource_or_type)
    end
  end

  defp only_primary_key?(resource, field) do
    resource
    |> Ash.Resource.Info.primary_key()
    |> case do
      [^field] -> true
      _ -> false
    end
  end

  defp set_aggregate_constraints(aggregates, resource) do
    Enum.map(aggregates, fn %{field: field, relationship_path: relationship_path} = aggregate ->
      field_type_and_constraints =
        with field when not is_nil(field) <- field,
             related when not is_nil(related) <-
               Ash.Resource.Info.related(resource, relationship_path),
             attr when not is_nil(attr) <- Ash.Resource.Info.field(related, field) do
          {attr.type, attr.constraints}
        end

      {field_type, field_constraints} = field_type_and_constraints || {nil, []}

      {:ok, aggregate_type, aggregate_constraints} =
        Ash.Query.Aggregate.kind_to_type(aggregate.kind, field_type, field_constraints)

      Map.merge(aggregate, %{type: aggregate_type, constraints: aggregate_constraints})
    end)
  end
end
