# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Tool.OutputSchema do
  @moduledoc """
  Builds the MCP `outputSchema` for tools that set `output_schema?: true`.

  The schema describes what `AshAi.Serializer` emits as the tool's structured
  content, and is never stricter than it, because clients reject results that
  don't conform. Keys are required only when the serializer always emits them,
  values are nullable as their types declare, extra keys are allowed, and
  values the serializer passes through unchanged (unions, unknown types) accept
  anything. Ash doesn't apply a generic action's return constraints, so the
  declared types are taken as the action's contract.
  """

  @doc """
  The output schema for a tool, or `nil` when the tool doesn't set `output_schema?`.
  """
  def for_tool(%AshAi.Tool{output_schema?: false}), do: nil

  def for_tool(%AshAi.Tool{} = tool) do
    with {:error, message} <- validate(tool, tool.action) do
      raise ArgumentError, "Tool #{inspect(tool.name)}: #{message}"
    end

    case tool.action do
      %{type: :action, returns: returns, constraints: constraints} ->
        value_schema(returns, constraints || [], tool.load || [], [])

      _ ->
        record_schema(tool.resource, tool.select, tool.load || [])
    end
  end

  @doc false
  # Run at compile time when the tool's action is available, and again when the schema is built
  def validate(%{load: load}, _action) when is_function(load) do
    {:error,
     "`output_schema?` requires a static `load` list, since the schema can't depend on the input"}
  end

  def validate(_tool, %{type: :action, returns: nil}) do
    {:error, "`output_schema?` requires the action to return a value"}
  end

  def validate(_tool, %{type: :action, allow_nil?: true}) do
    {:error,
     "`output_schema?` requires the action to set `allow_nil? false`, since a nil result carries no structured content"}
  end

  def validate(_tool, %{type: :action, returns: returns, constraints: constraints}) do
    if object_type?(returns, constraints || []) do
      :ok
    else
      {:error,
       "`output_schema?` requires the action to return an object (a map, struct, typed struct or resource), not #{inspect(returns)}"}
    end
  end

  def validate(%{get_by: nil}, %{type: :read}) do
    {:error,
     "`output_schema?` on read tools requires `get_by`, since other reads return a list or a page"}
  end

  def validate(_tool, _action), do: :ok

  # Shallow, so it can run while the tool's resource is still compiling
  defp object_type?({:array, _type}, _constraints), do: false

  defp object_type?(type, constraints) do
    type = Ash.Type.get_type(type)

    cond do
      Ash.Type.NewType.new_type?(type) ->
        object_type?(
          Ash.Type.NewType.subtype_of(type),
          Ash.Type.NewType.constraints(type, constraints)
        )

      type == Ash.Type.Map ->
        true

      type == Ash.Type.Struct ->
        not is_nil(constraints[:instance_of]) or constraints[:fields] not in [nil, []]

      type in [Ash.Type.Keyword, Ash.Type.Tuple] ->
        constraints[:fields] not in [nil, []]

      true ->
        resource?(type)
    end
  end

  defp value_schema({:array, type}, constraints, load, seen) do
    items = value_schema(type, constraints[:items] || [], load, seen)

    %{
      "type" => "array",
      "items" => if(constraints[:nil_items?], do: nullable(items), else: items)
    }
  end

  defp value_schema(type, constraints, load, seen) do
    type = Ash.Type.get_type(type)

    if Ash.Type.NewType.new_type?(type) do
      case Ash.Type.NewType.subtype_of(type) do
        # The serializer passes a NewType over an array through without serializing its items
        {:array, _type} ->
          %{"type" => "array"}

        subtype ->
          value_schema(subtype, Ash.Type.NewType.constraints(type, constraints), load, seen)
      end
    else
      typed_schema(type, constraints, load, seen)
    end
  end

  defp typed_schema(Ash.Type.Struct, constraints, load, seen) do
    instance_of = constraints[:instance_of]

    cond do
      instance_of && resource?(instance_of) ->
        embedded_schema(instance_of, load, seen)

      constraints[:fields] not in [nil, []] ->
        fields_schema(constraints[:fields], true, load, seen)

      true ->
        %{"type" => "object"}
    end
  end

  defp typed_schema(Ash.Type.Map, constraints, load, seen) do
    case constraints[:fields] do
      fields when fields not in [nil, []] -> fields_schema(fields, false, load, seen)
      _ -> %{"type" => "object"}
    end
  end

  # Keyword lists only carry the keys they were given; tuples are positional, so
  # every field is present
  defp typed_schema(type, constraints, load, seen)
       when type in [Ash.Type.Keyword, Ash.Type.Tuple] do
    case constraints[:fields] do
      fields when fields not in [nil, []] ->
        fields_schema(fields, type == Ash.Type.Tuple, load, seen)

      _ ->
        %{}
    end
  end

  defp typed_schema(Ash.Type.Union, _constraints, _load, _seen), do: %{}

  defp typed_schema(Ash.Type.Integer, _constraints, _load, _seen), do: %{"type" => "integer"}
  defp typed_schema(Ash.Type.Float, _constraints, _load, _seen), do: %{"type" => "number"}
  defp typed_schema(Ash.Type.Boolean, _constraints, _load, _seen), do: %{"type" => "boolean"}

  defp typed_schema(type, _constraints, _load, _seen)
       when type in [
              Ash.Type.String,
              Ash.Type.CiString,
              Ash.Type.Atom,
              Ash.Type.Decimal,
              Ash.Type.UUID,
              Ash.Type.UUIDv7,
              Ash.Type.Date,
              Ash.Type.DateTime,
              Ash.Type.NaiveDatetime,
              Ash.Type.Time,
              Ash.Type.TimeUsec,
              Ash.Type.Duration,
              Ash.Type.DurationName
            ],
       do: %{"type" => "string"}

  defp typed_schema(type, _constraints, load, seen) do
    cond do
      resource?(type) ->
        embedded_schema(type, load, seen)

      Spark.implements_behaviour?(type, Ash.Type.Enum) ->
        %{
          "type" => "string",
          "description" => "One of: #{Enum.map_join(type.values(), ", ", &to_string/1)}"
        }

      true ->
        %{}
    end
  end

  # Resources used as types can contain themselves, so a repeat stops at a bare object
  defp embedded_schema(resource, load, seen) do
    if resource in seen do
      %{"type" => "object"}
    else
      record_schema(resource, nil, load, [resource | seen])
    end
  end

  defp fields_schema(fields, all_present?, load, seen) do
    properties =
      Map.new(fields, fn {name, config} ->
        schema =
          config[:type]
          |> value_schema(config[:constraints] || [], load, seen)
          |> then(&if(Keyword.get(config, :allow_nil?, true), do: nullable(&1), else: &1))
          |> put_description(config[:description])

        {to_string(name), schema}
      end)

    schema = %{"type" => "object", "properties" => properties}

    if all_present? do
      Map.put(schema, "required", Enum.map(fields, &to_string(elem(&1, 0))))
    else
      schema
    end
  end

  # Mirrors `AshAi.Serializer`'s record serialization: the selected (or public)
  # attributes plus the loaded fields, with nil values left out, so no key is
  # required and no value is null
  defp record_schema(resource, select, load, seen \\ []) do
    load = List.wrap(load)

    properties =
      (select || default_attributes(resource))
      |> Enum.concat(Enum.map(load, &load_name/1))
      |> Enum.uniq()
      |> Enum.flat_map(fn name ->
        case Ash.Resource.Info.field(resource, name) do
          nil ->
            []

          field ->
            schema =
              resource
              |> field_schema(field, nested_load(load, name), seen)
              |> put_description(Map.get(field, :description))

            [{to_string(name), schema}]
        end
      end)
      |> Map.new()

    %{"type" => "object", "properties" => properties}
  end

  defp field_schema(_resource, %{cardinality: :many, destination: destination}, load, _seen),
    do: %{"type" => "array", "items" => record_schema(destination, nil, load)}

  defp field_schema(_resource, %{cardinality: :one, destination: destination}, load, _seen),
    do: record_schema(destination, nil, load)

  defp field_schema(resource, %Ash.Resource.Aggregate{} = aggregate, _load, seen) do
    {field_type, field_constraints} =
      with field_name when not is_nil(field_name) <- aggregate.field,
           related when not is_nil(related) <-
             Ash.Resource.Info.related(resource, aggregate.relationship_path),
           %{type: type, constraints: constraints} <- Ash.Resource.Info.field(related, field_name) do
        {type, constraints}
      else
        _ -> {nil, nil}
      end

    case Ash.Query.Aggregate.kind_to_type(aggregate.kind, field_type, field_constraints) do
      {:ok, type, constraints} -> value_schema(type, constraints, [], seen)
      _ -> %{}
    end
  end

  defp field_schema(_resource, field, load, seen),
    do: value_schema(field.type, field.constraints || [], load, seen)

  defp nested_load(load, name) do
    Enum.find_value(load, [], fn
      {^name, nested} when is_list(nested) -> nested
      _ -> nil
    end)
  end

  defp load_name({name, _nested}), do: name
  defp load_name(name), do: name

  defp default_attributes(resource) do
    resource
    |> Ash.Resource.Info.public_attributes()
    |> Enum.map(& &1.name)
  end

  defp nullable(schema) when schema == %{}, do: schema

  defp nullable(%{"type" => type} = schema) when is_binary(type),
    do: %{schema | "type" => [type, "null"]}

  defp nullable(schema), do: %{"anyOf" => [schema, %{"type" => "null"}]}

  defp put_description(schema, description) when is_binary(description),
    do: Map.put(schema, "description", description)

  defp put_description(schema, _description), do: schema

  defp resource?(module) do
    is_atom(module) and Code.ensure_loaded?(module) and Ash.Resource.Info.resource?(module)
  end
end
