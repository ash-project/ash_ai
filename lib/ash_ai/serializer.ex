# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Serializer do
  @moduledoc false
  @doc false
  def serialize_value(value, type, constraints, domain, opts \\ [])

  def serialize_value(nil, _, _, _, _), do: nil

  def serialize_value(value, {:array, type}, constraints, domain, opts) when is_list(value) do
    Enum.map(value, &serialize_value(&1, type, constraints[:items] || [], domain, opts))
  end

  def serialize_value(value, Ash.Type.Decimal, _constraints, _domain, _opts) do
    Decimal.to_string(value)
  end

  def serialize_value(value, type, constraints, domain, opts) do
    {type, constraints} = flatten_new_type(type, constraints || [])
    opts = [skip_only_primary_key?: false, top_level?: false] |> Keyword.merge(opts)

    with Ash.Type.Struct <- type,
         instance_of when not is_nil(instance_of) <- constraints[:instance_of],
         true <- Ash.Resource.Info.resource?(instance_of) do
      req = %{fields: %{}, route: %{}, domain: domain}
      serialize_attributes(req, value, opts)
    else
      _ ->
        if Ash.Resource.Info.resource?(type) do
          req = %{fields: %{}, route: %{}, domain: domain}
          serialize_attributes(req, value, opts)
        else
          value
        end
    end
  end

  defp flatten_new_type(type, constraints) do
    if Ash.Type.NewType.new_type?(type) do
      new_constraints = Ash.Type.NewType.constraints(type, constraints)
      new_type = Ash.Type.NewType.subtype_of(type)

      {new_type, new_constraints}
    else
      {type, constraints}
    end
  end

  defp serialize_attributes(_, nil, _opts), do: nil

  defp serialize_attributes(request, records, opts) when is_list(records) do
    Enum.map(records, &serialize_attributes(request, &1, opts))
  end

  defp serialize_attributes(request, %resource{} = record, opts) do
    load = Keyword.get(opts, :load, [])

    load_fields =
      load
      |> Enum.map(fn
        {key, _} -> key
        key -> key
      end)

    fields =
      if opts[:top_level?] do
        Map.get(request.fields, resource) || Map.get(request.route, :default_fields) ||
          default_attributes(resource)
      else
        Map.get(request.fields, resource) ||
          default_attributes(resource)
      end
      |> Enum.concat(load_fields)

    Enum.reduce(fields, %{}, fn field_name, acc ->
      field = Ash.Resource.Info.field(resource, field_name)

      {type, constraints} =
        case field do
          %Ash.Resource.Aggregate{} = agg ->
            case field_type_from_aggregate(resource, agg) do
              {field_type, field_constraints} ->
                {:ok, type, constraints} =
                  Ash.Query.Aggregate.kind_to_type(agg.kind, field_type, field_constraints)

                {type, constraints}

              _ ->
                {:ok, type, constraints} =
                  Ash.Query.Aggregate.kind_to_type(agg.kind, nil, nil)

                {type, constraints}
            end

          %relationship{destination: destination}
          when relationship in [
                 Ash.Resource.Relationships.HasMany,
                 Ash.Resource.Relationships.ManyToMany
               ] ->
            {{:array, destination}, []}

          %relationship{destination: destination}
          when relationship in [
                 Ash.Resource.Relationships.HasOne,
                 Ash.Resource.Relationships.BelongsTo
               ] ->
            {destination, []}

          nil ->
            {:string, []}

          attr ->
            {attr.type, attr.constraints}
        end

      cond do
        only_primary_key?(resource, field_name) &&
            Keyword.get(opts, :skip_only_primary_key?, true) ->
          acc

        !field ->
          acc

        match?(%Ash.Resource.Relationships.HasMany{}, field) &&
            match?(%Ash.NotLoaded{}, Map.get(record, field.name)) ->
          acc

        match?(%Ash.Resource.Relationships.HasOne{}, field) &&
            match?(%Ash.NotLoaded{}, Map.get(record, field.name)) ->
          acc

        match?(%Ash.Resource.Relationships.BelongsTo{}, field) &&
            match?(%Ash.NotLoaded{}, Map.get(record, field.name)) ->
          acc

        match?(%Ash.Resource.Relationships.ManyToMany{}, field) &&
            match?(%Ash.NotLoaded{}, Map.get(record, field.name)) ->
          acc

        match?(%Ash.Resource.Calculation{}, field) &&
            match?(%Ash.NotLoaded{}, Map.get(record, field.name)) ->
          acc

        match?(%Ash.Resource.Aggregate{}, field) &&
            match?(%Ash.NotLoaded{}, Map.get(record, field.name)) ->
          acc

        true ->
          new_load =
            load
            |> Enum.find_value([], fn
              {^field_name, value} -> value
              _ -> nil
            end)

          new_opts = opts |> Keyword.put(:load, new_load)

          value =
            serialize_value(
              Map.get(record, field.name),
              type,
              constraints,
              request.domain,
              new_opts
            )

          if not is_nil(value) or include_nil_values?(request, record) do
            Map.put(acc, field.name, value)
          else
            acc
          end
      end
    end)
  end

  defp default_attributes(resource) do
    resource
    |> Ash.Resource.Info.public_attributes()
    |> Enum.map(& &1.name)
  end

  defp field_type_from_aggregate(resource, agg) do
    if agg.field do
      related = Ash.Resource.Info.related(resource, agg.relationship_path)
      field = Ash.Resource.Info.field(related, agg.field)

      if field do
        {field.type, field.constraints}
      end
    end
  end

  defp include_nil_values?(_request, %_resource{} = _record) do
    # Before used AshJsonApi.Resource option,
    # if not set defaulted to AshJsonApi.Domain :include_nil_values? option
    # which defaulted to true, so leaving this false
    false
  end

  defp only_primary_key?(resource, field) do
    resource
    |> Ash.Resource.Info.primary_key()
    |> case do
      [^field] -> true
      _ -> false
    end
  end

  def serialize_errors(errors) do
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
