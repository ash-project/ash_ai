# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Tool.Execution do
  @moduledoc """
  Executes Ash actions from tool call arguments.
  """

  require Ash.Expr

  alias AshAi.Tool.Errors

  @grouped_scan_limit 25_000

  defmodule Context do
    @moduledoc """
    Execution context for tool calls.
    """
    defstruct [
      :actor,
      :tenant,
      :context,
      :load,
      :select,
      :domain,
      encode?: true,
      load_strict?: false
    ]
  end

  @doc """
  Executes a tool with the given arguments and context.

  Returns:
  - `{:ok, result, raw_result}` for successful tool calls
  - `{:error, error_text}` for execution failures

  Set `:encode?` to `false` to return the serialized result before JSON encoding.
  """
  def run(
        %AshAi.Tool{
          domain: domain,
          resource: resource,
          action: action,
          load: load,
          load_strict?: load_strict?,
          select: select,
          identity: identity,
          get_by: get_by,
          arguments: tool_arguments
        },
        client_arguments,
        context,
        run_opts \\ []
      ) do
    arguments = client_arguments || %{}
    client_input = arguments["input"] || %{}

    opts = build_opts(domain, context)

    with :ok <- validate_input_shape(client_input) do
      resolved_load =
        case load do
          func when is_function(func, 1) -> func.(client_input)
          list when is_list(list) -> list
          _ -> []
        end

      exec_ctx = %Context{
        actor: context[:actor],
        tenant: context[:tenant],
        context: context[:context] || %{},
        load: resolved_load,
        load_strict?: load_strict?,
        select: select,
        domain: domain,
        encode?: Keyword.get(run_opts, :encode?, true)
      }

      try do
        validate_inputs!(resource, client_input, action, tool_arguments)
        input = Map.take(client_input, valid_action_inputs(resource, action))

        case action.type do
          :read -> run_read(resource, action, arguments, input, opts, get_by, exec_ctx)
          :create -> run_create(resource, action, input, opts, exec_ctx)
          :update -> run_update(resource, action, arguments, input, opts, identity, exec_ctx)
          :destroy -> run_destroy(resource, action, arguments, input, opts, identity, exec_ctx)
          :action -> run_generic(resource, action, input, opts, exec_ctx)
        end
      rescue
        error ->
          {:error, Errors.format(error)}
      catch
        {:tool_error, error_msg} ->
          {:error, error_msg}
      end
    end
  end

  defp build_opts(domain, context) do
    [
      domain: domain,
      actor: context[:actor],
      tenant: context[:tenant],
      context: context[:context] || %{}
    ]
  end

  defp serialize_opts(%Context{select: nil} = ctx), do: [load: ctx.load]
  defp serialize_opts(ctx), do: [load: ctx.load, select: ctx.select]

  defp run_read(
         resource,
         action,
         %{"group_by" => [_ | _] = group_by} = arguments,
         input,
         opts,
         nil,
         ctx
       ) do
    resource
    |> apply_filter(arguments["filter"])
    |> Ash.Query.for_read(action.name, input, opts)
    |> execute_grouped(group_by, arguments["result_type"], ctx)
  end

  defp run_read(resource, action, arguments, input, opts, nil, ctx) do
    sort = build_sort(arguments["sort"])
    limit = build_limit(arguments["limit"], action.pagination)

    query =
      resource
      |> Ash.Query.limit(limit)
      |> Ash.Query.offset(arguments["offset"])
      |> apply_sort(sort)
      |> apply_filter(arguments["filter"])
      |> apply_select(ctx)
      |> Ash.Query.for_read(action.name, input, opts)
      |> reject_oversized_limit(arguments["limit"], action.pagination)

    execute_read(query, action, arguments["result_type"] || "run_query", ctx)
  end

  defp run_read(resource, action, arguments, input, opts, get_by, ctx) do
    resource
    |> apply_select(ctx)
    |> Ash.Query.for_read(action.name, input, opts)
    |> Ash.Query.do_filter(get_by_filter(resource, get_by, arguments))
    |> Ash.read_one!(
      Keyword.merge(opts,
        load: ctx.load,
        strict?: ctx.load_strict?,
        not_found_error?: true
      )
    )
    |> serialize_record(resource, ctx)
  end

  defp build_sort(sort) when is_list(sort) do
    sort
    |> Enum.map_join(",", fn map ->
      case map["direction"] || "asc" do
        "asc" -> map["field"]
        "desc" -> "-#{map["field"]}"
      end
    end)
  end

  defp build_sort(_), do: ""

  defp execute_grouped(query, group_by, result_type, ctx) do
    resource = query.resource
    fields = Enum.map(group_by, &group_field(resource, &1))
    aggregate = group_aggregate(resource, result_type)

    query
    |> select_for_group(fields, aggregate)
    |> Ash.stream!(batch_size: 500, allow_stream_with: :full_read)
    |> Enum.reduce({0, %{}}, &fold_record(&1, &2, fields, aggregate))
    |> elem(1)
    |> Enum.sort_by(fn {key, _tallies} -> key end)
    |> Enum.map(&render_group(&1, fields, aggregate, ctx))
    |> then(fn groups -> {:ok, encode_result(groups, ctx), groups} end)
  end

  defp group_field(resource, name) do
    resource
    |> AshAi.Tool.groupable_fields()
    |> Enum.find(&(to_string(&1.name) == to_string(name)))
    |> case do
      nil -> throw({:tool_error, "group_by: #{name} is not a groupable field of this resource"})
      field -> field
    end
  end

  defp group_aggregate(_resource, result_type) when result_type in [nil, "count"], do: nil

  defp group_aggregate(resource, %{"aggregate" => kind, "field" => name})
       when kind in ["min", "max", "sum", "avg", "count"] do
    field = Ash.Resource.Info.field(resource, name)

    if !field || !field.public? do
      throw({:tool_error, "group_by: no such field #{name}"})
    end

    kind = String.to_existing_atom(kind)

    ensure_foldable(kind, field)

    case Ash.Query.Aggregate.kind_to_type(kind, field.type, field.constraints || []) do
      {:ok, type, constraints} ->
        %{kind: kind, field: field, type: type, constraints: constraints}

      _unsupported ->
        throw(
          {:tool_error,
           "#{kind} is not supported for #{name}, whose type is #{inspect(field.type)}"}
        )
    end
  end

  defp group_aggregate(_resource, result_type) do
    throw(
      {:tool_error,
       "group_by requires result_type to be \"count\" or an aggregate object, got: #{inspect(result_type)}"}
    )
  end

  defp select_for_group(query, fields, aggregate) do
    named = Enum.map(fields, & &1.name) ++ aggregate_field_names(aggregate)

    {attributes, loads} =
      Enum.split_with(named, &Ash.Resource.Info.attribute(query.resource, &1))

    query
    |> Ash.Query.select(Ash.Resource.Info.primary_key(query.resource) ++ attributes)
    |> Ash.Query.load(loads)
  end

  defp aggregate_field_names(nil), do: []
  defp aggregate_field_names(%{field: field}), do: [field.name]

  defp fold_record(_record, {scanned, _groups}, _fields, _aggregate)
       when scanned >= @grouped_scan_limit do
    throw(
      {:tool_error,
       "group_by scanned more than #{@grouped_scan_limit} records. Narrow the filter and try again"}
    )
  end

  defp fold_record(record, {scanned, groups}, fields, aggregate) do
    key = Enum.map(fields, &Map.get(record, &1.name))

    {scanned + 1, Map.update(groups, key, first_tally(record, aggregate), &tally(record, &1, aggregate))}
  end

  defp first_tally(record, aggregate), do: tally(record, {0, initial_state(aggregate)}, aggregate)

  defp tally(_record, {rows, state}, nil), do: {rows + 1, state}

  defp tally(record, {rows, state}, %{kind: kind, field: field}) do
    case Map.get(record, field.name) do
      nil -> {rows + 1, state}
      value -> {rows + 1, fold_value(kind, value, state)}
    end
  end

  defp initial_state(nil), do: nil
  defp initial_state(%{kind: :avg}), do: {0, 0}
  defp initial_state(%{kind: kind}) when kind in [:count, :sum], do: 0
  defp initial_state(%{kind: _min_or_max}), do: nil

  defp fold_value(:count, _value, state), do: state + 1
  defp fold_value(:sum, value, state), do: add_values(state, value)
  defp fold_value(:avg, value, {sum, seen}), do: {add_values(sum, value), seen + 1}
  defp fold_value(:min, value, nil), do: value
  defp fold_value(:max, value, nil), do: value

  defp fold_value(:min, value, state) do
    if compare_values(value, state) == :lt, do: value, else: state
  end

  defp fold_value(:max, value, state) do
    if compare_values(value, state) == :gt, do: value, else: state
  end

  defp compare_values(%DateTime{} = left, %DateTime{} = right), do: DateTime.compare(left, right)
  defp compare_values(%Date{} = left, %Date{} = right), do: Date.compare(left, right)
  defp compare_values(%Decimal{} = left, %Decimal{} = right), do: Decimal.compare(left, right)
  defp compare_values(left, right) when left < right, do: :lt
  defp compare_values(left, right) when left > right, do: :gt
  defp compare_values(_left, _right), do: :eq

  defp ensure_foldable(kind, %{type: type, name: name}) when kind in [:sum, :avg] do
    if type not in [Ash.Type.Integer, Ash.Type.Float, Ash.Type.Decimal] do
      throw(
        {:tool_error, "#{kind} is not supported for #{name}, whose type is #{inspect(type)}"}
      )
    end
  end

  defp ensure_foldable(_kind, _field), do: :ok

  defp add_values(%Decimal{} = left, right), do: Decimal.add(left, Decimal.new(to_string(right)))
  defp add_values(left, %Decimal{} = right), do: Decimal.add(Decimal.new(to_string(left)), right)
  defp add_values(left, right), do: left + right

  defp finish_value(%{kind: :avg}, {_sum, 0}), do: nil
  defp finish_value(%{kind: :avg}, {%Decimal{} = sum, seen}), do: Decimal.div(sum, seen)
  defp finish_value(%{kind: :avg}, {sum, seen}), do: sum / seen
  defp finish_value(_aggregate, state), do: state

  defp render_group({key, {rows, state}}, fields, aggregate, ctx) do
    group =
      fields
      |> Enum.zip(key)
      |> Map.new(fn {field, value} ->
        {field.name,
         AshAi.Serializer.serialize_value(value, field.type, field.constraints, ctx.domain)}
      end)

    add_aggregate(%{group: group, count: rows}, aggregate, state, ctx)
  end

  defp add_aggregate(rendered, nil, _state, _ctx), do: rendered

  defp add_aggregate(rendered, %{type: type, constraints: constraints} = aggregate, state, ctx) do
    value =
      aggregate
      |> finish_value(state)
      |> AshAi.Serializer.serialize_value(type, constraints, ctx.domain)

    Map.put(rendered, :value, value)
  end

  defp reject_oversized_limit(
         query,
         requested,
         %Ash.Resource.Actions.Read.Pagination{max_page_size: max}
       )
       when is_integer(requested) and is_integer(max) and requested > max do
    Ash.Query.add_error(
      query,
      Ash.Error.Query.InvalidArgument.exception(
        field: :limit,
        value: requested,
        message:
          "exceeds the maximum page size of #{max}. Request at most #{max} and page with `offset`"
      )
    )
  end

  defp reject_oversized_limit(query, _requested, _pagination), do: query

  defp build_limit(limit, pagination) do
    case {limit, pagination} do
      {limit, false} when is_integer(limit) ->
        limit

      {limit, %Ash.Resource.Actions.Read.Pagination{default_limit: default, max_page_size: max}} ->
        cond do
          is_integer(limit) and is_integer(max) -> min(limit, max)
          is_nil(limit) and is_integer(default) -> default
          true -> 25
        end

      _ ->
        25
    end
  end

  defp apply_sort(query, ""), do: query
  defp apply_sort(query, sort), do: Ash.Query.sort_input(query, sort)

  defp apply_select(query, %Context{select: nil}), do: query
  defp apply_select(query, %Context{select: select}), do: Ash.Query.select(query, select)

  defp apply_changeset_select(changeset, %Context{select: nil}), do: changeset

  defp apply_changeset_select(changeset, %Context{select: select}),
    do: Ash.Changeset.select(changeset, select, replace?: true)

  defp put_select(opts, %Context{select: nil}), do: opts
  defp put_select(opts, %Context{select: select}), do: Keyword.put(opts, :select, select)

  defp apply_filter(query, nil), do: query
  defp apply_filter(query, []), do: query
  defp apply_filter(query, filter) when is_map(filter) and map_size(filter) == 0, do: query

  defp apply_filter(query, conditions) when is_list(conditions) do
    Enum.reduce(conditions, query, &apply_filter(&2, &1))
  end

  defp apply_filter(query, filter) when is_map(filter) do
    Ash.Query.filter_input(query, normalize_condition(filter))
  end

  defp apply_filter(query, input) do
    Ash.Query.add_error(query, "Invalid filter condition: #{Jason.encode!(input)}")
  end

  defp normalize_condition(%{"field" => field, "operator" => op, "value" => value}),
    do: %{field => %{op => value}}

  defp normalize_condition(%{"and" => conditions}) when is_list(conditions),
    do: %{"and" => Enum.map(conditions, &normalize_condition/1)}

  defp normalize_condition(%{"or" => conditions}) when is_list(conditions),
    do: %{"or" => Enum.map(conditions, &normalize_condition/1)}

  defp normalize_condition(other), do: other

  defp execute_read(query, action, "run_query", ctx) do
    query
    |> Ash.Actions.Read.unpaginated_read(action, load: ctx.load, strict?: ctx.load_strict?)
    |> case do
      {:ok, value} -> value
      {:error, error} -> raise Ash.Error.to_error_class(error)
    end
    |> then(fn result ->
      resource = query.resource

      result
      |> AshAi.Serializer.serialize_value({:array, resource}, [], ctx.domain, serialize_opts(ctx))
      |> encode_result(ctx)
      |> then(&{:ok, &1, result})
    end)
  end

  defp execute_read(query, _action, "count", ctx) do
    query
    |> Ash.Query.unset([:limit, :offset])
    |> Ash.count()
    |> case do
      {:ok, value} -> value
      {:error, error} -> raise Ash.Error.to_error_class(error)
    end
    |> then(fn result ->
      result
      |> AshAi.Serializer.serialize_value(Ash.Type.Integer, [], ctx.domain)
      |> encode_result(ctx)
      |> then(&{:ok, &1, result})
    end)
  end

  defp execute_read(query, _action, "exists", ctx) do
    query
    |> Ash.exists()
    |> case do
      {:ok, value} -> value
      {:error, error} -> raise Ash.Error.to_error_class(error)
    end
    |> then(fn result ->
      result
      |> AshAi.Serializer.serialize_value(Ash.Type.Boolean, [], ctx.domain)
      |> encode_result(ctx)
      |> then(&{:ok, &1, result})
    end)
  end

  defp execute_read(query, _action, %{"aggregate" => aggregate_kind} = aggregate, ctx) do
    resource = query.resource

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

    {:ok, aggregate_type, aggregate_constraints} =
      Ash.Query.Aggregate.kind_to_type(
        aggregate_kind,
        field.type,
        field.constraints || []
      )

    query
    |> Ash.Query.unset([:limit, :offset])
    |> Ash.aggregate({:aggregate_result, aggregate_kind, field: field.name},
      authorize_fields?: true
    )
    |> case do
      {:ok, %{aggregate_result: value}} -> value
      {:error, error} -> raise Ash.Error.to_error_class(error)
    end
    |> then(fn result ->
      result
      |> AshAi.Serializer.serialize_value(
        aggregate_type,
        aggregate_constraints,
        ctx.domain
      )
      |> encode_result(ctx)
      |> then(&{:ok, &1, result})
    end)
  end

  defp execute_read(query, action, result_type, ctx) do
    query
    |> Ash.Query.add_error(
      Ash.Error.Query.InvalidArgument.exception(
        field: :result_type,
        value: result_type,
        message: ~s(is not supported, use "run_query", "count", "exists", or an aggregate object)
      )
    )
    |> execute_read(action, "run_query", ctx)
  end

  defp run_create(resource, action, input, opts, ctx) do
    resource
    |> Ash.Changeset.for_create(action.name, input, opts)
    |> apply_changeset_select(ctx)
    |> Ash.create!(load: ctx.load)
    |> serialize_record(resource, ctx)
  end

  defp run_update(resource, action, arguments, input, opts, identity, ctx) do
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
        load: ctx.load,
        allow_stream_with: :full_read,
        return_records?: true
      )
      |> put_select(ctx)
    )
    |> case do
      %Ash.BulkResult{status: :success, records: [result]} ->
        serialize_record(result, resource, ctx)

      %Ash.BulkResult{status: :success, records: []} ->
        raise Ash.Error.to_error_class(Ash.Error.Query.NotFound.exception(primary_key: filter))
    end
  end

  defp run_destroy(resource, action, arguments, input, opts, identity, ctx) do
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
        load: ctx.load,
        strategy: [:atomic, :stream, :atomic_batches],
        allow_stream_with: :full_read,
        return_records?: true
      )
      |> put_select(ctx)
    )
    |> case do
      %Ash.BulkResult{status: :success, records: [result]} ->
        serialize_record(result, resource, ctx)

      %Ash.BulkResult{status: :success, records: []} ->
        raise Ash.Error.to_error_class(Ash.Error.Query.NotFound.exception(primary_key: filter))
    end
  end

  defp serialize_record(result, resource, ctx) do
    result
    |> AshAi.Serializer.serialize_value(resource, [], ctx.domain, serialize_opts(ctx))
    |> encode_result(ctx)
    |> then(&{:ok, &1, result})
  end

  defp run_generic(resource, action, input, opts, ctx) do
    resource
    |> Ash.ActionInput.for_action(action.name, input, opts)
    |> Ash.run_action!()
    |> then(fn result ->
      if action.returns do
        result
        |> AshAi.Serializer.serialize_value(
          action.returns,
          action.constraints,
          ctx.domain,
          load: ctx.load
        )
        |> encode_result(ctx)
      else
        "success"
      end
      |> then(&{:ok, &1, result})
    end)
  end

  defp encode_result(result, %Context{encode?: true}), do: Jason.encode!(result)
  defp encode_result(result, %Context{encode?: false}), do: result

  defp identity_filter(false, _resource, _arguments), do: nil

  defp identity_filter(nil, resource, arguments) do
    resource
    |> AshAi.Tool.identity_keys(nil)
    |> Enum.reduce(nil, fn key, expr ->
      value = identity_value(resource, key, arguments)

      if expr do
        Ash.Expr.expr(^expr and ^Ash.Expr.ref(key) == ^value)
      else
        Ash.Expr.expr(^Ash.Expr.ref(key) == ^value)
      end
    end)
  end

  defp identity_filter(identity, resource, arguments) do
    resource
    |> AshAi.Tool.identity_keys(identity)
    |> Enum.map(fn key ->
      {key, identity_value(resource, key, arguments)}
    end)
  end

  defp identity_value(resource, key, arguments) do
    arguments
    |> Map.get(to_string(key))
    |> then(&cast_lookup_value!(resource, key, &1, "identity"))
  end

  defp get_by_filter(resource, get_by, arguments) do
    get_by
    |> List.wrap()
    |> Map.new(fn field_name ->
      case Map.get(arguments, to_string(field_name)) do
        nil -> throw({:tool_error, "Missing required get_by argument: #{field_name}"})
        value -> {field_name, cast_lookup_value!(resource, field_name, value, "get_by")}
      end
    end)
  end

  # Values arrive as JSON primitives, so they are cast to the field's type before
  # filtering. Mirrors what `Ash.CodeInterface` does for `get_by` code interfaces.
  # A missing argument stays `nil` here, so the caller decides how to handle it.
  defp cast_lookup_value!(_resource, _field_name, nil, _label), do: nil

  defp cast_lookup_value!(resource, field_name, value, label) do
    {type, constraints} = lookup_field_type(resource, field_name)

    with {:ok, casted} <- Ash.Type.cast_input(type, value, constraints),
         {:ok, casted} <- Ash.Type.apply_constraints(type, casted, constraints) do
      casted
    else
      _ ->
        throw(
          {:tool_error,
           "Invalid value for #{label} argument #{field_name}: #{truncate(Jason.encode!(value))}"}
        )
    end
  end

  defp lookup_field_type(resource, field_name) do
    case Ash.Resource.Info.field(resource, field_name) do
      %Ash.Resource.Aggregate{} = aggregate ->
        {:ok, type, constraints} = Ash.Query.Aggregate.aggregate_type(resource, aggregate)
        {type, constraints}

      %{type: type} = field ->
        {type, Map.get(field, :constraints) || []}
    end
  end

  defp validate_input_shape(client_input) when is_map(client_input), do: :ok

  defp validate_input_shape(client_input) do
    {:error,
     "`input` must be a JSON object, got #{truncate(Jason.encode!(client_input))}. " <>
       "Pass the arguments themselves, not a JSON-encoded string of them."}
  end

  defp validate_inputs!(resource, client_input, action, tool_arguments) do
    allowed_keys =
      MapSet.new(
        valid_action_inputs(resource, action) ++ Enum.map(tool_arguments, &to_string(&1.name))
      )

    unknown_keys = MapSet.difference(MapSet.new(Map.keys(client_input)), allowed_keys)

    if MapSet.size(unknown_keys) > 0 do
      error_msg =
        "Unknown arguments provided: #{Enum.join(unknown_keys, ", ")}. Valid arguments are: #{Enum.join(allowed_keys, ", ")}"

      throw({:tool_error, error_msg})
    else
      :ok
    end
  end

  defp truncate(encoded) do
    if String.length(encoded) > 120, do: String.slice(encoded, 0, 120) <> "...", else: encoded
  end

  defp valid_action_inputs(resource, action) do
    resource
    |> Ash.Resource.Info.action_inputs(action.name)
    |> Enum.map(&to_string/1)
  end
end
