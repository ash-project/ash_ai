# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Tool.Execution do
  @moduledoc """
  Executes Ash actions from tool call arguments.
  """

  require Ash.Expr

  alias AshAi.Tool.Errors

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
          :read ->
            run_read(resource, action, arguments, input, opts, get_by, exec_ctx)

          :create ->
            run_create(resource, action, input, opts, exec_ctx)

          :update ->
            run_update(resource, action, arguments, input, opts, identity, exec_ctx)

          :destroy ->
            run_destroy(resource, action, arguments, input, opts, identity, exec_ctx)

          :action ->
            run_generic(resource, action, input, opts, exec_ctx)
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

    page_opts = build_page_opts(action.pagination, limit, arguments)

    execute_read(query, action, arguments["result_type"] || "run_query", page_opts, ctx)
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

  # Page options for paginated actions, `nil` otherwise. Keyset pagination is
  # the default whenever the action supports it; a positive `offset` switches
  # to offset pagination when that is supported. Mixing the two, or using a
  # control the action does not support, is a tool error. An `offset` of 0 is
  # the schema default, so it counts as "not requested".
  defp build_page_opts(%Ash.Resource.Actions.Read.Pagination{} = pagination, limit, arguments) do
    cursor =
      Enum.filter([after: arguments["after"], before: arguments["before"]], fn {_key, value} ->
        not is_nil(value)
      end)

    offset = arguments["offset"]
    offset_requested? = not is_nil(offset) and offset != 0

    cond do
      Keyword.has_key?(cursor, :after) and Keyword.has_key?(cursor, :before) ->
        throw({:tool_error, "Pass either `after` or `before`, not both."})

      cursor != [] and offset_requested? ->
        throw(
          {:tool_error,
           "Pass either a keyset cursor (`after`/`before`) or an `offset`, not both."}
        )

      cursor != [] and not pagination.keyset? ->
        throw(
          {:tool_error,
           "This tool does not support keyset pagination; use `offset` instead of `after`/`before`."}
        )

      offset_requested? and not pagination.offset? ->
        throw(
          {:tool_error,
           "This tool does not support offset pagination; use `after`/`before` cursors instead of `offset`."}
        )

      cursor != [] ->
        [limit: limit] ++ cursor

      pagination.offset? and (offset_requested? or not pagination.keyset?) ->
        [limit: limit, offset: offset || 0]

      true ->
        [limit: limit]
    end
  end

  defp build_page_opts(_pagination, _limit, _arguments), do: nil

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

  # Mirrors `Ash.read/2`: a paginated read action returns a page, any other
  # read action returns a bare list of records. The page carries `has_more` and
  # either `next_offset` or `start_keyset`/`end_keyset`, so the LLM knows when
  # and how to fetch further pages, plus a `count` whenever the action's
  # pagination is `countable: :by_default` (the same condition under which Ash
  # counts automatically).
  defp execute_read(query, _action, "run_query", page_opts, ctx) when is_list(page_opts) do
    query
    |> Ash.Query.unset([:limit, :offset])
    |> Ash.Query.page(page_opts)
    |> Ash.read(load: ctx.load, strict?: ctx.load_strict?)
    |> case do
      {:ok, %struct{} = page} when struct in [Ash.Page.Offset, Ash.Page.Keyset] -> page
      {:error, error} -> raise Ash.Error.to_error_class(error)
    end
    |> as_requested_page(page_opts)
    |> then(fn page ->
      page
      |> serialize_page(query.resource, ctx)
      |> encode_result(ctx)
      |> then(&{:ok, &1, page})
    end)
  end

  defp execute_read(query, action, "run_query", _page_opts, ctx) do
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

  defp execute_read(query, _action, "count", _page_opts, ctx) do
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

  defp execute_read(query, _action, "exists", _page_opts, ctx) do
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

  defp execute_read(query, _action, %{"aggregate" => aggregate_kind} = aggregate, _page_opts, ctx) do
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

  defp execute_read(query, action, result_type, page_opts, ctx) do
    query
    |> Ash.Query.add_error(
      Ash.Error.Query.InvalidArgument.exception(
        field: :result_type,
        value: result_type,
        message: ~s(is not supported, use "run_query", "count", "exists", or an aggregate object)
      )
    )
    |> execute_read(action, "run_query", page_opts, ctx)
  end

  # When an action supports both kinds of pagination and no cursor is given, Ash
  # paginates by keyset but wraps the result according to the global
  # `config :ash, :default_page_type` (offset unless configured). The tool asked
  # for keyset, so rebuild the page as one; the records already carry keysets.
  defp as_requested_page(%Ash.Page.Offset{} = page, page_opts) do
    if Keyword.has_key?(page_opts, :offset) do
      page
    else
      %Ash.Page.Keyset{
        results: page.results,
        count: page.count,
        before: nil,
        after: nil,
        limit: page.limit,
        more?: page.more?,
        rerun: page.rerun
      }
    end
  end

  defp as_requested_page(page, _page_opts), do: page

  defp serialize_page(%Ash.Page.Offset{} = page, resource, ctx) do
    offset = page.offset || 0

    %{
      "results" => serialize_results(page.results, resource, ctx),
      "limit" => page.limit,
      "offset" => offset,
      "has_more" => page.more?,
      "next_offset" => if(page.more?, do: offset + page.limit)
    }
    |> put_count(page)
  end

  defp serialize_page(%Ash.Page.Keyset{} = page, resource, ctx) do
    %{
      "results" => serialize_results(page.results, resource, ctx),
      "limit" => page.limit,
      "has_more" => page.more?,
      "start_keyset" => keyset(List.first(page.results)),
      "end_keyset" => keyset(List.last(page.results))
    }
    |> put_count(page)
  end

  defp serialize_results(results, resource, ctx) do
    AshAi.Serializer.serialize_value(
      results,
      {:array, resource},
      [],
      ctx.domain,
      serialize_opts(ctx)
    )
  end

  defp keyset(nil), do: nil
  defp keyset(record), do: record.__metadata__[:keyset]

  # `Ash.Page.*` typespecs declare `count: integer()`, but the field is `nil`
  # unless a count was requested. Reading it via `Map.get/2` keeps dialyzer from
  # treating the nil branch as unreachable.
  defp put_count(serialized, page) do
    case Map.get(page, :count) do
      count when is_integer(count) -> Map.put(serialized, "count", count)
      _ -> serialized
    end
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
