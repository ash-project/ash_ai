# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.ToolLoop do
  @moduledoc """
  Manages a ReqLLM conversation loop with tool calls.

  This module is the primary orchestration API for tool-enabled conversations.
  """

  alias ReqLLM.Context
  alias ReqLLM.Message.ContentPart

  defmodule IterationEvent do
    @moduledoc """
    Event emitted at the start of each iteration in the tool loop.
    """
    defstruct [:iteration, :messages_count, :tool_calls_count]
  end

  defmodule Result do
    @moduledoc """
    Result returned from a completed tool loop.

    `:usage` is the token-usage totals summed across every `stream_text/3`
    call made during the loop (one per iteration). Keys mirror what the
    underlying ReqLLM provider reports — typically `:input_tokens`,
    `:output_tokens`, and any cost/cache fields. Numeric fields are summed;
    non-numeric fields fall through to the most recent value. Empty `%{}`
    when no provider reported usage.
    """
    defstruct [:messages, :final_text, :iterations, :tool_calls_made, usage: %{}]
  end

  @doc """
  Runs the tool loop synchronously.
  """
  def run(messages, opts) do
    opts = AshAi.Options.validate!(opts)
    {tools, registry} = AshAi.Tools.build_tools_and_registry(opts)
    context = build_context(opts)
    model = resolve_model(opts.model, opts)

    run_loop(
      opts.req_llm,
      model,
      messages,
      tools,
      registry,
      opts.req_llm_opts,
      context,
      1,
      opts.max_iterations,
      [],
      %{}
    )
  end

  @doc """
  Streams events from the tool loop.

  Events:
  - `{:content, text}`
  - `{:tool_call, %{id: id, name: name, arguments: args}}`
  - `{:tool_result, %{id: id, result: result}}`
  - `{:iteration, %IterationEvent{}}`
  - `{:error, reason}`
  - `{:done, %Result{}}`
  """
  def stream(messages, opts) do
    Stream.resource(
      fn -> init_stream(messages, opts) end,
      &next_stream_chunk/1,
      &cleanup_stream/1
    )
  end

  defp init_stream(messages, opts) do
    opts = AshAi.Options.validate!(opts)
    {tools, registry} = AshAi.Tools.build_tools_and_registry(opts)
    context = build_context(opts)
    model = resolve_model(opts.model, opts)

    %{
      req_llm: opts.req_llm,
      model: model,
      messages: messages,
      tools: tools,
      registry: registry,
      req_llm_opts: opts.req_llm_opts,
      context: context,
      iteration: 1,
      max_iterations: opts.max_iterations,
      tool_calls_made: [],
      usage_acc: %{},
      state: :running
    }
  end

  defp next_stream_chunk(%{state: :done} = state), do: {:halt, state}

  # Mid-iteration: tool calls have already been announced. Run tools one at a
  # time, yielding a `:tool_result` event after each so the UI can render
  # tool-call rows as in-flight before their results land.
  defp next_stream_chunk(%{state: {:running_tools, [tc | rest], iteration}} = state) do
    {result, content} = run_single_tool(tc, state.registry, state.context)

    new_messages = state.messages ++ [Context.tool_result(tc.id, content)]
    result_event = {:tool_result, %{id: tc.id, result: result}}

    if rest == [] do
      iter_event = {:iteration, %IterationEvent{iteration: iteration + 1}}

      new_state = %{
        state
        | messages: new_messages,
          iteration: iteration + 1,
          state: :running
      }

      {[result_event, iter_event], new_state}
    else
      new_state = %{
        state
        | messages: new_messages,
          state: {:running_tools, rest, iteration}
      }

      {[result_event], new_state}
    end
  end

  # Mid-LLM-stream: pull one chunk at a time from the underlying ReqLLM
  # stream. Yield `:content` events as text deltas arrive so the consumer
  # (and the UI) sees text appear in real time. When the stream finishes,
  # transition either to `:running_tools` or to `:done`.
  defp next_stream_chunk(%{state: {:streaming_llm, cont, accum}} = state) do
    case advance_llm_stream(cont) do
      {:next, chunk, new_cont} ->
        {events, new_accum} = process_llm_chunk(chunk, accum)
        {events, %{state | state: {:streaming_llm, new_cont, new_accum}}}

      :exhausted ->
        finalize_llm_stream(state, accum)
    end
  end

  defp next_stream_chunk(%{state: :running} = state) do
    %{
      req_llm: req_llm,
      model: model,
      messages: messages,
      tools: tools,
      req_llm_opts: req_llm_opts,
      iteration: iteration,
      max_iterations: max_iterations,
      tool_calls_made: tool_calls_made
    } = state

    cond do
      max_iterations_reached?(iteration, max_iterations) ->
        result = %Result{
          messages: messages,
          final_text: "",
          iterations: iteration - 1,
          tool_calls_made: tool_calls_made,
          usage: state.usage_acc
        }

        {[{:error, :max_iterations_reached}, {:done, result}], %{state | state: :done}}

      true ->
        case req_llm.stream_text(model, messages, req_llm_stream_opts(req_llm_opts, tools)) do
          {:ok, stream_response} ->
            cont = start_llm_stream(stream_response.stream)

            new_state = %{
              state
              | state: {:streaming_llm, cont, fresh_llm_accum(stream_response)}
            }

            {[], new_state}

          {:error, reason} ->
            result = %Result{
              messages: messages,
              final_text: "",
              iterations: iteration - 1,
              tool_calls_made: tool_calls_made,
              usage: state.usage_acc
            }

            {[{:error, reason}, {:done, result}], %{state | state: :done}}
        end
    end
  end

  defp cleanup_stream(%{state: {:streaming_llm, {:suspended, _, cont}, _}}) do
    _ = cont.({:halt, nil})
    :ok
  end

  defp cleanup_stream(_state), do: :ok

  # Returns either {:next, chunk, new_state} or :exhausted. `state` is the
  # tuple returned by Enumerable.reduce on each step.
  defp advance_llm_stream({:suspended, chunk, cont}) do
    {:next, chunk, cont.({:cont, nil})}
  end

  defp advance_llm_stream({:done, _}), do: :exhausted
  defp advance_llm_stream({:halted, _}), do: :exhausted

  # Produces the initial Enumerable.reduce return value. We use `:suspend` to
  # pause after every element, so each subsequent `cont.({:cont, nil})` yields
  # the next element of the underlying lazy stream.
  defp start_llm_stream(stream) do
    Enumerable.reduce(stream, {:cont, nil}, fn elem, _ -> {:suspend, elem} end)
  end

  defp fresh_llm_accum(stream_response) do
    %{
      stream_response: stream_response,
      text_chunks: [],
      thinking_chunks: [],
      tool_call_starts: [],
      arg_fragments: %{},
      finish_reason: nil,
      chunk_tool_call_ids: [],
      usage: nil
    }
  end

  # Single-chunk processing. Returns {events, updated_accum}.
  defp process_llm_chunk(chunk, accum) do
    case chunk.type do
      :content ->
        text = chunk.text || ""
        events = if text == "", do: [], else: [{:content, text}]
        {events, %{accum | text_chunks: [text | accum.text_chunks]}}

      :thinking ->
        text = chunk.text || ""
        {[], %{accum | thinking_chunks: [text | accum.thinking_chunks]}}

      :tool_call ->
        metadata = chunk.metadata || %{}
        id = metadata_field(metadata, :id) || metadata_field(metadata, :call_id)
        index = metadata_field(metadata, :index) || 0

        partial = %{
          id: id,
          name: chunk.name,
          arguments: chunk.arguments || %{},
          index: index
        }

        accum = %{
          accum
          | tool_call_starts: [partial | accum.tool_call_starts],
            chunk_tool_call_ids: accum.chunk_tool_call_ids ++ [id]
        }

        {[], accum}

      :meta ->
        meta = chunk.metadata || %{}
        accum = handle_meta(meta, accum)
        {[], accum}

      _ ->
        {[], accum}
    end
  end

  defp handle_meta(%{tool_call_args: %{index: index, fragment: fragment}}, accum) do
    existing = Map.get(accum.arg_fragments, index, "")
    %{accum | arg_fragments: Map.put(accum.arg_fragments, index, existing <> fragment)}
  end

  defp handle_meta(%{finish_reason: reason}, accum) when not is_nil(reason) do
    %{accum | finish_reason: reason}
  end

  defp handle_meta(%{usage: usage}, accum) when is_map(usage) do
    merged = merge_usage(accum.usage, usage)
    %{accum | usage: merged}
  end

  defp handle_meta(_meta, accum), do: accum

  defp merge_usage(nil, b), do: b

  defp merge_usage(a, b) do
    Map.merge(a, b, fn _k, va, vb ->
      cond do
        is_number(va) and is_number(vb) -> max(va, vb)
        true -> vb
      end
    end)
  end

  # Stream is finished: build classification, emit assistant_message and
  # tool_calls, transition to next phase.
  defp finalize_llm_stream(state, accum) do
    %{
      messages: messages,
      iteration: iteration,
      tool_calls_made: tool_calls_made,
      usage_acc: usage_acc,
      model: model
    } = state

    classification = classify_accum(accum)

    usage_acc =
      usage_acc
      |> accumulate_usage(accum.usage)
      |> accumulate_usage(safe_stream_usage(accum.stream_response))

    usage_events =
      case accum.usage do
        nil -> []
        usage -> [{:usage, usage}]
      end

    if classification.type == :tool_calls do
      tool_calls =
        classification.tool_calls
        |> normalize_tool_calls(accum.chunk_tool_call_ids)
        |> unprocessed_tool_calls(messages)

      new_messages =
        append_tool_call_turn(
          messages,
          classification.text,
          classification.thinking,
          tool_calls
        )

      assistant_events =
        if classification.text && classification.text != "",
          do: [{:assistant_message, classification.text}],
          else: []

      tool_call_events = Enum.map(tool_calls, &{:tool_call, &1})

      events = usage_events ++ assistant_events ++ tool_call_events

      new_state = %{
        state
        | messages: new_messages,
          tool_calls_made: tool_calls_made ++ tool_calls,
          usage_acc: usage_acc,
          state: {:running_tools, tool_calls, iteration}
      }

      {events, new_state}
    else
      new_messages =
        maybe_append_assistant_message(
          messages,
          classification.text,
          classification.thinking,
          model
        )

      result = %Result{
        messages: new_messages,
        final_text: classification.text,
        iterations: iteration,
        tool_calls_made: tool_calls_made,
        usage: usage_acc
      }

      assistant_events =
        if classification.text && classification.text != "",
          do: [{:assistant_message, classification.text}],
          else: []

      {usage_events ++ assistant_events ++ [{:done, result}],
       %{state | usage_acc: usage_acc, state: :done}}
    end
  end

  # Sums per-iteration usage maps into a running accumulator. Numeric
  # fields (input_tokens, output_tokens, cached_tokens, *_cost, ...) are
  # summed so the final `Result.usage` reflects everything billed across
  # the entire tool loop. Non-numeric fields fall through to the most
  # recent iteration's value.
  defp accumulate_usage(acc, nil), do: acc
  defp accumulate_usage(acc, usage) when usage == %{}, do: acc

  defp accumulate_usage(acc, usage) when is_map(usage) do
    Map.merge(acc, usage, fn
      _key, a, b when is_number(a) and is_number(b) -> a + b
      _key, _a, b -> b
    end)
  end

  defp classify_accum(accum) do
    text =
      accum.text_chunks
      |> Enum.reverse()
      |> Enum.join()

    thinking =
      accum.thinking_chunks
      |> Enum.reverse()
      |> Enum.join()

    tool_calls = reconstruct_tool_calls(accum)
    finish_reason = normalize_finish_reason(accum.finish_reason)

    type =
      cond do
        tool_calls != [] -> :tool_calls
        finish_reason == :tool_calls -> :tool_calls
        true -> :final_answer
      end

    %{type: type, text: text, thinking: thinking, tool_calls: tool_calls, finish_reason: finish_reason}
  end

  defp reconstruct_tool_calls(%{tool_call_starts: []}), do: []

  defp reconstruct_tool_calls(accum) do
    accum.tool_call_starts
    |> Enum.reverse()
    |> Enum.map(fn partial ->
      case Map.get(accum.arg_fragments, partial.index) do
        nil ->
          partial |> Map.delete(:index)

        json_str ->
          case Jason.decode(json_str) do
            {:ok, args} ->
              partial |> Map.put(:arguments, args) |> Map.delete(:index)

            {:error, _} ->
              partial |> Map.delete(:index)
          end
      end
    end)
  end

  defp normalize_finish_reason(nil), do: nil
  defp normalize_finish_reason(reason) when is_atom(reason), do: reason
  defp normalize_finish_reason("stop"), do: :stop
  defp normalize_finish_reason("end_turn"), do: :stop
  defp normalize_finish_reason("tool_calls"), do: :tool_calls
  defp normalize_finish_reason("tool_use"), do: :tool_calls
  defp normalize_finish_reason("length"), do: :length
  defp normalize_finish_reason("max_tokens"), do: :length
  defp normalize_finish_reason(_), do: :unknown

  defp build_context(opts) do
    %{
      actor: opts.actor,
      tenant: opts.tenant,
      context: opts.context,
      tool_callbacks: %{
        on_tool_start: opts.on_tool_start,
        on_tool_end: opts.on_tool_end
      }
    }
  end

  defp req_llm_stream_opts(req_llm_opts, tools) do
    req_llm_opts
    |> Keyword.drop([:tools])
    |> Keyword.put(:tools, tools)
  end

  defp resolve_model(model, opts) when is_function(model, 1),
    do: resolve_model(model.(opts), opts)

  defp resolve_model(model, _opts) when is_function(model, 0), do: model.()
  defp resolve_model(model, _opts), do: ReqLLM.model!(model)

  defp run_loop(
         req_llm,
         model,
         messages,
         tools,
         registry,
         req_llm_opts,
         context,
         iteration,
         max_iterations,
         tool_calls_made,
         usage_acc
       ) do
    if max_iterations_reached?(iteration, max_iterations) do
      {:error, :max_iterations_reached}
    else
      case req_llm.stream_text(model, messages, req_llm_stream_opts(req_llm_opts, tools)) do
        {:ok, stream_response} ->
          chunks = Enum.to_list(stream_response.stream)

          chunk_tool_call_ids =
            chunks
            |> Enum.filter(&(&1.type == :tool_call))
            |> Enum.map(fn chunk ->
              metadata = chunk.metadata || %{}
              metadata_field(metadata, :id) || metadata_field(metadata, :call_id)
            end)

          usage_acc =
            usage_acc
            |> accumulate_usage(usage_from_chunks(chunks))
            |> accumulate_usage(safe_stream_usage(stream_response))

          classification =
            stream_response
            |> Map.put(:stream, chunks)
            |> ReqLLM.StreamResponse.classify()

          if classification.type == :tool_calls do
            tool_calls =
              classification.tool_calls
              |> normalize_tool_calls(chunk_tool_call_ids)
              |> unprocessed_tool_calls(messages)

            messages =
              append_tool_call_turn(
                messages,
                classification.text,
                classification.thinking,
                tool_calls
              )

            messages = run_tools(tool_calls, messages, registry, context)

            run_loop(
              req_llm,
              model,
              messages,
              tools,
              registry,
              req_llm_opts,
              context,
              iteration + 1,
              max_iterations,
              tool_calls_made ++ tool_calls,
              usage_acc
            )
          else
            messages =
              maybe_append_assistant_message(
                messages,
                classification.text,
                classification.thinking,
                model
              )

            {:ok,
             %Result{
               messages: messages,
               final_text: classification.text,
               iterations: iteration,
               tool_calls_made: tool_calls_made,
               usage: usage_acc
             }}
          end

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  defp usage_from_chunks(chunks) do
    chunks
    |> Enum.filter(&(&1.type == :meta))
    |> Enum.reduce(nil, fn chunk, acc ->
      meta = chunk.metadata || %{}

      case Map.get(meta, :usage) || Map.get(meta, "usage") do
        nil -> acc
        usage when is_map(usage) -> merge_usage(acc, usage)
        _ -> acc
      end
    end)
  end

  # Some providers expose final usage via `stream_response.metadata_handle`
  # (a pid resolved by `ReqLLM.StreamResponse.usage/1`) rather than meta
  # chunks. Test fixtures may stub the field with non-pid values, so guard.
  defp safe_stream_usage(%{metadata_handle: handle} = stream_response) when is_pid(handle) do
    ReqLLM.StreamResponse.usage(stream_response)
  end

  defp safe_stream_usage(_), do: nil

  defp run_tools(tool_calls, messages, registry, ctx) do
    Enum.reduce(tool_calls, messages, fn tool_call, msgs ->
      {_, content} = run_single_tool(tool_call, registry, ctx)
      msgs ++ [Context.tool_result(tool_call.id, content)]
    end)
  end

  defp run_single_tool(tool_call, registry, ctx) do
    fun = Map.get(registry, tool_call.name)

    if is_nil(fun) do
      content = Jason.encode!(%{error: "Unknown tool: #{tool_call.name}"})
      {{:error, content}, content}
    else
      result =
        case decode_tool_call_arguments(tool_call.arguments) do
          {:ok, args} ->
            try do
              fun.(args, ctx)
            rescue
              e ->
                {:error, Jason.encode!(%{error: Exception.message(e)})}
            end

          {:error, reason} ->
            {:error, Jason.encode!(%{error: reason})}
        end

      content =
        case result do
          {:ok, content, _raw} -> content
          {:error, content} -> content
        end

      {result, content}
    end
  end

  defp decode_tool_call_arguments(s) when is_binary(s) do
    case Jason.decode(s) do
      {:ok, m} when is_map(m) ->
        {:ok, m}

      {:ok, other} ->
        {:error, "Invalid tool arguments JSON type: #{inspect(other)}"}

      {:error, error} ->
        {:error, "Invalid tool arguments JSON: #{Exception.message(error)}"}
    end
  end

  defp decode_tool_call_arguments(m) when is_map(m), do: {:ok, m}
  defp decode_tool_call_arguments(_), do: {:ok, %{}}

  defp maybe_append_assistant_message(messages, _text, _thinking, %{provider: :anthropic}),
    do: messages

  defp maybe_append_assistant_message(messages, text, thinking, _model)
       when is_binary(text) and text != "" do
    content = build_assistant_content(text, thinking)
    messages ++ [Context.assistant(content)]
  end

  defp maybe_append_assistant_message(messages, _, _, _), do: messages

  defp build_assistant_content(text, thinking) do
    parts = []
    parts = if text != "", do: parts ++ [ContentPart.text(text)], else: parts

    parts =
      if thinking != "", do: parts ++ [ContentPart.thinking(thinking)], else: parts

    parts
  end

  defp normalize_tool_calls(tool_calls, chunk_tool_call_ids) do
    tool_calls
    |> List.wrap()
    |> Enum.with_index()
    |> Enum.flat_map(fn {tool_call, index} ->
      case normalize_tool_call(tool_call, Enum.at(chunk_tool_call_ids, index)) do
        nil -> []
        normalized -> [normalized]
      end
    end)
  end

  defp normalize_tool_call(%ReqLLM.ToolCall{} = tool_call, chunk_id) do
    tool_call
    |> ReqLLM.ToolCall.to_map()
    |> normalize_tool_call(chunk_id)
  end

  defp normalize_tool_call(tool_call, chunk_id) when is_map(tool_call) do
    name =
      Map.get(tool_call, :name) ||
        Map.get(tool_call, "name") ||
        get_in(tool_call, [:function, :name]) ||
        get_in(tool_call, ["function", "name"])

    arguments =
      Map.get(tool_call, :arguments) ||
        Map.get(tool_call, "arguments") ||
        get_in(tool_call, [:function, :arguments]) ||
        get_in(tool_call, ["function", "arguments"]) ||
        %{}

    id =
      chunk_id ||
        Map.get(tool_call, :id) ||
        Map.get(tool_call, "id") ||
        Map.get(tool_call, :call_id) ||
        Map.get(tool_call, "call_id")

    if is_binary(name) and name != "" do
      %{
        id: normalize_tool_call_id(id),
        name: name,
        arguments: normalize_tool_call_arguments(arguments)
      }
    else
      nil
    end
  end

  defp normalize_tool_call(_tool_call, _chunk_id), do: nil

  defp normalize_tool_call_id(id) when is_binary(id) and id != "", do: id
  defp normalize_tool_call_id(id) when is_atom(id), do: Atom.to_string(id)
  defp normalize_tool_call_id(id) when is_number(id), do: to_string(id)
  defp normalize_tool_call_id(_), do: generate_tool_id()

  defp normalize_tool_call_arguments(arguments) when is_map(arguments), do: arguments

  defp normalize_tool_call_arguments(arguments) when is_binary(arguments) do
    case Jason.decode(arguments) do
      {:ok, parsed} when is_map(parsed) -> parsed
      _ -> arguments
    end
  end

  defp normalize_tool_call_arguments(_), do: %{}

  defp append_tool_call_turn(messages, _text, _thinking, []), do: messages

  defp append_tool_call_turn(messages, text, thinking, tool_calls) do
    content = build_assistant_content(text, thinking)
    messages ++ [Context.assistant(content, tool_calls: tool_calls)]
  end

  defp unprocessed_tool_calls(tool_calls, messages) do
    processed_ids =
      messages
      |> Enum.filter(fn message -> Map.get(message, :role) == :tool end)
      |> Enum.map(&Map.get(&1, :tool_call_id))
      |> Enum.filter(&is_binary/1)
      |> MapSet.new()

    Enum.reject(List.wrap(tool_calls), fn tool_call ->
      case tool_call_id(tool_call) do
        id when is_binary(id) -> MapSet.member?(processed_ids, id)
        _ -> false
      end
    end)
  end

  defp tool_call_id(%ReqLLM.ToolCall{} = tool_call), do: tool_call.id

  defp tool_call_id(tool_call) when is_map(tool_call) do
    Map.get(tool_call, :id) ||
      Map.get(tool_call, "id") ||
      Map.get(tool_call, :call_id) ||
      Map.get(tool_call, "call_id")
  end

  defp tool_call_id(_), do: nil

  defp metadata_field(metadata, key) when is_map(metadata) do
    Map.get(metadata, key) || Map.get(metadata, to_string(key))
  end

  defp generate_tool_id do
    "call_#{:erlang.unique_integer([:positive])}"
  end

  defp max_iterations_reached?(_iteration, :infinity), do: false
  defp max_iterations_reached?(iteration, max_iterations), do: iteration > max_iterations
end
