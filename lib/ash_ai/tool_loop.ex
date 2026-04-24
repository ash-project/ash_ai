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
    """
    defstruct [:messages, :final_text, :iterations, :tool_calls_made]
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
      []
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
      state: :running
    }
  end

  defp next_stream_chunk(%{state: :done} = state), do: {:halt, state}

  defp next_stream_chunk(state) do
    case stream_iteration(state) do
      {:continue, events, new_state} ->
        {events, new_state}

      {:done, events, result} ->
        {events ++ [{:done, result}], %{state | state: :done}}
    end
  end

  defp cleanup_stream(_state), do: :ok

  defp stream_iteration(state) do
    %{
      req_llm: req_llm,
      model: model,
      messages: messages,
      tools: tools,
      registry: registry,
      req_llm_opts: req_llm_opts,
      context: context,
      iteration: iteration,
      max_iterations: max_iterations,
      tool_calls_made: tool_calls_made
    } = state

    if max_iterations_reached?(iteration, max_iterations) do
      result = %Result{
        messages: messages,
        final_text: "",
        iterations: iteration - 1,
        tool_calls_made: tool_calls_made
      }

      {:done, [{:error, :max_iterations_reached}], result}
    else
      case req_llm.stream_text(model, messages, req_llm_stream_opts(req_llm_opts, tools)) do
        {:ok, stream_response} ->
          chunks = Enum.to_list(stream_response.stream)
          content_events = content_events(chunks)
          chunk_tool_call_ids = chunk_tool_call_ids(chunks)

          classification =
            stream_response
            |> Map.put(:stream, chunks)
            |> ReqLLM.StreamResponse.classify()

          if classification.type == :tool_calls do
            tool_calls =
              classification.tool_calls
              |> normalize_tool_calls(chunk_tool_call_ids)
              |> unprocessed_tool_calls(messages)

            messages = append_tool_call_turn(messages, classification.text, tool_calls)

            {messages, tool_events} = run_tools_streaming(tool_calls, messages, registry, context)

            new_state = %{
              state
              | messages: messages,
                iteration: iteration + 1,
                tool_calls_made: tool_calls_made ++ tool_calls
            }

            {:continue,
             content_events ++
               Enum.map(tool_calls, &{:tool_call, &1}) ++
               tool_events ++
               [{:iteration, %IterationEvent{iteration: iteration + 1}}], new_state}
          else
            messages = maybe_append_assistant_message(messages, classification.text, model)

            result = %Result{
              messages: messages,
              final_text: classification.text,
              iterations: iteration,
              tool_calls_made: tool_calls_made
            }

            {:done, content_events, result}
          end

        {:error, reason} ->
          result = %Result{
            messages: messages,
            final_text: "",
            iterations: iteration - 1,
            tool_calls_made: tool_calls_made
          }

          {:done, [{:error, reason}], result}
      end
    end
  end

  defp content_events(chunks) do
    chunks
    |> Enum.filter(&(&1.type == :content))
    |> Enum.map(fn chunk -> {:content, chunk.text || ""} end)
  end

  defp run_tools_streaming(tool_calls, messages, registry, ctx) do
    Enum.reduce(tool_calls, {messages, []}, fn tool_call, {msgs, events} ->
      case run_single_tool(tool_call, registry, ctx) do
        {result, content} ->
          {
            msgs ++ [Context.tool_result(tool_call.id, content)],
            events ++ [{:tool_result, %{id: tool_call.id, result: result}}]
          }
      end
    end)
  end

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
         tool_calls_made
       ) do
    if max_iterations_reached?(iteration, max_iterations) do
      {:error, :max_iterations_reached}
    else
      case req_llm.stream_text(model, messages, req_llm_stream_opts(req_llm_opts, tools)) do
        {:ok, stream_response} ->
          chunks = Enum.to_list(stream_response.stream)
          chunk_tool_call_ids = chunk_tool_call_ids(chunks)

          classification =
            stream_response
            |> Map.put(:stream, chunks)
            |> ReqLLM.StreamResponse.classify()

          if classification.type == :tool_calls do
            tool_calls =
              classification.tool_calls
              |> normalize_tool_calls(chunk_tool_call_ids)
              |> unprocessed_tool_calls(messages)

            messages = append_tool_call_turn(messages, classification.text, tool_calls)
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
              tool_calls_made ++ tool_calls
            )
          else
            messages = maybe_append_assistant_message(messages, classification.text, model)

            {:ok,
             %Result{
               messages: messages,
               final_text: classification.text,
               iterations: iteration,
               tool_calls_made: tool_calls_made
             }}
          end

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

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

  defp maybe_append_assistant_message(messages, _text, %{provider: :anthropic}), do: messages

  defp maybe_append_assistant_message(messages, text, _model)
       when is_binary(text) and text != "" do
    messages ++ [Context.assistant(text)]
  end

  defp maybe_append_assistant_message(messages, _, _), do: messages

  defp chunk_tool_call_ids(chunks) do
    chunks
    |> Enum.filter(&(&1.type == :tool_call))
    |> Enum.map(fn chunk ->
      metadata = chunk.metadata || %{}
      metadata_field(metadata, :id) || metadata_field(metadata, :call_id)
    end)
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

  defp append_tool_call_turn(messages, _text, []), do: messages

  defp append_tool_call_turn(messages, text, tool_calls) do
    case merge_into_previous_tool_turn(messages, text, tool_calls) do
      {:ok, merged_messages} ->
        merged_messages

      :no_merge ->
        messages ++ [Context.assistant(text, tool_calls: tool_calls)]
    end
  end

  defp merge_into_previous_tool_turn(messages, text, tool_calls) do
    {trailing_tools_rev, rest_rev} =
      messages
      |> Enum.reverse()
      |> Enum.split_while(fn message -> Map.get(message, :role) == :tool end)

    trailing_tools = Enum.reverse(trailing_tools_rev)
    rest = Enum.reverse(rest_rev)

    case List.last(rest) do
      %{role: :assistant} = assistant ->
        if has_tool_calls?(assistant.tool_calls) do
          prefix = Enum.drop(rest, -1)

          merged_tool_calls =
            merge_tool_call_lists(
              assistant.tool_calls || [],
              normalize_context_tool_calls(tool_calls)
            )

          merged_assistant = %{
            assistant
            | tool_calls: merged_tool_calls,
              content: merge_assistant_content(assistant.content, text)
          }

          {:ok, prefix ++ [merged_assistant] ++ trailing_tools}
        else
          :no_merge
        end

      _ ->
        :no_merge
    end
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

  defp merge_tool_call_lists(existing, new_calls) do
    {merged, _seen_ids} =
      Enum.reduce(List.wrap(existing) ++ List.wrap(new_calls), {[], MapSet.new()}, fn call,
                                                                                      {acc, seen} ->
        case tool_call_id(call) do
          id when is_binary(id) ->
            if MapSet.member?(seen, id) do
              {acc, seen}
            else
              {acc ++ [call], MapSet.put(seen, id)}
            end

          _ ->
            {acc ++ [call], seen}
        end
      end)

    merged
  end

  defp tool_call_id(%ReqLLM.ToolCall{} = tool_call), do: tool_call.id

  defp tool_call_id(tool_call) when is_map(tool_call) do
    Map.get(tool_call, :id) ||
      Map.get(tool_call, "id") ||
      Map.get(tool_call, :call_id) ||
      Map.get(tool_call, "call_id")
  end

  defp tool_call_id(_), do: nil

  defp has_tool_calls?(tool_calls) when is_list(tool_calls), do: tool_calls != []
  defp has_tool_calls?(_), do: false

  defp normalize_context_tool_calls(tool_calls) do
    Context.assistant("", tool_calls: tool_calls).tool_calls || []
  end

  defp merge_assistant_content(content, text) when text in [nil, ""], do: content

  defp merge_assistant_content(content, text) do
    existing_text = assistant_text(content)

    combined_text =
      if existing_text == "" do
        text
      else
        existing_text <> "\n" <> text
      end

    [ContentPart.text(combined_text)]
  end

  defp assistant_text(content_parts) when is_list(content_parts) do
    content_parts
    |> Enum.map_join(fn
      %ContentPart{type: :text, text: text} when is_binary(text) -> text
      %{type: :text, text: text} when is_binary(text) -> text
      _ -> ""
    end)
    |> String.trim()
  end

  defp assistant_text(_), do: ""

  defp metadata_field(metadata, key) when is_map(metadata) do
    Map.get(metadata, key) || Map.get(metadata, to_string(key))
  end

  defp generate_tool_id do
    "call_#{:erlang.unique_integer([:positive])}"
  end

  defp max_iterations_reached?(_iteration, :infinity), do: false
  defp max_iterations_reached?(iteration, max_iterations), do: iteration > max_iterations
end
