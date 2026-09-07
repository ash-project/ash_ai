# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

if Code.ensure_loaded?(ReqLLM) do
  defmodule AshAi.ToolLoop do
    @moduledoc """
    Manages a ReqLLM conversation loop with tool calls.

    This module is the primary orchestration API for tool-enabled conversations.

    Each assistant tool-call turn is appended before its tool results. Earlier
    messages remain unchanged, including their reasoning and provider metadata.
    """

    alias ReqLLM.Context
    alias ReqLLM.StreamResponse

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
        tool_calls_made: tool_calls_made,
        usage_acc: usage_acc
      } = state

      if max_iterations_reached?(iteration, max_iterations) do
        result = %Result{
          messages: messages,
          final_text: "",
          iterations: iteration - 1,
          tool_calls_made: tool_calls_made,
          usage: usage_acc
        }

        {:done, [{:error, :max_iterations_reached}], result}
      else
        case request_response(req_llm, model, messages, req_llm_opts, tools) do
          {:ok, stream_response, chunks, response, usage} ->
            content_events = content_events(chunks)
            assistant = response.message
            usage_acc = accumulate_usage(usage_acc, usage)

            classification =
              stream_response
              |> Map.put(:stream, chunks)
              |> ReqLLM.StreamResponse.classify()

            tool_calls =
              if classification.type == :tool_calls do
                classification.tool_calls
                |> normalize_tool_calls()
                |> unprocessed_tool_calls(messages)
              else
                []
              end

            # An empty post-filter list means the model returned only invalid or
            # already-processed tool calls, so `messages` would not advance.
            # Recursing would re-send a byte-identical request forever (a
            # no-progress loop, unbounded under `max_iterations: :infinity`), so
            # treat it as terminal.
            if tool_calls != [] do
              messages =
                append_tool_call_turn(
                  messages,
                  assistant,
                  tool_calls
                )

              {messages, tool_events} =
                run_tools_streaming(tool_calls, messages, registry, context)

              new_state = %{
                state
                | messages: messages,
                  iteration: iteration + 1,
                  tool_calls_made: tool_calls_made ++ tool_calls,
                  usage_acc: usage_acc
              }

              {:continue,
               content_events ++
                 Enum.map(tool_calls, &{:tool_call, &1}) ++
                 tool_events ++
                 [{:iteration, %IterationEvent{iteration: iteration + 1}}], new_state}
            else
              messages =
                maybe_append_assistant_message(
                  messages,
                  assistant,
                  classification.text,
                  model
                )

              result = %Result{
                messages: messages,
                final_text: classification.text,
                iterations: iteration,
                tool_calls_made: tool_calls_made,
                usage: usage_acc
              }

              {:done, content_events, result}
            end

          {:error, reason} ->
            result = %Result{
              messages: messages,
              final_text: "",
              iterations: iteration - 1,
              tool_calls_made: tool_calls_made,
              usage: usage_acc
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

    # Sums per-iteration usage maps into a running accumulator. Numeric
    # fields (input_tokens, output_tokens, cached_tokens, *_cost, ...) are
    # summed so the final `Result.usage` reflects everything billed across
    # the entire tool loop. Non-numeric fields fall through to the most
    # recent iteration's value, since they're typically per-call metadata
    # like `:provider_meta` or `:model`.
    defp accumulate_usage(acc, nil), do: acc
    defp accumulate_usage(acc, usage) when usage == %{}, do: acc

    defp accumulate_usage(acc, usage) when is_map(usage) do
      Map.merge(acc, usage, fn
        _key, a, b when is_number(a) and is_number(b) -> a + b
        _key, _a, b -> b
      end)
    end

    defp request_response(req_llm, model, messages, req_llm_opts, tools) do
      with {:ok, stream_response} <-
             req_llm.stream_text(model, messages, req_llm_stream_opts(req_llm_opts, tools)) do
        chunks = Enum.map(stream_response.stream, &normalize_chunk_tool_call_id/1)
        usage = StreamResponse.usage(stream_response)

        with {:ok, response} <-
               StreamResponse.to_response(%{stream_response | stream: chunks, model: model}) do
          {:ok, stream_response, chunks, response, usage}
        end
      end
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

    defp resolve_model(model, opts) when is_function(model, 0),
      do: resolve_model(model.(), opts)

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
        case request_response(req_llm, model, messages, req_llm_opts, tools) do
          {:ok, stream_response, chunks, response, usage} ->
            assistant = response.message
            usage_acc = accumulate_usage(usage_acc, usage)

            classification =
              stream_response
              |> Map.put(:stream, chunks)
              |> ReqLLM.StreamResponse.classify()

            tool_calls =
              if classification.type == :tool_calls do
                classification.tool_calls
                |> normalize_tool_calls()
                |> unprocessed_tool_calls(messages)
              else
                []
              end

            # An empty post-filter list means the model returned only invalid or
            # already-processed tool calls, so `messages` would not advance.
            # Recursing would re-send a byte-identical request forever (a
            # no-progress loop, unbounded under `max_iterations: :infinity`), so
            # treat it as terminal.
            if tool_calls != [] do
              messages =
                append_tool_call_turn(
                  messages,
                  assistant,
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
                  assistant,
                  classification.text,
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
                  # Route the raised exception through the same safe formatter as
                  # other tool errors instead of echoing Exception.message/1,
                  # which can carry internal details (DB schema, SQL, policy
                  # internals). Unknown errors are logged and rendered generically.
                  {:error, Jason.encode!(%{error: AshAi.Tool.Errors.format(e)})}
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

    defp maybe_append_assistant_message(messages, _assistant, _text, %{provider: :anthropic}),
      do: messages

    defp maybe_append_assistant_message(messages, assistant, text, _model)
         when is_binary(text) and text != "" do
      messages ++ [%{assistant | tool_calls: nil}]
    end

    defp maybe_append_assistant_message(messages, _, _, _), do: messages

    defp normalize_chunk_tool_call_id(%ReqLLM.StreamChunk{type: :tool_call} = chunk) do
      metadata = chunk.metadata || %{}
      id = metadata_field(metadata, :id) || metadata_field(metadata, :call_id)
      %{chunk | metadata: Map.put(metadata, :id, normalize_tool_call_id(id))}
    end

    defp normalize_chunk_tool_call_id(chunk), do: chunk

    defp normalize_tool_calls(tool_calls) do
      tool_calls
      |> List.wrap()
      |> Enum.flat_map(fn tool_call ->
        case normalize_tool_call(tool_call) do
          nil -> []
          normalized -> [normalized]
        end
      end)
    end

    defp normalize_tool_call(%ReqLLM.ToolCall{} = tool_call) do
      tool_call
      |> ReqLLM.ToolCall.to_map()
      |> normalize_tool_call()
    end

    defp normalize_tool_call(tool_call) when is_map(tool_call) do
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

    defp normalize_tool_call(_tool_call), do: nil

    defp normalize_tool_call_id(id) when is_binary(id) and id != "", do: id
    defp normalize_tool_call_id(id) when is_atom(id) and not is_nil(id), do: Atom.to_string(id)
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

    defp append_tool_call_turn(messages, assistant, tool_calls) do
      ids = MapSet.new(tool_calls, & &1.id)
      calls = Enum.filter(assistant.tool_calls, &MapSet.member?(ids, &1.id))
      messages ++ [%{assistant | tool_calls: calls}]
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
else
  defmodule AshAi.ToolLoop do
    @moduledoc "Requires the `req_llm` dependency."

    def run(_messages, _opts), do: AshAi.Dependencies.require_req_llm!("`AshAi.ToolLoop`")
    def stream(_messages, _opts), do: AshAi.Dependencies.require_req_llm!("`AshAi.ToolLoop`")
  end
end
