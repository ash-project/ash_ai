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

    When `:system_prompt` is given, its result is sent as a system message ahead
    of `messages` on every model request. It is not part of the returned
    `Result.messages`, so pass the same option when continuing a conversation
    from those messages.

    ## Approvals

    Pass `:approve_tool_call`, a function that receives each tool call
    (`%{id: id, name: name, arguments: args}`) and the tool context, and returns
    `:ok`, `{:deny, reason}`, or `:ask`. Approved calls run and denied calls get
    an error result as usual. When any call in a round needs approval, the loop
    finishes the other calls of that round and stops, returning a `Result` with
    `status: :awaiting_approval` and the calls in `pending_approvals`.

    The loop keeps no state between calls. To resume, call `run/2` or `stream/2`
    again with the returned messages (which end in the paused tool round) and an
    `:approvals` map from call id to `:approve` or `{:deny, reason}`. Calls
    without a decision go through `:approve_tool_call` again. `resume/3` is a
    shorthand.

    If the conversation moves on instead (a user message follows a paused
    round), each unanswered call is sent to the model with a fixed "not run"
    result, so the history stays valid and identical across requests.

    ## Persisting turns

    `stream/2` emits `{:message, message}` for every message the loop adds to
    the conversation: each assistant turn (with its reasoning and provider
    metadata) and each tool result. Store them with `AshAi.Transcript.to_parts/2`
    to replay turns exactly, which keeps prompt caching and reasoning intact
    across turns and lets a paused turn resume later.
    """

    alias ReqLLM.Context
    alias ReqLLM.StreamResponse

    @not_run_message "Not run: the conversation continued before this tool call could run."

    defmodule IterationEvent do
      @moduledoc """
      Event emitted at the start of each iteration in the tool loop.
      """
      defstruct [:iteration, :messages_count, :tool_calls_count]
    end

    defmodule Result do
      @moduledoc """
      Result returned from a completed tool loop.

      `:status` is one of:

      - `:complete`
      - `:awaiting_approval` - the loop stopped for the tool calls in
        `:pending_approvals`. See "Approvals" in `AshAi.ToolLoop`.
      - `:paused` - a tool asked to pause, for example because the user has
        to authorize an MCP server. `:paused_calls` holds
        `%{call: call, reason: reason}` for each. Resume like an approval.

      `:approvals` holds the decisions from the `:approvals` option for calls
      that are still waiting, such as an approved call that then paused.
      Store them with the turn and pass them back when resuming, so the user
      isn't asked twice.

      `:usage` is the token-usage totals summed across every `stream_text/3`
      call made during the loop (one per iteration). Keys mirror what the
      underlying ReqLLM provider reports — typically `:input_tokens`,
      `:output_tokens`, and any cost/cache fields. Numeric fields are summed;
      non-numeric fields fall through to the most recent value. Empty `%{}`
      when no provider reported usage.
      """
      defstruct [
        :messages,
        :final_text,
        :iterations,
        :tool_calls_made,
        status: :complete,
        pending_approvals: [],
        paused_calls: [],
        approvals: %{},
        usage: %{}
      ]
    end

    @doc """
    Runs the tool loop synchronously.

    Returns `{:ok, %Result{}}`, including when the loop stops to wait for
    approvals, or `{:error, reason}`.
    """
    def run(messages, opts) do
      messages
      |> stream(opts)
      |> Enum.reduce({nil, nil}, fn
        {:error, reason}, {nil, result} -> {{:error, reason}, result}
        {:done, result}, {error, _} -> {error, result}
        _event, acc -> acc
      end)
      |> case do
        {nil, result} -> {:ok, result}
        {error, _result} -> error
      end
    end

    @doc """
    Resumes a loop that stopped for approvals.

    `decisions` maps tool call ids to `:approve` or `{:deny, reason}`. Shorthand
    for `run(messages, Keyword.put(opts, :approvals, decisions))`.
    """
    def resume(messages, decisions, opts) do
      run(messages, Keyword.put(opts, :approvals, decisions))
    end

    @doc """
    Streams events from the tool loop.

    Content events are emitted as chunks arrive. Complete assistant messages and
    usage are assembled after each provider response ends. Halting enumeration
    closes the active provider stream without starting another iteration.

    Events:
    - `{:content, text}`
    - `{:thinking, text}`
    - `{:tool_call, %{id: id, name: name, arguments: args}}`
    - `{:tool_result, %{id: id, result: result}}`
    - `{:message, %ReqLLM.Message{}}` - an assistant turn or tool result added
      to the conversation
    - `{:approval_required, [%{id: id, name: name, arguments: args}]}`
    - `{:paused, [%{call: call, reason: reason}]}`
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

    @doc """
    The tool calls of a paused round: calls in the last assistant message that
    have no result, when nothing but tool results follows that message.
    """
    def pending_tool_calls(messages) do
      {trailing_results, rest} =
        messages
        |> Enum.reverse()
        |> Enum.split_while(&(Map.get(&1, :role) == :tool))

      case rest do
        [%{role: :assistant, tool_calls: [_ | _] = calls} | _] ->
          calls |> normalize_tool_calls() |> unprocessed_tool_calls(trailing_results)

        _ ->
          []
      end
    end

    defp init_stream(messages, opts) do
      opts = AshAi.Options.validate!(opts)
      {tools, registry} = AshAi.Tools.build_tools_and_registry(opts)
      context = build_context(opts)
      model = resolve_model(opts.model, opts)

      pending = pending_tool_calls(messages)

      %{
        req_llm: opts.req_llm,
        model: model,
        system_messages: system_messages(opts),
        messages: messages,
        tools: tools,
        registry: registry,
        approve_tool_call: opts.approve_tool_call,
        approvals: opts.approvals,
        req_llm_opts: opts.req_llm_opts,
        context: context,
        # A resumed round runs before the first request, which is iteration 1.
        iteration: if(pending == [], do: 1, else: 0),
        max_iterations: opts.max_iterations,
        tool_calls_made: [],
        usage_acc: %{},
        stream_response: nil,
        continuation: nil,
        chunks: [],
        pending_tool_calls: pending,
        awaiting_approval: [],
        paused_calls: [],
        state: if(pending == [], do: :running, else: :tools)
      }
    end

    defp next_stream_chunk(%{state: :done} = state), do: {:halt, state}

    defp next_stream_chunk(%{state: :streaming} = state) do
      case resume_stream(state.continuation) do
        {:suspended, chunk, continuation} ->
          {chunk_events(chunk),
           %{state | continuation: continuation, chunks: [chunk | state.chunks]}}

        {status, _} when status in [:done, :halted] ->
          {[], %{state | state: :finalizing, continuation: nil}}

        {:raised, kind, reason, stacktrace} ->
          # The upstream enumerable has already unwound. Clear its consumed
          # continuation before reraising so cleanup cannot invoke it twice.
          {[], %{state | state: {:raised, kind, reason, stacktrace}, continuation: nil}}
      end
    end

    defp next_stream_chunk(%{state: {:raised, kind, reason, stacktrace}}) do
      :erlang.raise(kind, reason, stacktrace)
    end

    defp next_stream_chunk(%{state: :finalizing} = state) do
      chunks = Enum.reverse(state.chunks)
      stream_response = %{state.stream_response | stream: chunks, model: state.model}
      usage = StreamResponse.usage(stream_response)

      case StreamResponse.to_response(stream_response) do
        {:ok, response} ->
          finish_stream_iteration(
            %{state | stream_response: nil, chunks: []},
            response.message,
            StreamResponse.classify(stream_response),
            usage
          )

        {:error, reason} ->
          stream_error(%{state | stream_response: nil, chunks: []}, reason)
      end
    end

    defp next_stream_chunk(
           %{
             state: :tools,
             pending_tool_calls: [],
             awaiting_approval: awaiting,
             paused_calls: paused
           } = state
         )
         when awaiting != [] or paused != [] do
      waiting_ids = Enum.map(awaiting ++ Enum.map(paused, & &1.call), & &1.id)

      result = %Result{
        messages: state.messages,
        final_text: "",
        iterations: state.iteration,
        tool_calls_made: state.tool_calls_made,
        status: if(awaiting != [], do: :awaiting_approval, else: :paused),
        pending_approvals: awaiting,
        paused_calls: paused,
        approvals: Map.take(state.approvals, waiting_ids),
        usage: state.usage_acc
      }

      events =
        [
          if(awaiting != [], do: {:approval_required, awaiting}),
          if(paused != [], do: {:paused, paused}),
          {:done, result}
        ]
        |> Enum.reject(&is_nil/1)

      {events, %{state | state: :done}}
    end

    defp next_stream_chunk(%{state: :tools, pending_tool_calls: []} = state) do
      iteration = state.iteration + 1

      {[{:iteration, %IterationEvent{iteration: iteration}}],
       %{state | state: :running, iteration: iteration}}
    end

    defp next_stream_chunk(%{state: :tools, pending_tool_calls: [call | rest]} = state) do
      case decide(call, state) do
        :ask ->
          {[],
           %{
             state
             | pending_tool_calls: rest,
               awaiting_approval: state.awaiting_approval ++ [call]
           }}

        decision ->
          outcome =
            case decision do
              :approve ->
                run_single_tool(call, state.registry, state.context)

              {:deny, reason} ->
                content = Jason.encode!(%{error: denial_message(reason)})
                {{:error, content}, content}
            end

          case outcome do
            # The call stays unanswered, so resuming runs it again.
            {:pause, reason} ->
              paused = %{call: call, reason: reason}

              {[],
               %{state | pending_tool_calls: rest, paused_calls: state.paused_calls ++ [paused]}}

            {result, content} ->
              message = Context.tool_result(call.id, content)

              {[{:tool_result, %{id: call.id, result: result}}, {:message, message}],
               %{state | messages: state.messages ++ [message], pending_tool_calls: rest}}
          end
      end
    end

    defp next_stream_chunk(%{state: :running} = state) do
      if max_iterations_reached?(state.iteration, state.max_iterations) do
        stream_error(state, :max_iterations_reached)
      else
        case state.req_llm.stream_text(
               state.model,
               state.system_messages ++ close_dangling_tool_calls(state.messages),
               req_llm_stream_opts(state.req_llm_opts, state.tools)
             ) do
          {:ok, stream_response} ->
            # Suspend after each chunk so the caller can consume it before we pull another.
            continuation = fn command ->
              Enumerable.reduce(stream_response.stream, command, fn chunk, _acc ->
                {:suspend, normalize_chunk_tool_call_id(chunk)}
              end)
            end

            {[],
             %{
               state
               | state: :streaming,
                 stream_response: stream_response,
                 continuation: continuation
             }}

          {:error, reason} ->
            stream_error(state, reason)
        end
      end
    end

    defp chunk_events(%{type: :content, text: text}), do: [{:content, text || ""}]

    defp chunk_events(%{type: :thinking, text: text}) when is_binary(text),
      do: [{:thinking, text}]

    defp chunk_events(_chunk), do: []

    defp decide(call, state) do
      cond do
        Map.has_key?(state.approvals, call.id) ->
          normalize_decision(state.approvals[call.id])

        is_function(state.approve_tool_call, 2) ->
          normalize_decision(state.approve_tool_call.(call, state.context))

        true ->
          :approve
      end
    end

    defp normalize_decision(decision) when decision in [:ok, :approve, :approved, true],
      do: :approve

    defp normalize_decision(decision) when decision in [:deny, :denied, false],
      do: {:deny, nil}

    defp normalize_decision({:deny, reason}), do: {:deny, reason}
    defp normalize_decision(:ask), do: :ask

    defp normalize_decision(other) do
      raise ArgumentError,
            "Expected :ok, :approve, {:deny, reason}, or :ask as a tool call decision, got: #{inspect(other)}"
    end

    defp denial_message(nil), do: "The user denied this tool call."
    defp denial_message(reason), do: "The user denied this tool call: #{reason}"

    # Gives every tool call that a later message left unanswered a fixed result,
    # right after the results it did get. The provider rejects a history with
    # unanswered calls, and a fixed result keeps every request's prefix identical.
    defp close_dangling_tool_calls(messages) do
      {acc, _open} =
        Enum.reduce(messages, {[], []}, fn message, {acc, open} ->
          case message do
            %{role: :tool, tool_call_id: id} ->
              {[message | acc], List.delete(open, id)}

            %{role: :assistant, tool_calls: [_ | _] = calls} ->
              ids = calls |> normalize_tool_calls() |> Enum.map(& &1.id)
              {[message | not_run_results(open) ++ acc], ids}

            message ->
              {[message | not_run_results(open) ++ acc], []}
          end
        end)

      # Calls still open at the end belong to a paused round, which is resolved
      # before any request is made.
      Enum.reverse(acc)
    end

    defp not_run_results(ids) do
      ids
      |> Enum.reverse()
      |> Enum.map(&Context.tool_result(&1, Jason.encode!(%{error: @not_run_message})))
    end

    defp resume_stream(continuation) do
      continuation.({:cont, nil})
    catch
      kind, reason -> {:raised, kind, reason, __STACKTRACE__}
    end

    defp cleanup_stream(state) do
      if state.continuation, do: state.continuation.({:halt, nil})
    after
      if state.stream_response, do: StreamResponse.close(state.stream_response)
    end

    defp finish_stream_iteration(state, assistant, classification, usage) do
      usage_acc = accumulate_usage(state.usage_acc, usage)

      tool_calls =
        if classification.type == :tool_calls do
          classification.tool_calls
          |> normalize_tool_calls()
          |> unprocessed_tool_calls(state.messages)
        else
          []
        end

      # No new calls means no progress is possible, including when the provider
      # only replays previously processed calls. Finish instead of looping.
      if tool_calls != [] do
        turn = tool_call_turn(assistant, tool_calls)
        messages = state.messages ++ [turn]

        {[{:message, turn} | Enum.map(tool_calls, &{:tool_call, &1})],
         %{
           state
           | state: :tools,
             messages: messages,
             pending_tool_calls: tool_calls,
             tool_calls_made: state.tool_calls_made ++ tool_calls,
             usage_acc: usage_acc
         }}
      else
        messages =
          maybe_append_assistant_message(
            state.messages,
            assistant,
            classification.text,
            state.model
          )

        result = %Result{
          messages: messages,
          final_text: classification.text,
          iterations: state.iteration,
          tool_calls_made: state.tool_calls_made,
          usage: usage_acc
        }

        # Emitted whenever the turn has content, even without text, so a caller
        # persisting turns keeps its reasoning and metadata.
        events =
          case assistant do
            %{content: [_ | _]} -> [{:message, %{assistant | tool_calls: nil}}, {:done, result}]
            _ -> [{:done, result}]
          end

        {events, %{state | state: :done}}
      end
    end

    defp stream_error(state, reason) do
      result = %Result{
        messages: state.messages,
        final_text: "",
        iterations: state.iteration - 1,
        tool_calls_made: state.tool_calls_made,
        usage: state.usage_acc
      }

      {[{:error, reason}, {:done, result}], %{state | state: :done}}
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

    defp system_messages(%{system_prompt: system_prompt} = opts)
         when is_function(system_prompt, 1),
         do: [Context.system(system_prompt.(opts))]

    defp system_messages(_opts), do: []

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

        case result do
          {:ok, content, _raw} -> {result, content}
          {:error, content} -> {result, content}
          {:pause, reason} -> {:pause, reason}
        end
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

    defp tool_call_turn(assistant, tool_calls) do
      ids = MapSet.new(tool_calls, & &1.id)
      calls = Enum.filter(assistant.tool_calls, &MapSet.member?(ids, &1.id))
      %{assistant | tool_calls: calls}
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
