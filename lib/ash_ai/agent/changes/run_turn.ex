# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Agent.Changes.RunTurn do
  @moduledoc """
  Implements one synchronous turn for an `AshAi.Agent`.

  In sequence:

    1. If the optional `:message` argument is provided, inserts it as a `:user`
       row at the current generation (already-drained state).
    2. Drains any `pending: true` rows for this agent — flips them to
       `pending: false` and assigns the agent's `current_generation`. Drained
       rows become part of the LLM context for this turn.
    3. Loads conversation history (`pending: false AND generation == current_generation`).
    4. Streams the LLM response via `ReqLLM.stream_text/3`. Each `:content`
       chunk is forwarded to the agent's optional `on_stream` callback (the
       caller decides whether/how to broadcast it).
    5. Inserts assistant rows per iteration as they finalize, and tool_call /
       tool_result rows as the model emits them. AshAi never touches a
       Phoenix Endpoint — row inserts publish via the messages resource's
       configured Ash notifier.

  The action that runs this change should be non-transactional (`transaction?
  false`) because the LLM call can take seconds and shouldn't hold a database
  transaction open. Empty turns (no message, no pending, no history) short-circuit
  with no LLM call.
  """
  use Ash.Resource.Change

  @impl true
  def change(changeset, _opts, _context) do
    Ash.Changeset.after_action(changeset, fn changeset, agent ->
      user_message = Ash.Changeset.get_argument(changeset, :message)
      resource = changeset.resource

      with {:ok, agent} <- maybe_compact(resource, agent),
           {:ok, user_added?} <- maybe_insert_user_message(resource, agent, user_message),
           {:ok, drained} <- drain_pending(resource, agent) do
        if user_added? or drained > 0 do
          with {:ok, history} <- load_history(resource, agent),
               {:ok, _text} <- stream_llm(resource, agent, history) do
            {:ok, agent}
          end
        else
          {:ok, agent}
        end
      end
    end)
  end

  # Triggers compaction at turn-start when the latest persisted assistant
  # message in the current generation reports input-token usage above the
  # configured threshold. Returns the (possibly updated) agent.
  defp maybe_compact(resource, agent) do
    case compaction_trigger(resource) do
      :never ->
        {:ok, agent}

      trigger ->
        if compaction_threshold_exceeded?(resource, agent, trigger) do
          run_compaction(resource, agent)
        else
          {:ok, agent}
        end
    end
  end

  defp compaction_trigger(resource) do
    case AshAi.Agent.Info.compaction_on(resource) do
      {:ok, value} -> value
      _ -> :never
    end
  end

  defp compaction_threshold_exceeded?(resource, agent, trigger) do
    case latest_input_tokens(resource, agent) do
      nil ->
        false

      tokens ->
        tokens >= compaction_threshold(resource, trigger)
    end
  end

  defp compaction_threshold(_resource, {:token_threshold, n}), do: n

  defp compaction_threshold(resource, {:percentage, fraction}) do
    case AshAi.Agent.Info.agent_model!(resource) |> ReqLLM.model!() do
      %{limits: %{context: ctx}} when is_integer(ctx) and ctx > 0 ->
        round(ctx * fraction)

      _ ->
        # Unknown context window — never compact rather than guessing.
        :infinity
    end
  end

  defp compaction_threshold(_, _), do: :infinity

  defp latest_input_tokens(resource, agent) do
    messages_module = AshAi.Agent.Info.agent_messages!(resource)

    messages_module
    |> Ash.Query.filter(
      agent_id == ^agent.id and pending == false and generation == ^agent.current_generation and
        role == :assistant
    )
    |> Ash.Query.sort(inserted_at: :desc)
    |> Ash.Query.limit(1)
    |> Ash.read!()
    |> case do
      [%{metadata: %{"usage" => %{"input_tokens" => n}}}] when is_integer(n) -> n
      _ -> nil
    end
  end

  defp run_compaction(resource, agent) do
    messages_module = AshAi.Agent.Info.agent_messages!(resource)

    history =
      messages_module
      |> Ash.Query.filter(
        agent_id == ^agent.id and pending == false and generation == ^agent.current_generation
      )
      |> Ash.Query.sort(inserted_at: :asc)
      |> Ash.read!()

    {:ok, agent} = mark_state(agent, :compacting)

    result =
      case summarize(resource, history) do
        {:ok, summary_text} ->
          new_generation = agent.current_generation + 1

          with {:ok, _} <- write_summary(resource, agent, summary_text, new_generation),
               {:ok, agent} <- bump_generation(agent, new_generation) do
            {:ok, agent}
          end

        {:error, _} ->
          # Best-effort: skip compaction on summarize failure, let the turn
          # proceed. Will retry on next turn.
          {:ok, agent}
      end

    case result do
      {:ok, agent} ->
        {:ok, agent} = mark_state(agent, :working)
        {:ok, agent}

      other ->
        other
    end
  end

  defp mark_state(agent, new_state) do
    agent
    |> Ash.Changeset.for_update(:update_lifecycle_state, %{state: new_state})
    |> Ash.update()
  end

  defp summarize(resource, history) do
    model = AshAi.Agent.Info.agent_model!(resource)
    prompt = AshAi.Agent.Info.compaction_prompt!(resource)

    transcript = Enum.map_join(history, "\n", &format_history_row/1)

    messages = [
      ReqLLM.Context.user(transcript)
    ]

    case ReqLLM.generate_text(model, messages, system_prompt: prompt) do
      {:ok, %{message: %{content: content}}} -> {:ok, extract_text(content)}
      {:error, error} -> {:error, error}
      other -> {:error, other}
    end
  rescue
    e -> {:error, e}
  end

  defp extract_text(content) when is_binary(content), do: content

  defp extract_text(parts) when is_list(parts) do
    parts
    |> Enum.map(fn
      %{type: :text, text: t} when is_binary(t) -> t
      %{"type" => "text", "text" => t} when is_binary(t) -> t
      _ -> ""
    end)
    |> Enum.join()
  end

  defp extract_text(_), do: ""

  defp format_history_row(%{role: role, message: text}) when is_binary(text) do
    "[#{role}] #{text}"
  end

  defp format_history_row(_), do: ""

  defp write_summary(resource, agent, text, new_generation) do
    messages_module = AshAi.Agent.Info.agent_messages!(resource)

    messages_module
    |> Ash.Changeset.for_create(:create, %{
      agent_id: agent.id,
      role: :summary,
      message: text,
      pending: false,
      generation: new_generation
    })
    |> Ash.create()
  end

  defp bump_generation(agent, new_generation) do
    agent
    |> Ash.Changeset.for_update(:bump_generation, %{current_generation: new_generation})
    |> Ash.update()
  end

  defp maybe_insert_user_message(_, _, nil), do: {:ok, false}
  defp maybe_insert_user_message(_, _, ""), do: {:ok, false}

  defp maybe_insert_user_message(resource, agent, text) do
    messages_module = AshAi.Agent.Info.agent_messages!(resource)

    case messages_module
         |> Ash.Changeset.for_create(:create, %{
           agent_id: agent.id,
           role: :user,
           message: text,
           pending: false,
           generation: agent.current_generation
         })
         |> Ash.create() do
      {:ok, _} -> {:ok, true}
      {:error, e} -> {:error, e}
    end
  end

  defp drain_pending(resource, agent) do
    messages_module = AshAi.Agent.Info.agent_messages!(resource)

    pending =
      messages_module
      |> Ash.Query.filter(agent_id == ^agent.id and pending == true)
      |> Ash.read!()

    Enum.each(pending, fn row ->
      row
      |> Ash.Changeset.for_update(:update, %{
        pending: false,
        generation: agent.current_generation
      })
      |> Ash.update!()
    end)

    {:ok, length(pending)}
  end

  defp load_history(resource, agent) do
    messages_module = AshAi.Agent.Info.agent_messages!(resource)

    messages =
      messages_module
      |> Ash.Query.filter(
        agent_id == ^agent.id and pending == false and generation == ^agent.current_generation
      )
      |> Ash.Query.sort(inserted_at: :asc)
      |> Ash.read!()

    {:ok, messages}
  end

  defp stream_llm(resource, agent, history) do
    model = AshAi.Agent.Info.agent_model!(resource)
    base_prompt = AshAi.Agent.Info.agent_system_prompt!(resource)
    tool_names = resolve_tool_names(resource)
    on_stream = on_stream(resource)
    agent_type = AshAi.Agent.Info.agent_type!(resource)
    context = build_context(history, resource)

    {agent, peer_relationships} = load_peer_context(resource, agent)
    system_prompt = build_system_prompt(base_prompt, resource, agent, peer_relationships)

    emit_stream(on_stream, %AshAi.Agent.StreamEvent{
      type: :start,
      agent_id: agent.id,
      agent_type: agent_type
    })

    extra_tools = build_extra_tools(resource, agent)
    req_llm_opts = build_req_llm_opts(resource)

    opts =
      [
        model: model,
        system_prompt: fn _ -> system_prompt end,
        otp_app: Application.get_application(resource),
        actor: agent,
        extra_tools: extra_tools,
        req_llm_opts: req_llm_opts
      ] ++ if tool_names == [], do: [tools: false], else: [tools: tool_names]

    messages = ReqLLM.Context.to_list(context)

    # Accumulator: %{text: cumulative text for this iteration,
    #               status: nil | :error,
    #               error_reason: term | nil,
    #               message_id: pre-generated UUID for the row this iteration
    #                           will persist (also sent in :delta events so the
    #                           UI can key its placeholder),
    #               pending_usage: most recent {:usage, ...} payload — paired
    #                              with the next :assistant_message we persist}
    initial_acc = %{
      text: "",
      status: nil,
      error_reason: nil,
      message_id: nil,
      pending_usage: nil
    }

    final_acc =
      messages
      |> AshAi.ToolLoop.stream(opts)
      |> Enum.reduce(initial_acc, fn event, acc ->
        handle_tool_loop_event(event, acc, resource, agent, on_stream, agent_type)
      end)

    case final_acc do
      %{status: :error, error_reason: reason} ->
        {:error, reason}

      %{text: text} ->
        emit_stream(on_stream, %AshAi.Agent.StreamEvent{
          type: :done,
          agent_id: agent.id,
          agent_type: agent_type
        })

        {:ok, text}
    end
  end

  defp handle_tool_loop_event({:content, text}, acc, _, agent, on_stream, agent_type) do
    message_id = acc.message_id || Ash.UUIDv7.generate()
    new_text = acc.text <> text

    emit_stream(on_stream, %AshAi.Agent.StreamEvent{
      type: :delta,
      agent_id: agent.id,
      agent_type: agent_type,
      message_id: message_id,
      text: new_text
    })

    %{acc | text: new_text, message_id: message_id}
  end

  defp handle_tool_loop_event(
         {:assistant_message, text},
         acc,
         resource,
         agent,
         on_stream,
         agent_type
       ) do
    message_id = acc.message_id || Ash.UUIDv7.generate()
    insert_assistant_message(resource, agent, text, message_id, acc.pending_usage)

    # Reset the streaming buffer in the UI for the next iteration. The
    # persisted row arrives via the messages-resource notifier; the UI
    # should swap its placeholder for the row, keyed by message_id.
    emit_stream(on_stream, %AshAi.Agent.StreamEvent{
      type: :delta,
      agent_id: agent.id,
      agent_type: agent_type,
      message_id: message_id,
      text: ""
    })

    %{acc | text: "", message_id: nil, pending_usage: nil}
  end

  defp handle_tool_loop_event({:usage, usage}, acc, _, _, _, _) do
    %{acc | pending_usage: usage}
  end

  defp handle_tool_loop_event({:tool_call, tc}, acc, resource, agent, _, _) do
    insert_tool_call_row(resource, agent, tc)
    acc
  end

  defp handle_tool_loop_event({:tool_result, tr}, acc, resource, agent, _, _) do
    insert_tool_result_row(resource, agent, tr)
    acc
  end

  defp handle_tool_loop_event({:done, %{final_text: final}}, acc, _, _, _, _),
    do: %{acc | text: final || acc.text}

  defp handle_tool_loop_event({:error, reason}, acc, _, agent, on_stream, agent_type) do
    emit_stream(on_stream, %AshAi.Agent.StreamEvent{
      type: :error,
      agent_id: agent.id,
      agent_type: agent_type,
      reason: inspect(reason)
    })

    %{acc | status: :error, error_reason: reason}
  end

  defp handle_tool_loop_event(_, acc, _, _, _, _), do: acc

  defp emit_stream(nil, _event), do: :ok

  defp emit_stream(callback, event) when is_function(callback, 1) do
    safe_apply(fn -> callback.(event) end)
  end

  defp emit_stream({mod, fun}, event) when is_atom(mod) and is_atom(fun) do
    safe_apply(fn -> apply(mod, fun, [event]) end)
  end

  defp emit_stream({mod, fun, extra}, event)
       when is_atom(mod) and is_atom(fun) and is_list(extra) do
    safe_apply(fn -> apply(mod, fun, [event | extra]) end)
  end

  defp safe_apply(fun) do
    fun.()
    :ok
  rescue
    e ->
      require Logger
      Logger.warning("AshAi on_stream callback raised: #{Exception.message(e)}")
      :ok
  end

  defp insert_tool_call_row(resource, agent, %{id: id, name: name, arguments: args}) do
    messages_module = AshAi.Agent.Info.agent_messages!(resource)

    messages_module
    |> Ash.Changeset.for_create(:create, %{
      agent_id: agent.id,
      role: :tool_call,
      message: "#{name}(#{Jason.encode!(args)})",
      data: %{name: to_string(name), arguments: args},
      tool_call_id: to_string(id),
      pending: false,
      generation: agent.current_generation
    })
    |> Ash.create!()
  end

  defp insert_tool_result_row(resource, agent, %{id: id, result: result}) do
    messages_module = AshAi.Agent.Info.agent_messages!(resource)
    {message_text, data_value} = format_tool_result(result)

    messages_module
    |> Ash.Changeset.for_create(:create, %{
      agent_id: agent.id,
      role: :tool_result,
      message: message_text,
      data: data_value,
      tool_call_id: to_string(id),
      pending: false,
      generation: agent.current_generation
    })
    |> Ash.create!()
  end

  defp format_tool_result({:ok, json_str, _raw}) when is_binary(json_str),
    do: {json_str, decode_data(json_str)}

  defp format_tool_result({:error, json_err}) when is_binary(json_err),
    do: {json_err, %{"error" => json_err}}

  defp format_tool_result(text) when is_binary(text), do: {text, decode_data(text)}
  defp format_tool_result(other), do: {inspect(other), %{}}

  defp decode_data(json_str) do
    case Jason.decode(json_str) do
      {:ok, decoded} when is_map(decoded) -> decoded
      {:ok, decoded} -> %{"value" => decoded}
      _ -> %{"raw" => json_str}
    end
  end

  defp on_stream(resource) do
    case AshAi.Agent.Info.agent_on_stream(resource) do
      {:ok, callback} when not is_nil(callback) -> callback
      _ -> nil
    end
  end

  # Tool resolution is explicit-only: the agent's `tools [...]` list. Tools
  # declared on the agent's own resource OR on related-agent resources are
  # NOT auto-included — capabilities should always be a deliberate choice.
  defp resolve_tool_names(resource) do
    AshAi.Agent.Info.agent_tools!(resource)
  end

  # Default a generous max_tokens so the model can emit large structured tool
  # arguments (e.g. a summary into a `findings` field) without the response
  # stream being truncated mid-JSON. Provider defaults like Anthropic's 1024
  # are far too low for agents that summarize tool results into another tool
  # call. Callers can override via `req_llm_opts` on the agent DSL.
  @default_max_tokens 16_384

  defp build_req_llm_opts(resource) do
    base = [max_tokens: @default_max_tokens]

    case AshAi.Agent.Info.agent_tool_choice(resource) do
      {:ok, choice} when not is_nil(choice) -> [tool_choice: choice] ++ base
      _ -> base
    end
  end

  # Auto-add a `wait_on_agent` ReqLLM tool when the resource has at least one
  # relationship to another agent. Lets the LLM block on a peer's process
  # being free (i.e. its current turn finished) — useful for sync rendezvous
  # like "wait for my researcher to be done before I continue."
  defp build_extra_tools(resource, agent) do
    case peer_agent_relationships(resource) do
      [] -> []
      _ -> [wait_on_agent_tool(resource, agent)]
    end
  end

  # The tool closes over the calling agent's resource + id so its callback
  # can also surface any pending messages that arrived for the caller during
  # the wait. Otherwise the caller's current turn finishes blind to what
  # came in (the messages would be drained on the NEXT turn).
  defp wait_on_agent_tool(caller_resource, caller_agent) do
    caller_id = caller_agent.id

    {:ok, tool} =
      ReqLLM.Tool.new(
        name: "wait_on_agent",
        description: """
        Block until another agent's process is responsive (its current turn
        has finished). Useful when you've spawned or messaged another agent
        and want to wait for it to be done before continuing. The result
        also includes any messages that arrived for you during the wait.
        """,
        parameter_schema: [
          id: [type: :string, required: true, doc: "The target agent's id."],
          timeout_ms: [
            type: :integer,
            default: 180_000,
            doc: "Max wait in milliseconds. Default 3 minutes."
          ]
        ],
        callback: fn args ->
          target_id = args["id"] || args[:id]
          timeout = args["timeout_ms"] || args[:timeout_ms] || 180_000

          case AshAi.Agents.call(target_id, :ping, timeout) do
            {:ok, _} ->
              {:ok, render_wait_result(target_id, caller_resource, caller_id)}

            {:error, :not_running} ->
              {:ok,
               "Agent #{target_id} is not running (it may have completed and " <>
                 "stopped). " <> render_pending_section(caller_resource, caller_id)}

            {:error, :timeout} ->
              {:ok,
               "Agent #{target_id} is still working. Call wait_on_agent " <>
                 "again to keep waiting. " <>
                 render_pending_section(caller_resource, caller_id)}

            {:error, _} ->
              {:ok, "Wait on agent #{target_id} did not complete normally."}
          end
        end
      )

    tool
  end

  defp render_wait_result(target_id, caller_resource, caller_id) do
    "Agent #{target_id} is done with its current turn. " <>
      render_pending_section(caller_resource, caller_id)
  end

  defp render_pending_section(caller_resource, caller_id) do
    case read_pending_for(caller_resource, caller_id) do
      [] ->
        "(No new messages arrived for you during the wait.)"

      messages ->
        "While waiting, the following messages arrived for you:\n" <>
          Enum.map_join(messages, "\n\n", &render_pending_message/1)
    end
  end

  defp read_pending_for(resource, agent_id) do
    messages_module = AshAi.Agent.Info.agent_messages!(resource)

    messages_module
    |> Ash.Query.filter(agent_id == ^agent_id and pending == true)
    |> Ash.Query.sort(inserted_at: :asc)
    |> Ash.read!()
  end

  defp render_pending_message(%{role: role, sender_id: sender, message: text}) do
    "  - [#{role}#{if sender, do: " from #{sender}", else: ""}] #{text}"
  end

  defp load_peer_context(resource, agent) do
    peer_rels = peer_agent_relationships(resource)

    case peer_rels do
      [] ->
        {agent, []}

      rels ->
        agent = Ash.load!(agent, Enum.map(rels, & &1.name))
        {agent, rels}
    end
  end

  defp peer_agent_relationships(resource) do
    Ash.Resource.Info.relationships(resource)
    |> Enum.filter(fn rel ->
      rel.type in [:belongs_to, :has_one, :has_many] and
        agent_resource?(rel.destination)
    end)
  end

  defp agent_resource?(module) when is_atom(module) do
    AshAi.Agent in Spark.extensions(module)
  rescue
    _ -> false
  end

  defp agent_resource?(_), do: false

  defp build_system_prompt(base, resource, agent, peer_rels) do
    type = AshAi.Agent.Info.agent_type!(resource)

    state_json = Jason.encode!(public_state(agent), pretty: true)

    peers_section =
      case peer_rels do
        [] ->
          ""

        rels ->
          payload =
            rels
            |> Enum.map(fn rel ->
              {rel.name, format_peer_value(Map.get(agent, rel.name))}
            end)
            |> Map.new()
            |> Jason.encode!(pretty: true)

          "\n\nRelated agents:\n#{payload}"
      end

    """
    #{base}

    ---
    Your identity:
    - id: #{agent.id}
    - type: #{type}

    Your state:
    #{state_json}#{peers_section}
    """
  end

  defp public_state(agent) do
    resource = agent.__struct__

    Ash.Resource.Info.public_attributes(resource)
    |> Enum.reject(&(&1.name in [:id, :inserted_at, :updated_at]))
    |> Enum.map(fn attr -> {attr.name, jsonable(Map.get(agent, attr.name))} end)
    |> Map.new()
  end

  defp format_peer_value(%Ash.NotLoaded{}), do: nil
  defp format_peer_value(nil), do: nil
  defp format_peer_value(list) when is_list(list), do: Enum.map(list, &peer_summary/1)
  defp format_peer_value(struct), do: peer_summary(struct)

  defp peer_summary(%resource{} = record) do
    %{
      id: record.id,
      type: AshAi.Agent.Info.agent_type!(resource),
      state: public_state(record)
    }
  end

  defp jsonable(%Ash.NotLoaded{}), do: nil
  defp jsonable(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp jsonable(value) when is_atom(value) and not is_nil(value), do: to_string(value)
  defp jsonable(value), do: value

  defp build_context(messages, resource) do
    sender_lookup = build_sender_lookup(messages, resource)

    messages
    |> Enum.map(&to_req_llm_message(&1, sender_lookup))
    |> Enum.reject(&is_nil/1)
    |> ReqLLM.Context.new()
  end

  defp build_sender_lookup(messages, resource) do
    directory = AshAi.Agent.Info.agent_directory!(resource)

    sender_ids =
      messages
      |> Enum.filter(&(&1.role == :agent and not is_nil(&1.sender_id)))
      |> Enum.map(& &1.sender_id)
      |> Enum.uniq()

    case sender_ids do
      [] ->
        %{}

      ids ->
        directory
        |> Ash.Query.filter(id in ^ids)
        |> Ash.read!()
        |> Map.new(&{&1.id, &1.type})
    end
  end

  defp to_req_llm_message(%{role: :user, message: text}, _) when is_binary(text) and text != "",
    do: ReqLLM.Context.user(text)

  defp to_req_llm_message(%{role: :assistant, message: text}, _)
       when is_binary(text) and text != "",
       do: ReqLLM.Context.assistant(text)

  defp to_req_llm_message(%{role: :system, message: text}, _)
       when is_binary(text) and text != "",
       do: ReqLLM.Context.system(text)

  defp to_req_llm_message(
         %{role: :agent, sender_id: sender_id, message: text},
         sender_lookup
       )
       when is_binary(text) and text != "" do
    type = Map.get(sender_lookup, sender_id)

    sender_label =
      if type do
        ~s(##{type}{id: "#{sender_id}"})
      else
        ~s(agent #{sender_id})
      end

    payload =
      Jason.encode!(%{
        type: "agent_message_received",
        from: sender_label,
        content: text
      })

    ReqLLM.Context.system(payload)
  end

  defp to_req_llm_message(%{role: :event, message: text}, _)
       when is_binary(text) and text != "" do
    ReqLLM.Context.system(Jason.encode!(%{type: "event", content: text}))
  end

  defp to_req_llm_message(%{role: :summary, message: text}, _)
       when is_binary(text) and text != "",
       do: ReqLLM.Context.system(text)

  defp to_req_llm_message(_, _), do: nil

  defp insert_assistant_message(resource, agent, text, message_id, usage) do
    messages_module = AshAi.Agent.Info.agent_messages!(resource)
    {token_count, metadata} = usage_to_meta(usage)

    messages_module
    |> Ash.Changeset.for_create(:create, %{
      agent_id: agent.id,
      role: :assistant,
      message: text,
      pending: false,
      generation: agent.current_generation,
      token_count: token_count,
      metadata: metadata
    })
    |> Ash.Changeset.force_change_attribute(:id, message_id)
    |> Ash.create()
  end

  defp usage_to_meta(nil), do: {nil, %{}}

  defp usage_to_meta(usage) when is_map(usage) do
    input = numeric(Map.get(usage, :input_tokens) || Map.get(usage, "input_tokens"))
    output = numeric(Map.get(usage, :output_tokens) || Map.get(usage, "output_tokens"))
    total = numeric(Map.get(usage, :total_tokens) || Map.get(usage, "total_tokens"))

    {output,
     %{
       "usage" => %{
         "input_tokens" => input,
         "output_tokens" => output,
         "total_tokens" => total || ((input || 0) + (output || 0))
       }
     }}
  end

  defp numeric(n) when is_integer(n), do: n
  defp numeric(_), do: nil
end
