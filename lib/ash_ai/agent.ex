# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Agent do
  @moduledoc """
  Resource extension that turns an Ash resource into an LLM-powered agent.

  Add this extension to a resource alongside an `agent do ... end` block:

      defmodule MyApp.Agents.Chat do
        use Ash.Resource,
          domain: MyApp.Agents,
          extensions: [AshAi.Agent],
          data_layer: AshPostgres.DataLayer

        agent do
          system_prompt "You are a helpful assistant."
          model "anthropic:claude-haiku-4-5"
          messages MyApp.Agents.Message
        end

        postgres do
          table "chat_agents"
          repo MyApp.Repo
        end

        actions do
          defaults [:create, :read, :destroy]
        end
      end

  The extension injects:

    * `:id` — uuid_v7 primary key
    * `:current_generation` — integer, increments on compaction
    * `:state` — atom, one of `:idle | :working | :compacting | :stopped | :errored`
    * `:last_error` — string, set when `state` is `:errored`
    * `:updated_at` — update timestamp
    * `:run_turn` update action — takes a `:message` argument, inserts the user
      message into the linked Message resource, calls the LLM, and inserts the
      assistant response. Has `transaction? false` so long LLM calls don't hold
      a database transaction open.
    * `has_many :messages` relationship pointing at the configured Message resource

  ## DSL

  See `AshAi.Agent.Dsl` for the full DSL schema.
  """

  @agent_section %Spark.Dsl.Section{
    name: :agent,
    describe: "Configures the agent runtime for this resource.",
    schema: [
      type: [
        type: :atom,
        required: true,
        doc: ~S"""
        Symbolic agent type (e.g. `:chat`, `:researcher`). Used in framing so
        the LLM sees agent kinds without exposing module paths. Must be unique
        within the directory's agents list.
        """
      ],
      system_prompt: [
        type: :string,
        required: true,
        doc: "The system prompt prepended to every LLM call."
      ],
      model: [
        type: :string,
        required: true,
        doc: ~S"""
        The model spec passed to `req_llm`, e.g. `"anthropic:claude-haiku-4-5"`.
        """
      ],
      messages: [
        type: {:spark, Ash.Resource},
        required: true,
        doc: "The Message resource used as this agent's conversation log."
      ],
      on_stream: [
        type: {:or, [:mfa, {:fun, 1}, {:tuple, [:atom, :atom]}]},
        required: false,
        doc: ~S"""
        Optional callback invoked for streaming events during a turn (token
        deltas, start/done/error). AshAi does not know about Phoenix or any
        broadcast mechanism — the callback is where you wire that up if you
        want it. Receives one `%AshAi.Agent.StreamEvent{}` per call.

        Forms accepted:

          * `{Module, :function}` — called as `Module.function(event)`
          * `{Module, :function, extra_args}` — called as
            `apply(Module, function, [event | extra_args])`
          * `fn event -> ... end` — anonymous one-arg function

        Row-level updates (user/assistant/tool_call/tool_result inserts) are
        published via the regular Ash notifier on the messages resource —
        configure `Ash.Notifier.PubSub` there if you want to subscribe to
        those.
        """
      ],
      directory: [
        type: {:spark, Ash.Resource},
        required: true,
        doc: ~S"""
        The polymorphic agent directory resource (using
        `AshAi.Agents.Directory`). The agent auto-inserts a directory row on
        create (with matching id) and removes it on destroy. The directory
        entry is the canonical identity record for cross-agent references and
        policies.
        """
      ],
      tools: [
        type: {:list, :atom},
        default: [],
        doc: ~S"""
        List of tool names this agent can call. Tools must be declared via
        AshAi's resource-level or domain-level `tools do ... end` block; this
        is just a name-based filter referencing those declarations.
        """
      ],
      tool_choice: [
        type: :any,
        required: false,
        doc: ~S"""
        Optional tool-choice strategy passed to the LLM. Values are
        provider-specific via `req_llm`; common ones:

        * `:auto` (default if unset) — model decides whether to call a tool
        * `:any` — model MUST call a tool every turn (no plain-text responses)
        * `:required` — alias for `:any` on some providers

        Useful for sub-agents that should always communicate via tools (e.g.
        a researcher that must always end with `send_message_to_chat`).
        """
      ],
      on_complete: [
        type: {:in, [:wait, :destroy, :stop]},
        default: :wait,
        doc: ~S"""
        What to do when a turn ends with nothing left to do (no pending
        events, no continuations). Options:

        * `:wait` (default) — process stays alive, idle, waiting for the next
          message or event.
        * `:destroy` — destroy the agent record (which terminates the
          DurableServer process via the directory-sync hook). Useful for
          one-shot agents that report their result via messages and exit.
        * `:stop` — stop the DurableServer process but keep the record.
          Useful for sub-agents that save results to their own record (via
          a `record_findings`-style action) and let the parent read the
          record afterwards.
        """
      ]
    ]
  }

  @compaction_section %Spark.Dsl.Section{
    name: :compaction,
    describe: """
    Configures memory-era compaction. When the agent's input-token usage
    crosses the configured threshold, the next turn pauses to summarize the
    current generation's messages, writes a `:summary` row at the next
    generation, increments `:current_generation`, and continues working from
    the new generation.

    Defaults trigger compaction at 80% of the model's context window with a
    generic summarization prompt. Disable by setting `on: :never`.
    """,
    schema: [
      on: [
        type:
          {:or,
           [
             {:literal, :never},
             {:tuple, [{:literal, :percentage}, :float]},
             {:tuple, [{:literal, :token_threshold}, :pos_integer]}
           ]},
        default: {:percentage, 0.8},
        doc: ~S"""
        When to trigger compaction:

        * `{:percentage, fraction}` — trigger when input tokens exceed
          `fraction * model.limits.context`. `fraction` is between 0 and 1.
        * `{:token_threshold, n}` — trigger when input tokens exceed `n`
          (absolute).
        * `:never` — disable compaction.
        """
      ],
      prompt: [
        type: :string,
        default: """
        Summarize the conversation so far for compaction. Produce a dense
        summary that preserves: key facts learned, decisions made, current
        goals, outstanding tasks, and important context the assistant needs
        to continue. Drop low-value chatter and verbose tool output unless
        the result itself is the answer. Write in third person as a
        recollection of what happened, not a transcript.
        """,
        doc: """
        System prompt used to instruct the model during compaction. The
        message history of the current generation is sent as the user input.
        """
      ]
    ]
  }

  use Spark.Dsl.Extension,
    sections: [@agent_section, @compaction_section],
    transformers: [AshAi.Agent.Transformer],
    verifiers: [AshAi.Agent.Verifiers.InDirectory]
end
