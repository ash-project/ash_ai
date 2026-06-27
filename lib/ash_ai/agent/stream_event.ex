# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Agent.StreamEvent do
  @moduledoc """
  In-flight streaming event emitted during an agent turn.

  Passed to the `on_stream` callback configured on an `AshAi.Agent` resource.
  Lets the caller forward streaming text to a UI without AshAi needing to
  know anything about Phoenix or PubSub.

  Persisted rows (user/assistant/tool_call/tool_result messages) are
  published via the regular Ash notifier on the messages resource — this
  struct is for the in-flight pieces that don't correspond to a row.

  ## Types

    * `:start` — the turn has begun streaming. No `text`, no `message_id`.
    * `:delta` — accumulated content text so far. `text` is the cumulative
      string for the current iteration. `message_id` is the UUID that the
      assistant row will be persisted with — same ID for every delta of the
      iteration, so the UI can render a placeholder keyed by that id and
      merge incoming text into it.
    * `:done` — the turn finished. No `text`.
    * `:error` — something failed. `reason` set; `text` not set.

  ## Fields

    * `:type` — one of `:start | :delta | :done | :error`
    * `:agent_id` — the agent's id
    * `:agent_type` — the agent's type atom (from the DSL)
    * `:message_id` — UUID of the assistant row this delta belongs to
      (set on `:delta` only). The persisted row will use the same id.
    * `:text` — accumulated streaming text (only on `:delta`)
    * `:reason` — failure reason inspect-formatted (only on `:error`)
  """

  @type t :: %__MODULE__{
          type: :start | :delta | :done | :error,
          agent_id: binary(),
          agent_type: atom(),
          message_id: binary() | nil,
          text: String.t() | nil,
          reason: String.t() | nil
        }

  defstruct [:type, :agent_id, :agent_type, :message_id, :text, :reason]
end
