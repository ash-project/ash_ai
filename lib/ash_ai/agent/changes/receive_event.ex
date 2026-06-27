# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Agent.Changes.ReceiveEvent do
  @moduledoc """
  Writes a system event into the receiving agent's Message table as a
  `pending: true` row with role `:event`.

  Use for system-emitted notifications that aren't direct communication from
  another agent or user — e.g. timers firing, webhooks delivering, build
  pipelines reporting status. Sender is not tracked: events come from "the
  world," not from a specific addressed party.

  For direct messages from an agent or user, use
  `AshAi.Agent.Changes.ReceiveMessage` instead.

  ## Usage

      update :receive_event do
        accept []
        require_atomic? false
        argument :message, :string, allow_nil?: false
        argument :data, :map
        change AshAi.Agent.Changes.ReceiveEvent
      end
  """
  use Ash.Resource.Change

  @impl true
  def change(changeset, _opts, _context) do
    Ash.Changeset.after_action(changeset, fn changeset, agent ->
      message = Ash.Changeset.get_argument(changeset, :message)
      data = Ash.Changeset.get_argument(changeset, :data)
      messages_module = AshAi.Agent.Info.agent_messages!(changeset.resource)

      attrs = %{
        agent_id: agent.id,
        sender_id: nil,
        role: :event,
        message: message,
        data: data,
        pending: true
      }

      case messages_module
           |> Ash.Changeset.for_create(:create, attrs)
           |> Ash.create() do
        {:ok, _row} -> {:ok, agent}
        {:error, error} -> {:error, error}
      end
    end)
  end
end
