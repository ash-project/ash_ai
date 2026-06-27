# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Agent.Changes.ReceiveMessage do
  @moduledoc """
  Writes an incoming direct message into the receiving agent's Message table as
  a `pending: true` row. Used by an agent's "receive_message"-style update
  action.

  The role is determined automatically from the actor:

    * actor is an `AshAi.Agent` resource instance → `:agent` (and `sender_id`
      is set to the actor's id)
    * actor is anything else (a user struct, etc.) → `:user`
    * actor is `nil` → `:system`

  For non-message system events ("build finished", "timer fired", etc.) use
  `AshAi.Agent.Changes.ReceiveEvent` instead.

  ## Usage

      update :receive_message do
        accept []
        argument :message, :string, allow_nil?: false
        argument :data, :map
        change AshAi.Agent.Changes.ReceiveMessage
      end

  Caller passes the actor; the change handles the role.
  """
  use Ash.Resource.Change

  @impl true
  def change(changeset, _opts, context) do
    Ash.Changeset.after_action(changeset, fn changeset, agent ->
      message = Ash.Changeset.get_argument(changeset, :message)
      data = Ash.Changeset.get_argument(changeset, :data)
      actor = context.actor
      messages_module = AshAi.Agent.Info.agent_messages!(changeset.resource)

      attrs = %{
        agent_id: agent.id,
        sender_id: sender_id(actor),
        role: role_for_actor(actor),
        message: message,
        data: data,
        pending: true
      }

      case messages_module
           |> Ash.Changeset.for_create(:create, attrs, actor: actor)
           |> Ash.create() do
        {:ok, _row} ->
          AshAi.Agents.cast(agent.id, :check_inbox)
          {:ok, agent}

        {:error, error} ->
          {:error, error}
      end
    end)
  end

  defp role_for_actor(nil), do: :system

  defp role_for_actor(%mod{} = _actor) do
    if agent_resource?(mod), do: :agent, else: :user
  end

  defp role_for_actor(_), do: :user

  defp sender_id(%_mod{id: id}), do: id
  defp sender_id(_), do: nil

  defp agent_resource?(module) when is_atom(module) do
    AshAi.Agent in Spark.extensions(module)
  rescue
    _ -> false
  end

  defp agent_resource?(_), do: false
end
