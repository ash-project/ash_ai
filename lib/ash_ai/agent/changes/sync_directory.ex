# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Agent.Changes.SyncDirectory do
  @moduledoc """
  Keeps the configured `AshAi.Agents.Directory` resource in sync with this
  agent's lifecycle.

  Inserted as a global change on the agent resource by `AshAi.Agent.Transformer`
  when the agent's `directory` DSL option is set. Pattern-matches the action
  type and runs the appropriate hook:

    * `:create` — after the agent is created, insert a directory row with
      `id: agent.id, agent_resource: inspect(resource)`.
    * `:destroy` — before the agent is destroyed, delete the corresponding
      directory row.

  Other action types pass through unmodified.
  """
  use Ash.Resource.Change

  @impl true
  def change(changeset, _opts, _context) do
    case changeset.action_type do
      :create -> on_create(changeset)
      :destroy -> on_destroy(changeset)
      _ -> changeset
    end
  end

  defp on_create(changeset) do
    # `prepend?: true` so the directory row + DurableServer process are in
    # place BEFORE any action-specific after_actions run. Other hooks can
    # safely cast/look-up the agent's process or reference its directory id.
    Ash.Changeset.after_action(
      changeset,
      fn cs, agent ->
        directory_module = AshAi.Agent.Info.agent_directory!(cs.resource)
        type = AshAi.Agent.Info.agent_type!(cs.resource)

        directory_module
        |> Ash.Changeset.for_create(:create, %{id: agent.id, type: type})
        |> Ash.create!()

        AshAi.Agents.start(agent)

        {:ok, agent}
      end,
      prepend?: true
    )
  end

  defp on_destroy(changeset) do
    Ash.Changeset.before_action(changeset, fn cs ->
      directory_module = AshAi.Agent.Info.agent_directory!(cs.resource)
      agent_id = cs.data.id

      AshAi.Agents.stop(cs.data)

      case Ash.get(directory_module, agent_id) do
        {:ok, dir_record} -> Ash.destroy!(dir_record)
        {:error, _} -> :ok
      end

      cs
    end)
  end
end
