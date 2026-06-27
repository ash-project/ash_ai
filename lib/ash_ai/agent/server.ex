# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Agent.Server do
  @moduledoc """
  Per-agent DurableServer process.

  One process per agent (keyed by agent id), lives across the cluster via
  `DurableServer.Supervisor`. Holds no in-process state of consequence — the
  agent's actual state (conversation, generation, etc.) lives in the agent's
  Ash resources.

  The server's job is purely to run turns when poked:

    * `cast(:check_inbox)` — drain pending events and run a turn if anything's
      new. Sent by `AshAi.Agent.Changes.ReceiveMessage` after writing a pending
      row.
    * `cast({:user_message, text})` — insert a user message and run a turn.
      Used by external callers (UI) to submit input.
  """
  use DurableServer, vsn: 1
  require Ash.Query

  @impl true
  def dump_state(state) do
    %{"resource" => Atom.to_string(state.resource)}
  end

  @impl true
  def load_state(_old_vsn, %{"resource" => resource_str}) do
    %{resource: String.to_existing_atom(resource_str)}
  end

  @impl true
  def init(state, info) do
    agent_id = info.key

    {:ok, Map.put(state, :agent_id, agent_id), permanent: true}
  end

  @impl true
  def handle_call(:ping, _from, state) do
    {:reply, :pong, state}
  end

  @impl true
  def handle_cast(:check_inbox, state) do
    run_turn(state, %{})
    finalize(state)
  end

  @impl true
  def handle_cast({:user_message, text}, state) do
    run_turn(state, %{message: text})
    finalize(state)
  end

  defp run_turn(state, args) do
    case Ash.get(state.resource, state.agent_id) do
      {:ok, agent} ->
        set_state(agent, %{state: :working, last_error: nil})

        case agent
             |> Ash.Changeset.for_update(:run_turn, args)
             |> Ash.update() do
          {:ok, _agent} ->
            reload_and_set_state(state, %{state: :idle, last_error: nil})

          {:error, error} ->
            reload_and_set_state(state, %{
              state: :errored,
              last_error: format_error(error)
            })
        end

      {:error, _} ->
        :ok
    end
  end

  defp reload_and_set_state(state, attrs) do
    case Ash.get(state.resource, state.agent_id) do
      {:ok, agent} -> set_state(agent, attrs)
      _ -> :ok
    end
  end

  defp set_state(agent, attrs) do
    agent
    |> Ash.Changeset.for_update(:update_lifecycle_state, attrs)
    |> Ash.update()
  rescue
    _ -> :ok
  end

  defp format_error(%{__struct__: _} = error) do
    try do
      Exception.message(error)
    rescue
      _ -> inspect(error, limit: 5)
    end
  end

  defp format_error(other), do: inspect(other, limit: 5)

  # End-of-turn lifecycle: pick what to do based on `on_complete` and whether
  # the agent has pending events. Returns the GenServer reply for handle_cast.
  defp finalize(state) do
    if no_pending?(state) do
      case AshAi.Agent.Info.agent_on_complete!(state.resource) do
        :destroy ->
          destroy_async(state)

        :stop ->
          reload_and_set_state(state, %{state: :stopped})
          {:stop, :normal, state}

        :wait ->
          {:noreply, state}
      end
    else
      {:noreply, state}
    end
  end

  defp destroy_async(state) do
    resource = state.resource
    agent_id = state.agent_id

    Task.start(fn ->
      Process.sleep(50)

      case Ash.get(resource, agent_id) do
        {:ok, agent} -> Ash.destroy(agent)
        {:error, _} -> :ok
      end
    end)

    {:noreply, state}
  end

  defp no_pending?(state) do
    messages_module = AshAi.Agent.Info.agent_messages!(state.resource)

    messages_module
    |> Ash.Query.filter(agent_id == ^state.agent_id and pending == true)
    |> Ash.read!()
    |> Enum.empty?()
  end
end
