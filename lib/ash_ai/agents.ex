# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Agents do
  @moduledoc """
  Public facade for the agent runtime.

  All callers of agent processes (lifecycle changes, message-receiving changes,
  external code) go through this module rather than touching DurableServer or
  EKV directly. This way the underlying registry/supervisor mechanics can be
  swapped without rippling into agent-behavior code.

  Backed by `DurableServer.Supervisor` registered as `AshAi.Agents.Supervisor`.
  """

  @supervisor AshAi.Agents.DurableSup

  @doc """
  Starts (or returns existing) a DurableServer process for the given agent
  record. Idempotent — safe to call repeatedly.
  """
  @spec start(struct()) :: {:ok, pid()} | {:error, term()}
  def start(%resource{id: agent_id}) do
    case DurableServer.Supervisor.ensure_started_child(
           @supervisor,
           {AshAi.Agent.Server, key: agent_id, initial_state: %{resource: resource}}
         ) do
      {:ok, {pid, _meta}} -> {:ok, pid}
      other -> other
    end
  end

  @doc """
  Stops the DurableServer process for the given agent (e.g. on destroy).
  """
  @spec stop(struct()) :: :ok
  def stop(%_{id: agent_id}) do
    case DurableServer.Supervisor.lookup(@supervisor, agent_id) do
      {pid, _meta} when is_pid(pid) ->
        DurableServer.Supervisor.terminate_child(@supervisor, pid)
        :ok

      _ ->
        :ok
    end
  end

  @doc """
  Looks up the running pid for an agent by id, returning `nil` if not running.
  """
  @spec whereis(binary()) :: pid() | nil
  def whereis(agent_id) do
    case DurableServer.Supervisor.lookup(@supervisor, agent_id) do
      {pid, _meta} when is_pid(pid) -> pid
      _ -> nil
    end
  end

  @doc """
  Casts a message to the running agent process. Returns `:ok` even if no
  process is running — silent no-op for now; callers can choose to wake the
  process via `start/1` first if they need stronger guarantees.
  """
  @spec cast(binary(), term()) :: :ok
  def cast(agent_id, msg) do
    case whereis(agent_id) do
      pid when is_pid(pid) -> GenServer.cast(pid, msg)
      _ -> :ok
    end
  end

  @doc """
  Synchronously calls the running agent process. Useful for `:ping`-style
  rendezvous when you want to wait for the target's current turn to complete
  (call blocks until the target's mailbox is processed up to your message).

  Returns `{:error, :not_running}` if no process exists, or
  `{:error, :timeout}` if the call times out.
  """
  @spec call(binary(), term(), timeout()) :: {:ok, term()} | {:error, term()}
  def call(agent_id, msg, timeout \\ 10_000) do
    case whereis(agent_id) do
      pid when is_pid(pid) ->
        try do
          {:ok, GenServer.call(pid, msg, timeout)}
        catch
          :exit, {:timeout, _} ->
            {:error, :timeout}

          :exit, {:normal, _} ->
            # Process completed normally during the call (e.g., on_complete
            # :stop terminated it). Treat as a successful completion — the
            # caller waited; the agent is done.
            {:ok, :done}

          :exit, {:noproc, _} ->
            # Process gone (likely destroyed via on_complete :destroy during
            # or just before the call). Also a successful completion.
            {:ok, :done}

          :exit, reason ->
            {:error, reason}
        end

      _ ->
        {:error, :not_running}
    end
  end
end
