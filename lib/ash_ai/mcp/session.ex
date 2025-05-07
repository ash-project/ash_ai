defmodule AshAi.Mcp.Session do
  @moduledoc """
  Manages MCP server sessions.

  This module handles session creation, retrieval, and cleanup.
  """

  use GenServer

  @doc """
  Start a new session process
  """
  def start_link(session_id) do
    GenServer.start_link(__MODULE__, %{session_id: session_id}, name: via_tuple(session_id))
  end

  @doc """
  Get a session by ID, starting it if it doesn't exist
  """
  def get_or_create(session_id) do
    case Registry.lookup(AshAi.Mcp.Registry, session_id) do
      [{pid, _}] ->
        {:ok, pid}

      [] ->
        DynamicSupervisor.start_child(
          AshAi.Mcp.SessionSupervisor,
          {__MODULE__, session_id}
        )
    end
  end

  @doc """
  Terminate a session
  """
  def terminate(session_id) do
    case Registry.lookup(AshAi.Mcp.Registry, session_id) do
      [{pid, _}] ->
        GenServer.stop(pid)
        :ok

      [] ->
        {:error, :not_found}
    end
  end

  @doc """
  Check if a session exists
  """
  def exists?(session_id) do
    case Registry.lookup(AshAi.Mcp.Registry, session_id) do
      [{_pid, _}] -> true
      [] -> false
    end
  end

  @doc """
  Store data in the session
  """
  def put(session_id, key, value) do
    with {:ok, pid} <- get_or_create(session_id) do
      GenServer.call(pid, {:put, key, value})
    end
  end

  @doc """
  Retrieve data from the session
  """
  def get(session_id, key) do
    with {:ok, pid} <- get_or_create(session_id) do
      GenServer.call(pid, {:get, key})
    end
  end

  # GenServer callbacks

  @impl true
  def init(state) do
    # Set up session state and possibly a timeout for cleanup
    {:ok, Map.put(state, :data, %{})}
  end

  @impl true
  def handle_call({:put, key, value}, _from, state) do
    new_data = Map.put(state.data, key, value)
    {:reply, :ok, %{state | data: new_data}}
  end

  @impl true
  def handle_call({:get, key}, _from, state) do
    value = Map.get(state.data, key)
    {:reply, {:ok, value}, state}
  end

  # Helper functions

  defp via_tuple(session_id) do
    {:via, Registry, {AshAi.Mcp.Registry, session_id}}
  end
end
