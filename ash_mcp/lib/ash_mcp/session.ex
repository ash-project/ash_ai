defmodule AshMcp.Session do
  @moduledoc """
  Enhanced session management for MCP server.

  Provides comprehensive session lifecycle management with state tracking,
  automatic cleanup, and ETS-based storage for performance.
  """

  use GenServer
  require Logger

  @table_name :ash_mcp_sessions
  @cleanup_interval :timer.minutes(5)
  @default_timeout :timer.hours(1)

  defstruct [
    :id,
    :initialized_at,
    :last_activity,
    :capabilities,
    :client_info,
    :auth_context,
    :status,
    timeout: @default_timeout
  ]

  @type t :: %__MODULE__{
          id: String.t(),
          initialized_at: DateTime.t(),
          last_activity: DateTime.t(),
          capabilities: map(),
          client_info: map(),
          auth_context: map(),
          status: :initializing | :active | :terminated,
          timeout: pos_integer()
        }

  @doc """
  Starts the session manager process.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Creates a new session.
  """
  def create_session(session_id \\ nil, opts \\ []) do
    session_id = session_id || generate_session_id()
    timeout = opts[:timeout] || @default_timeout

    session = %__MODULE__{
      id: session_id,
      initialized_at: DateTime.utc_now(),
      last_activity: DateTime.utc_now(),
      capabilities: %{},
      client_info: opts[:client_info] || %{},
      auth_context: opts[:auth_context] || %{},
      status: :initializing,
      timeout: timeout
    }

    GenServer.call(__MODULE__, {:create_session, session})
  end

  @doc """
  Gets session information by ID.
  """
  def get_session(session_id) do
    case :ets.lookup(@table_name, session_id) do
      [{^session_id, session}] ->
        {:ok, session}

      [] ->
        {:error, :session_not_found}
    end
  end

  @doc """
  Updates session information.
  """
  def update_session(session_id, updates) when is_map(updates) do
    GenServer.call(__MODULE__, {:update_session, session_id, updates})
  end

  @doc """
  Updates the last activity timestamp for a session.
  """
  def touch_session(session_id) do
    update_session(session_id, %{last_activity: DateTime.utc_now()})
  end

  @doc """
  Marks a session as initialized with negotiated capabilities.
  """
  def initialize_session(session_id, capabilities \\ %{}) do
    updates = %{
      status: :active,
      capabilities: capabilities,
      last_activity: DateTime.utc_now()
    }

    update_session(session_id, updates)
  end

  @doc """
  Terminates a session.
  """
  def terminate_session(session_id) do
    GenServer.call(__MODULE__, {:terminate_session, session_id})
  end

  @doc """
  Lists all active sessions.
  """
  def list_sessions do
    :ets.tab2list(@table_name)
    |> Enum.map(fn {_id, session} -> session end)
  end

  @doc """
  Lists sessions by status.
  """
  def list_sessions_by_status(status) do
    list_sessions()
    |> Enum.filter(&(&1.status == status))
  end

  @doc """
  Cleans up expired sessions.
  """
  def cleanup_expired_sessions do
    GenServer.cast(__MODULE__, :cleanup_expired)
  end

  @doc """
  Generate a new session ID.
  """
  def generate_session_id do
    # Use Ash.UUIDv7.generate/0 if Ash is available, otherwise use a simple UUID
    if Code.ensure_loaded?(Ash.UUIDv7) do
      Ash.UUIDv7.generate()
    else
      # Fallback UUID generation
      :crypto.strong_rand_bytes(16)
      |> Base.encode64(padding: false)
      |> String.replace(["+", "/"], "")
      |> String.slice(0, 22)
    end
  end

  # GenServer callbacks

  @impl GenServer
  def init(_opts) do
    :ets.new(@table_name, [:named_table, :public, :set, read_concurrency: true])

    # Schedule periodic cleanup
    Process.send_after(self(), :cleanup_expired, @cleanup_interval)

    Logger.info("MCP Session Manager started")
    {:ok, %{}}
  end

  @impl GenServer
  def handle_call({:create_session, session}, _from, state) do
    :ets.insert(@table_name, {session.id, session})
    Logger.debug("Created MCP session: #{session.id}")
    {:reply, {:ok, session}, state}
  end

  @impl GenServer
  def handle_call({:update_session, session_id, updates}, _from, state) do
    case :ets.lookup(@table_name, session_id) do
      [{^session_id, session}] ->
        updated_session = struct(session, updates)
        :ets.insert(@table_name, {session_id, updated_session})
        Logger.debug("Updated MCP session: #{session_id}")
        {:reply, {:ok, updated_session}, state}

      [] ->
        {:reply, {:error, :session_not_found}, state}
    end
  end

  @impl GenServer
  def handle_call({:terminate_session, session_id}, _from, state) do
    case :ets.lookup(@table_name, session_id) do
      [{^session_id, session}] ->
        terminated_session = %{session | status: :terminated}
        :ets.insert(@table_name, {session_id, terminated_session})
        Logger.debug("Terminated MCP session: #{session_id}")
        {:reply, :ok, state}

      [] ->
        {:reply, {:error, :session_not_found}, state}
    end
  end

  @impl GenServer
  def handle_cast(:cleanup_expired, state) do
    cleanup_expired_sessions_internal()
    {:noreply, state}
  end

  @impl GenServer
  def handle_info(:cleanup_expired, state) do
    cleanup_expired_sessions_internal()

    # Schedule next cleanup
    Process.send_after(self(), :cleanup_expired, @cleanup_interval)
    {:noreply, state}
  end

  # Private functions

  defp cleanup_expired_sessions_internal do
    now = DateTime.utc_now()
    expired_count = 0

    list_sessions()
    |> Enum.reduce(expired_count, fn session, count ->
      time_since_activity = DateTime.diff(now, session.last_activity, :millisecond)

      if time_since_activity > session.timeout do
        :ets.delete(@table_name, session.id)
        Logger.debug("Cleaned up expired MCP session: #{session.id}")
        count + 1
      else
        count
      end
    end)
    |> case do
      0 ->
        :ok

      count ->
        Logger.info("Cleaned up #{count} expired MCP sessions")
    end
  end
end
