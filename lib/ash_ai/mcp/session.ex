defmodule AshAi.Mcp.Session do
  @moduledoc """
  Enhanced session management for MCP server.

  Provides comprehensive session lifecycle management with state tracking,
  automatic cleanup, and ETS-based storage for performance.

  This module now delegates to AshMcp.Session for core functionality.
  """

  @deprecated "Use AshMcp.Session instead"

  require Logger



  @doc """
  Starts the session manager process.
  """
  def start_link(opts \\ []) do
    if Code.ensure_loaded?(AshMcp.Session) do
      AshMcp.Session.start_link(opts)
    else
      {:error, :ash_mcp_not_available}
    end
  end

  @doc """
  Creates a new session.
  """
  def create_session(session_id \\ nil, opts \\ []) do
    if Code.ensure_loaded?(AshMcp.Session) do
      AshMcp.Session.create_session(session_id, opts)
    else
      {:error, :ash_mcp_not_available}
    end
  end

  @doc """
  Gets session information by ID.
  """
  def get_session(session_id) do
    if Code.ensure_loaded?(AshMcp.Session) do
      AshMcp.Session.get_session(session_id)
    else
      {:error, :ash_mcp_not_available}
    end
  end

  @doc """
  Updates session information.
  """
  def update_session(session_id, updates) when is_map(updates) do
    if Code.ensure_loaded?(AshMcp.Session) do
      AshMcp.Session.update_session(session_id, updates)
    else
      {:error, :ash_mcp_not_available}
    end
  end

  @doc """
  Updates the last activity timestamp for a session.
  """
  def touch_session(session_id) do
    if Code.ensure_loaded?(AshMcp.Session) do
      AshMcp.Session.touch_session(session_id)
    else
      {:error, :ash_mcp_not_available}
    end
  end

  @doc """
  Marks a session as initialized with negotiated capabilities.
  """
  def initialize_session(session_id, capabilities \\ %{}) do
    if Code.ensure_loaded?(AshMcp.Session) do
      AshMcp.Session.initialize_session(session_id, capabilities)
    else
      {:error, :ash_mcp_not_available}
    end
  end

  @doc """
  Terminates a session.
  """
  def terminate_session(session_id) do
    if Code.ensure_loaded?(AshMcp.Session) do
      AshMcp.Session.terminate_session(session_id)
    else
      {:error, :ash_mcp_not_available}
    end
  end

  @doc """
  Lists all active sessions.
  """
  def list_sessions do
    if Code.ensure_loaded?(AshMcp.Session) do
      AshMcp.Session.list_sessions()
    else
      []
    end
  end

  @doc """
  Lists sessions by status.
  """
  def list_sessions_by_status(status) do
    if Code.ensure_loaded?(AshMcp.Session) do
      AshMcp.Session.list_sessions_by_status(status)
    else
      []
    end
  end

  @doc """
  Cleans up expired sessions.
  """
  def cleanup_expired_sessions do
    if Code.ensure_loaded?(AshMcp.Session) do
      AshMcp.Session.cleanup_expired_sessions()
    else
      :ok
    end
  end

end
