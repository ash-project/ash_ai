defmodule AshAi.Application do
  @moduledoc false
  use Application

  @impl true
  def start(_type, _args) do
    children = []

    # Register AshAi-specific capabilities with AshMcp
    if Code.ensure_loaded?(AshMcp.Registry) do
      Task.start_link(fn ->
        # Wait a bit for AshMcp to start
        Process.sleep(100)
        AshAi.Mcp.Registry.register_default_capabilities()
      end)
    end

    Supervisor.start_link(
      children,
      strategy: :one_for_one,
      name: AshAi.Supervisor
    )
  end
end
