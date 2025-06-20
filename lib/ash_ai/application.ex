defmodule AshAi.Application do
  @moduledoc false
  use Application

  @impl true
  def start(_type, _args) do
    children = []

    Supervisor.start_link(
      children,
      strategy: :one_for_one,
      name: AshAi.Supervisor
    )
  end
end
