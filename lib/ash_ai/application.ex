defmodule AshAi.Application do
  @moduledoc false
  use Application

  @impl true
  def start(_type, _args) do
    Supervisor.start_link(
      [],
      strategy: :one_for_one,
      name: AshAi.Supervisor
    )
  end
end
