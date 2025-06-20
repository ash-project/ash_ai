defmodule AshMcp.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      # Starts a worker by calling: AshMcp.Worker.start_link(arg)
      # {AshMcp.Worker, arg}
      AshMcp.Registry,
      AshMcp.Session
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: AshMcp.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
