# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule Mix.Tasks.AshAi.Install.Docs do
  @moduledoc false

  def short_doc do
    "Installs `AshAi`. Call with `mix igniter.install ash_ai`. Requires igniter to run."
  end

  def example do
    "mix ash_ai.install"
  end

  def long_doc do
    """
    #{short_doc()}

    ## Example

    ```bash
    #{example()}
    ```
    """
  end
end

if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.AshAi.Install do
    @shortdoc "#{__MODULE__.Docs.short_doc()}"

    @moduledoc __MODULE__.Docs.long_doc()

    use Igniter.Mix.Task

    @impl Igniter.Mix.Task
    def info(_argv, _composing_task) do
      %Igniter.Mix.Task.Info{
        group: :ash,
        schema: [
          yes: :boolean
        ],
        installs: [],
        example: __MODULE__.Docs.example()
      }
    end

    @impl Igniter.Mix.Task
    def igniter(igniter) do
      igniter
      |> Igniter.Project.Formatter.import_dep(:ash_ai)
      |> add_dev_mcp()
    end

    defp add_dev_mcp(igniter) do
      otp_app = Igniter.Project.Application.app_name(igniter)

      if igniter.args.options[:yes] do
        {igniter, routers} = Igniter.Libs.Phoenix.list_routers(igniter)
        router = Enum.at(routers, 0)

        if router do
          {igniter, endpoints} = Igniter.Libs.Phoenix.endpoints_for_router(igniter, router)
          endpoint = Enum.at(endpoints, 0)

          if endpoint do
            Mix.Tasks.AshAi.Gen.Mcp.add_plug_to_endpoint(igniter, endpoint, otp_app)
          else
            igniter
          end
        else
          igniter
        end
      else
        {igniter, router} =
          Igniter.Libs.Phoenix.select_router(
            igniter,
            "Which router's endpoint should we install the dev MCP in?"
          )

        if router do
          {igniter, endpoint} =
            Igniter.Libs.Phoenix.select_endpoint(
              igniter,
              router,
              "Which endpoint should we install the dev MCP in?"
            )

          if endpoint do
            Mix.Tasks.AshAi.Gen.Mcp.add_plug_to_endpoint(igniter, endpoint, otp_app)
          else
            igniter
          end
        else
          igniter
        end
      end
    end
  end
else
  defmodule Mix.Tasks.AshAi.Install do
    @shortdoc "#{__MODULE__.Docs.short_doc()} | Install `igniter` to use"

    @moduledoc __MODULE__.Docs.long_doc()

    use Mix.Task

    def run(_argv) do
      Mix.shell().error("""
      The task 'ash_ai.install' requires igniter. Please install igniter and try again.

      For more information, see: https://hexdocs.pm/igniter/readme.html#installation
      """)

      exit({:shutdown, 1})
    end
  end
end
