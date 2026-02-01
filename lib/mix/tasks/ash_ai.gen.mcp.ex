# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule Mix.Tasks.AshAi.Gen.Mcp.Docs do
  @moduledoc false

  def short_doc do
    "Sets up an MCP server for your application"
  end

  def example do
    "mix ash_ai.gen.mcp --api-key"
  end

  def long_doc do
    """
    #{short_doc()}

    Adds an MCP server to your router.
    Sets up Api Key authentication if
    - `--no-api-key` is not provided
    - `AshAuthentication` is available.
    - The user module is defined

    ## Example

    ```bash
    #{example()}
    ```

    ## Options

    ## Flags

    * `--no-api-key` - Skip setting up api key authentication and adding it to the MCP server.
    * `--user` - The user to add api key auth to, if setting it up.
    """
  end
end

if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.AshAi.Gen.Mcp do
    @shortdoc "#{__MODULE__.Docs.short_doc()}"

    @moduledoc __MODULE__.Docs.long_doc()

    use Igniter.Mix.Task

    @impl Igniter.Mix.Task
    def info(_argv, _composing_task) do
      %Igniter.Mix.Task.Info{
        group: :ash_ai,
        example: __MODULE__.Docs.example(),
        composes: ["ash_authentication.add_strategy"],
        schema: [api_key: :boolean, user: :string],
        defaults: [api_key: true]
      }
    end

    @impl Igniter.Mix.Task
    def igniter(igniter) do
      api_key? = igniter.args.options[:api_key]

      otp_app = Igniter.Project.Application.app_name(igniter)

      {igniter, router} =
        Igniter.Libs.Phoenix.select_router(
          igniter,
          "Which router should Ash AI be installed into?"
        )

      {igniter, mcp_scope?} =
        maybe_setup_api_key_auth(igniter, router, api_key?)

      pipe_through =
        if mcp_scope? do
          "pipe_through :mcp"
        end

      if router do
        {igniter, endpoints} = Igniter.Libs.Phoenix.endpoints_for_router(igniter, router)
        endpoint = Enum.at(endpoints, 0)

        Igniter.Libs.Phoenix.add_scope(
          igniter,
          "/mcp",
          """
          #{pipe_through}

          forward "/", AshAi.Mcp.Router,
            tools: [
              # list your tools here
              # :tool1,
              # :tool2,
            ],
            # For many tools, you will need to set the `protocol_version_statement` to the older version.
            protocol_version_statement: "2024-11-05",
            otp_app: :#{otp_app}
          """,
          router: router
        )
        |> add_plug_to_endpoint(endpoint, otp_app)
      end
    end

    @doc false
    def add_plug_to_endpoint(igniter, endpoint, otp_app) do
      Igniter.Project.Module.find_and_update_module!(igniter, endpoint, fn zipper ->
        with {:ok, zipper} <- Igniter.Code.Common.move_to(zipper, &code_reloading?/1),
             {:ok, zipper} <- Igniter.Code.Common.move_to_do_block(zipper) do
          {:ok,
           Igniter.Code.Common.add_code(
             zipper,
             """
             plug AshAi.Mcp.Dev,
               # For many tools, you will need to set the `protocol_version_statement` to the older version.
               protocol_version_statement: "2024-11-05",
               otp_app: :#{otp_app},
               path: "/ash_ai/mcp"
             """,
             placement: :before
           )}
        else
          :error ->
            {:warning,
             """
             Could not find the section of your endpoint `#{inspect(endpoint)}` dedicated to dev plugs.
             We look for `if code_reloading? do`, but you may have customized this code.
             Please add the plug manually, for example:

             if code_relading?
             """}
        end
      end)
    end

    defp code_reloading?(zipper) do
      Igniter.Code.Function.function_call?(
        zipper,
        :if,
        2
      ) &&
        Igniter.Code.Function.argument_matches_predicate?(
          zipper,
          0,
          &Igniter.Code.Common.variable?(&1, :code_reloading?)
        )
    end

    defp user_module(igniter) do
      if igniter.args.options[:user] do
        {igniter, Igniter.Project.Module.parse(igniter.args.options[:user])}
      else
        default =
          Igniter.Project.Module.module_name(igniter, "Accounts.User")

        {exists?, igniter} = Igniter.Project.Module.module_exists(igniter, default)

        if exists? do
          {igniter, default}
        else
          {igniter, nil}
        end
      end
    end

    defp maybe_setup_api_key_auth(igniter, router, true) do
      {igniter, user} = user_module(igniter)

      if user do
        AshAi.AshAuth.setup_api_key_auth(igniter, router, user)
      else
        {igniter, false}
      end
    end

    defp maybe_setup_api_key_auth(igniter, _, _) do
      {igniter, false}
    end
  end
else
  defmodule Mix.Tasks.AshAi.Gen.Mcp do
    @shortdoc "#{__MODULE__.Docs.short_doc()} | Install `igniter` to use"

    @moduledoc __MODULE__.Docs.long_doc()

    use Mix.Task

    def run(_argv) do
      Mix.shell().error("""
      The task 'ash_ai.gen.mcp' requires igniter. Please install igniter and try again.

      For more information, see: https://hexdocs.pm/igniter/readme.html#installation
      """)

      exit({:shutdown, 1})
    end
  end
end
