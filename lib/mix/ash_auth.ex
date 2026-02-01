# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

if Code.ensure_loaded?(AshAuthentication) && Code.ensure_loaded?(Igniter) do
  defmodule AshAi.AshAuth do
    @moduledoc false
    def setup_api_key_auth(igniter, router, user) do
      {igniter, defines?} =
        AshAuthentication.Igniter.defines_strategy(igniter, user, :api_key, :api_key)

      if defines? do
        igniter
      else
        Igniter.compose_task(igniter, "ash_authentication.add_strategy", [
          "api_key"
          | igniter.args.argv_flags
        ])
        |> Igniter.add_notice("""
        AshAI generated API key authentication strategy for #{inspect(user)}.
        To skip this, rerun with `--no-api-key`
        """)
      end
      |> Igniter.Libs.Phoenix.add_pipeline(
        :mcp,
        """
        plug AshAuthentication.Strategy.ApiKey.Plug,
          resource: #{inspect(user)},
          # Use `required?: false` to allow unauthenticated
          # users to connect, for example if some tools
          # are publicly accessible.
          required?: true
        """,
        router: router
      )
      |> then(&{&1, true})
    end
  end
else
  defmodule AshAi.AshAuth do
    @moduledoc false
    def setup_api_key_auth(igniter, _router, _user) do
      {igniter, false}
    end
  end
end
