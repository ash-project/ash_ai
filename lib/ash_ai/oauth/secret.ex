# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Oauth.Secret do
  @moduledoc """
  Default `AshAuthentication.Secret` implementation.

  Reads the OAuth signing secret from the user's `runtime.exs` configuration.
  Users may swap this for their own secret module.

  The secret can be specified directly:

      config :my_app, AshAi.Oauth,
        signing_secret: "raw-secret-string"

  Or via env var:

      config :my_app, AshAi.Oauth,
        signing_secret: System.fetch_env!("MCP_SIGNING_SECRET")
  """

  if Code.ensure_loaded?(AshAuthentication) do
    @behaviour AshAuthentication.Secret

    @impl true
    def secret_for(_path, _resource, _opts, context) do
      otp_app = context[:otp_app] || raise "AshAi.Oauth.Secret requires :otp_app in context"

      case AshAi.Oauth.Config.signing_secret(otp_app) do
        {mod, opts} when is_atom(mod) -> mod.secret_for([], nil, opts, context)
        secret when is_binary(secret) -> {:ok, secret}
        other -> {:error, "Invalid signing_secret: #{inspect(other)}"}
      end
    end
  end
end
