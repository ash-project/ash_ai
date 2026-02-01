# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

import Config

config :ash,
  validate_domain_resource_inclusion?: false,
  validate_domain_config_inclusion?: false,
  disable_async?: true

config :ash_ai, AshAi.TestRepo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  database: "ash_ai_test",
  stacktrace: true,
  show_sensitive_data_on_connection_error: true,
  pool_size: 10,
  pool: Ecto.Adapters.SQL.Sandbox,
  log: false,
  prepare: :unnamed,
  types: AshAi.PostgrexTypes

config :ash_ai,
  ecto_repos: [AshAi.TestRepo],
  ash_domains: [AshAi.Test.Music]

config :ash_ai, :oban,
  testing: :manual,
  repo: AshAi.TestRepo,
  prefix: "private",
  plugins: [
    {Oban.Plugins.Cron, []}
  ],
  queues: [
    artist_oban_ash_ai_update_embeddings: 1
  ]
