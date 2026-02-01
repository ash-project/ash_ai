# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

Postgrex.Types.define(
  AshAi.PostgrexTypes,
  [AshPostgres.Extensions.Vector] ++ Ecto.Adapters.Postgres.extensions(),
  []
)

defmodule AshAi.TestRepo do
  @moduledoc """
  Repo for testing with AshPostgres
  """
  use AshPostgres.Repo, otp_app: :ash_ai

  def installed_extensions do
    ["uuid-ossp", "citext", "ash-functions", "vector"]
  end

  def on_transaction_begin(data) do
    send(self(), data)
  end

  def prefer_transaction?, do: false

  def prefer_transaction_for_atomic_updates?, do: false

  def min_pg_version do
    %Version{major: 16, minor: 0, patch: 0}
  end
end
