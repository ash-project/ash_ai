# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

ExUnit.start()

AshAi.TestRepo.start_link()
Ecto.Adapters.SQL.Sandbox.mode(AshAi.TestRepo, :manual)
