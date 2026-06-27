# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Agent.Info do
  @moduledoc "Introspection helpers for the AshAi.Agent extension."

  use Spark.InfoGenerator,
    extension: AshAi.Agent,
    sections: [:agent, :compaction]
end
