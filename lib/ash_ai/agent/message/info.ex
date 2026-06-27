# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Agent.Message.Info do
  @moduledoc "Introspection helpers for the AshAi.Agent.Message extension."

  use Spark.InfoGenerator,
    extension: AshAi.Agent.Message,
    sections: [:message]
end
