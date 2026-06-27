# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Agents.Directory.Info do
  @moduledoc "Introspection helpers for the AshAi.Agents.Directory extension."

  use Spark.InfoGenerator,
    extension: AshAi.Agents.Directory,
    sections: [:directory]
end
