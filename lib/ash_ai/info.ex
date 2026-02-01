# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Info do
  @moduledoc "Introspection functions for the `AshAi` extension."
  use Spark.InfoGenerator, extension: AshAi, sections: [:tools, :vectorize, :mcp_resources]
end
