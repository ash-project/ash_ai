# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Test.EmbeddingModel do
  @moduledoc false
  use AshAi.EmbeddingModel
  require Logger

  @impl true
  def dimensions(_opts), do: 1536

  @impl true
  def generate(texts, _opts) do
    {:ok, Enum.map(texts, fn _ -> Enum.map(1..1536, fn _ -> 0.5 end) end)}
  end
end
