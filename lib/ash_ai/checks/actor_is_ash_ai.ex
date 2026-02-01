# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Checks.ActorIsAshAi do
  @moduledoc "A check that is true when the actor is `%AshAi{}`"
  use Ash.Policy.SimpleCheck

  def describe(_), do: "actor is %AshAi{}"

  def match?(%AshAi{}, _, _), do: true
  def match?(_, _, _), do: false
end
