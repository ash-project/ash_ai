# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Evaluate.Score do
  @moduledoc """
  An evaluation answer rating the state along ordered, described levels.

  The `levels` constraint is an ordered list of at least two level descriptions.
  Each level should describe a concrete situation and stand on its own.

  ## Fields

  - `value` - the probability-weighted position across the levels; may fall between two levels
  - `level` - the description of the level nearest to `value`
  - `probabilities` - each level index mapped to its probability
  - `confidence` - how concentrated the distribution is, from 0 to 1

  ## Example

      action :frustration, AshAi.Evaluate.Score do
        description "How frustrated is the customer in `ticket`?"
        constraints levels: ["Calm", "Frustrated but civil", "Very angry"]
        argument :ticket, :string, allow_nil?: false

        run evaluate("typesafe:jev-latest")
      end
  """

  defstruct [:value, :level, :probabilities, :confidence]

  @type t :: %__MODULE__{
          value: float(),
          level: String.t(),
          probabilities: %{non_neg_integer() => float()},
          confidence: float()
        }

  use AshAi.Evaluate.Answer,
    constraints: [
      levels: [
        type: {:list, :string},
        required: true,
        doc: "An ordered list of at least two level descriptions."
      ]
    ]

  @impl AshAi.Evaluate.Answer
  def answer_fields(constraints) do
    if length(constraints[:levels]) < 2 do
      {:error, "`levels` must contain at least two levels"}
    else
      {:ok,
       [
         value: [type: :float, allow_nil?: false],
         level: [type: :string, allow_nil?: false],
         probabilities: [type: :map, allow_nil?: false],
         confidence: [type: :float, allow_nil?: false]
       ]}
    end
  end

  @impl AshAi.Evaluate.Answer
  def to_question(instructions, constraints) do
    %{type: :score, instructions: instructions, criteria: constraints[:levels]}
  end

  @impl AshAi.Evaluate.Answer
  def from_answer(
        %{"score" => score, "probabilities" => probabilities, "confidence" => confidence},
        constraints
      )
      when is_number(score) and is_map(probabilities) do
    levels = constraints[:levels]
    index = score |> round() |> max(0) |> min(length(levels) - 1)

    probabilities =
      Map.new(probabilities, fn
        {key, probability} when is_binary(key) -> {String.to_integer(key), probability}
        {key, probability} -> {key, probability}
      end)

    {:ok,
     %{
       value: score / 1,
       level: Enum.at(levels, index),
       probabilities: probabilities,
       confidence: confidence
     }}
  end

  def from_answer(other, _constraints) do
    {:error, "expected a score answer, got: #{inspect(other)}"}
  end
end
