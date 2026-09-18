# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Evaluate.Score do
  @moduledoc """
  An evaluation answer rating the state along ordered, described levels.

  The `levels` constraint is an ordered list of at least two level descriptions.
  Each level should describe a concrete situation and stand on its own. Levels
  can instead be supplied per question through the `questions` option of
  `AshAi.Actions.Evaluate`.

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
        doc:
          "An ordered list of at least two level descriptions. Omit to supply levels per question."
      ]
    ]

  @impl AshAi.Evaluate.Answer
  def answer_fields(constraints) do
    with :ok <- validate_levels(constraints[:levels], true) do
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
  def to_question(instructions, nil, constraints) do
    case constraints[:levels] do
      nil ->
        {:error,
         "#{inspect(__MODULE__)} without a `levels` constraint needs levels supplied per question through the `questions` option"}

      levels ->
        {:ok, %{type: :score, instructions: instructions, criteria: levels}}
    end
  end

  def to_question(instructions, levels, _constraints) do
    with :ok <- validate_levels(levels, false) do
      {:ok, %{type: :score, instructions: instructions, criteria: levels}}
    end
  end

  @impl AshAi.Evaluate.Answer
  def from_answer(
        %{"score" => score, "probabilities" => probabilities, "confidence" => confidence} =
          answer,
        constraints
      )
      when is_number(score) and is_map(probabilities) do
    legend = answer["legend"] || %{}
    levels = constraints[:levels] || []
    count = max(map_size(legend), length(levels))
    index = score |> round() |> max(0) |> min(max(count - 1, 0))

    level = legend[Integer.to_string(index)] || Enum.at(levels, index)

    probabilities =
      Map.new(probabilities, fn
        {key, probability} when is_binary(key) -> {String.to_integer(key), probability}
        {key, probability} -> {key, probability}
      end)

    if is_nil(level) do
      {:error, "score answer has no legend and the type has no `levels`: #{inspect(answer)}"}
    else
      {:ok,
       %{value: score / 1, level: level, probabilities: probabilities, confidence: confidence}}
    end
  end

  def from_answer(other, _constraints) do
    {:error, "expected a score answer, got: #{inspect(other)}"}
  end

  defp validate_levels(nil, true), do: :ok
  defp validate_levels(levels, _) when is_list(levels) and length(levels) >= 2, do: :ok
  defp validate_levels(_, _), do: {:error, "`levels` must be a list of at least two levels"}
end
