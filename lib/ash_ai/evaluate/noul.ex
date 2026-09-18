# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Evaluate.Noul do
  @moduledoc """
  An evaluation answer giving the probability that a yes/no question is true.

  A noul is TypeSafe's yes/no question type. The model returns a single number
  from 0 (no) to 1 (yes). Near 0.5 means yes and no are equally likely; it does
  not mean "medium". A noul has no separate confidence.

  No threshold is applied here. Decide what counts as a yes in your code, where
  the threshold can depend on the stakes.

  ## Fields

  - `probability` - the probability that the answer is yes

  ## Example

      action :urgent, AshAi.Evaluate.Noul do
        description "Does `ticket` convey urgency?"
        argument :ticket, :string, allow_nil?: false

        run evaluate("typesafe:jev-latest")
      end

      urgent = Ash.run_action!(input)
      if urgent.probability >= 0.8, do: page_on_call()
  """

  defstruct [:probability]

  @type t :: %__MODULE__{probability: float()}

  use AshAi.Evaluate.Answer,
    constraints: [
      criteria: [
        type: :keyword_list,
        keys: [
          true: [type: :string, doc: "What a yes means."],
          false: [type: :string, doc: "What a no means."]
        ],
        default: [],
        doc: "Optional descriptions of what a yes and a no mean."
      ]
    ]

  @impl AshAi.Evaluate.Answer
  def answer_fields(_constraints) do
    {:ok, [probability: [type: :float, allow_nil?: false]]}
  end

  @impl AshAi.Evaluate.Answer
  def to_question(instructions, criteria, constraints) do
    question = %{type: :boolean, instructions: instructions}

    case criteria || constraints[:criteria] do
      criteria when criteria in [nil, []] ->
        {:ok, question}

      criteria when is_list(criteria) or is_map(criteria) ->
        {:ok, Map.put(question, :criteria, Map.new(criteria, fn {k, v} -> {to_string(k), v} end))}

      other ->
        {:error, "noul criteria must describe `true` and `false`, got: #{inspect(other)}"}
    end
  end

  @impl AshAi.Evaluate.Answer
  def from_answer(%{"probability" => probability}, _constraints) when is_number(probability) do
    {:ok, %{probability: probability / 1}}
  end

  def from_answer(%{"noul" => probability}, constraints) when is_number(probability) do
    from_answer(%{"probability" => probability}, constraints)
  end

  def from_answer(other, _constraints) do
    {:error, "expected a noul answer, got: #{inspect(other)}"}
  end
end
