# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Evaluate.Judgments do
  @moduledoc """
  A map of evaluation answers, one per field, asked together in a single request.

  Declare the collapsed type you care about for each field and it is expanded
  into the matching answer type at compile time, so the result keeps
  probabilities and confidence for every judgment:

  - an `Ash.Type.Enum`, or `:atom` with `one_of`, becomes `AshAi.Evaluate.Choice`
  - `:boolean` becomes `AshAi.Evaluate.Noul`
  - an answer type such as `AshAi.Evaluate.Score` is kept as is

  Each field's `description` is the question's instructions.

  ## Example

      action :triage, AshAi.Evaluate.Judgments do
        argument :ticket, :string, allow_nil?: false

        constraints fields: [
          department: [type: MyApp.Department, description: "Which team should handle `ticket`?"],
          urgent: [type: :boolean, description: "Does `ticket` convey urgency?"],
          frustration: [
            type: AshAi.Evaluate.Score,
            constraints: [levels: ["Calm", "Frustrated but civil", "Very angry"]],
            description: "How frustrated is the customer in `ticket`?"
          ]
        ]

        run evaluate("typesafe:jev-latest")
      end

  The result is a map of answer structs:

      %{
        department: %AshAi.Evaluate.Choice{value: :technical, confidence: 0.82, probabilities: %{...}},
        urgent: %AshAi.Evaluate.Noul{probability: 0.92},
        frustration: %AshAi.Evaluate.Score{value: 1.6, level: "Frustrated but civil", ...}
      }
  """

  use Ash.Type.NewType, subtype_of: :map, constraints: []

  alias AshAi.Evaluate.Answer

  @impl Ash.Type.NewType
  def type_constraints(constraints, subtype_constraints) do
    constraints = super(constraints, subtype_constraints)

    case Keyword.fetch(constraints, :fields) do
      {:ok, fields} when is_list(fields) and fields != [] ->
        Keyword.put(constraints, :fields, Enum.map(fields, &expand_field/1))

      _ ->
        raise ArgumentError,
              "#{inspect(__MODULE__)} requires a non-empty `fields` constraint, one per question"
    end
  end

  defp expand_field({name, config}) do
    type = Ash.Type.get_type(config[:type])
    inner = config[:constraints] || []

    cond do
      Answer.answer_type?(type) ->
        {name, config}

      Spark.implements_behaviour?(type, Ash.Type.Enum) or type == Ash.Type.Atom ->
        {name,
         config
         |> Keyword.put(:type, AshAi.Evaluate.Choice)
         |> Keyword.put(:constraints, of: type, constraints: inner)}

      type == Ash.Type.Boolean ->
        {name,
         config
         |> Keyword.put(:type, AshAi.Evaluate.Noul)
         |> Keyword.put(:constraints, [])}

      true ->
        raise ArgumentError, """
        Cannot derive an evaluation question for field `#{name}` of type #{inspect(config[:type])}.

        Use an `Ash.Type.Enum` or `:atom` with `one_of` for a choice, `:boolean` for a
        yes/no probability, or an explicit answer type such as `AshAi.Evaluate.Score`.
        """
    end
  end
end
