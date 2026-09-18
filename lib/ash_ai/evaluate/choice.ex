# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Evaluate.Choice do
  @moduledoc """
  An evaluation answer selecting one option from a defined set.

  The `of` constraint names the type that defines the options: an
  `Ash.Type.Enum`, or `:atom` with a `one_of` constraint. Enum value
  descriptions become the criteria sent to the model.

  ## Fields

  - `value` - the selected option, cast to the `of` type
  - `probabilities` - every option mapped to its probability
  - `confidence` - how concentrated the distribution is, from 0 to 1

  ## Example

      action :department, AshAi.Evaluate.Choice do
        description "Which team should handle `ticket`?"
        constraints of: MyApp.Department
        argument :ticket, :string, allow_nil?: false

        run evaluate("typesafe:jev-latest")
      end
  """

  defstruct [:value, :probabilities, :confidence]

  @type t :: %__MODULE__{
          value: term(),
          probabilities: %{term() => float()},
          confidence: float()
        }

  use AshAi.Evaluate.Answer,
    constraints: [
      of: [
        type: :any,
        required: true,
        doc: "An `Ash.Type.Enum` module, or `:atom` used with a `one_of` constraint."
      ],
      constraints: [
        type: :keyword_list,
        default: [],
        doc: "Constraints for the `of` type, for example `one_of: [:a, :b]`."
      ],
      descriptions: [
        type: :any,
        default: [],
        doc: "Descriptions of each option, keyed by option. Overrides enum value descriptions."
      ]
    ]

  @impl AshAi.Evaluate.Answer
  def answer_fields(constraints) do
    with {:ok, type, inner} <- resolve_of(constraints),
         {:ok, _options} <- options(type, inner) do
      {:ok,
       [
         value: [type: type, constraints: inner, allow_nil?: false],
         probabilities: [type: :map, allow_nil?: false],
         confidence: [type: :float, allow_nil?: false]
       ]}
    end
  end

  @impl AshAi.Evaluate.Answer
  def to_question(instructions, constraints) do
    {:ok, type, inner} = resolve_of(constraints)
    {:ok, options} = options(type, inner)
    overrides = Map.new(constraints[:descriptions] || [], fn {k, v} -> {to_string(k), v} end)

    criteria =
      Map.new(options, fn option ->
        key = to_string(option)
        {key, Map.get(overrides, key) || default_description(type, option)}
      end)

    %{type: :choice, instructions: instructions, criteria: criteria}
  end

  @impl AshAi.Evaluate.Answer
  def from_answer(
        %{"choice" => choice, "probabilities" => probabilities, "confidence" => confidence},
        constraints
      )
      when is_map(probabilities) do
    {:ok, type, inner} = resolve_of(constraints)

    with {:ok, value} <- cast_option(type, choice, inner),
         {:ok, probabilities} <- cast_probabilities(type, probabilities, inner) do
      {:ok, %{value: value, probabilities: probabilities, confidence: confidence}}
    end
  end

  def from_answer(other, _constraints) do
    {:error, "expected a choice answer, got: #{inspect(other)}"}
  end

  @doc "Returns the options defined by the `of` type."
  @spec options(Keyword.t()) :: [term()]
  def options(constraints) do
    {:ok, type, inner} = resolve_of(constraints)
    {:ok, options} = options(type, inner)
    options
  end

  defp resolve_of(constraints) do
    case constraints[:of] do
      nil ->
        {:error, "the `of` constraint is required"}

      of ->
        {:ok, Ash.Type.get_type(of), constraints[:constraints] || []}
    end
  end

  defp options(type, inner) do
    cond do
      Spark.implements_behaviour?(type, Ash.Type.Enum) ->
        {:ok, type.values()}

      type == Ash.Type.Atom and is_list(inner[:one_of]) and inner[:one_of] != [] ->
        {:ok, inner[:one_of]}

      true ->
        {:error,
         "`of` must be an `Ash.Type.Enum` or `:atom` with a non-empty `one_of` constraint, got: #{inspect(type)}"}
    end
  end

  defp default_description(type, option) do
    if Spark.implements_behaviour?(type, Ash.Type.Enum) do
      type.description(option)
    end
  end

  defp cast_option(type, option, inner) do
    case Ash.Type.cast_input(type, option, inner) do
      {:ok, value} -> {:ok, value}
      _ -> {:error, "model returned an option outside the defined set: #{inspect(option)}"}
    end
  end

  defp cast_probabilities(type, probabilities, inner) do
    Enum.reduce_while(probabilities, {:ok, %{}}, fn {option, probability}, {:ok, acc} ->
      case cast_option(type, option, inner) do
        {:ok, value} -> {:cont, {:ok, Map.put(acc, value, probability)}}
        {:error, error} -> {:halt, {:error, error}}
      end
    end)
  end
end
