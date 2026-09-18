# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Evaluate.Choice do
  @moduledoc """
  An evaluation answer selecting one option from a defined set.

  The options come from one of two places:

  - the `of` constraint: an `Ash.Type.Enum`, or `:atom` with a `one_of`
    constraint. `value` is cast to that type and enum value descriptions become
    the criteria sent to the model.
  - criteria supplied per question through the `questions` option of
    `AshAi.Actions.Evaluate`. Without `of`, `value` is a string. With `of`, the
    runtime criteria must be a subset of its options, which is how options can
    depend on earlier answers (for example, the children of a taxonomy node).

  ## Fields

  - `value` - the selected option
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
        doc:
          "An `Ash.Type.Enum` module, or `:atom` used with a `one_of` constraint. Omit to supply criteria per question; `value` is then a string."
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
    with {:ok, type, inner} <- value_type(constraints) do
      {:ok,
       [
         value: [type: type, constraints: inner, allow_nil?: false],
         probabilities: [type: :map, allow_nil?: false],
         confidence: [type: :float, allow_nil?: false]
       ]}
    end
  end

  @impl AshAi.Evaluate.Answer
  def to_question(instructions, nil, constraints) do
    case constraints[:of] do
      nil ->
        {:error,
         "#{inspect(__MODULE__)} without an `of` constraint needs criteria supplied per question through the `questions` option"}

      _ ->
        options = options(constraints)
        {:ok, question(instructions, criteria_for(options, constraints))}
    end
  end

  def to_question(instructions, criteria, constraints) do
    with {:ok, criteria} <- normalize_criteria(criteria, constraints) do
      {:ok, question(instructions, criteria)}
    end
  end

  @impl AshAi.Evaluate.Answer
  def from_answer(
        %{"choice" => choice, "probabilities" => probabilities, "confidence" => confidence},
        constraints
      )
      when is_map(probabilities) do
    with {:ok, value} <- cast_option(choice, constraints),
         {:ok, probabilities} <- cast_probabilities(probabilities, constraints) do
      {:ok, %{value: value, probabilities: probabilities, confidence: confidence}}
    end
  end

  def from_answer(other, _constraints) do
    {:error, "expected a choice answer, got: #{inspect(other)}"}
  end

  defp options(constraints) do
    {:ok, type, inner} = value_type(constraints)
    {:ok, options} = options(type, inner)
    options
  end

  defp question(instructions, criteria) do
    %{type: :choice, instructions: instructions, criteria: criteria}
  end

  defp value_type(constraints) do
    case constraints[:of] do
      nil ->
        {:ok, Ash.Type.String, []}

      of ->
        type = Ash.Type.get_type(of)
        inner = constraints[:constraints] || []

        with {:ok, _options} <- options(type, inner) do
          {:ok, type, inner}
        end
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

  # Criteria may be a list of options, or a map/keyword of option => description.
  defp normalize_criteria(criteria, constraints) when is_list(criteria) do
    if Keyword.keyword?(criteria) and criteria != [] do
      normalize_criteria(Map.new(criteria), constraints)
    else
      normalize_criteria(Map.new(criteria, &{&1, nil}), constraints)
    end
  end

  defp normalize_criteria(criteria, constraints) when is_map(criteria) do
    cond do
      map_size(criteria) == 0 ->
        {:error, "choice criteria must not be empty"}

      is_nil(constraints[:of]) ->
        {:ok, criteria_for(Map.keys(criteria), constraints, criteria)}

      true ->
        criteria
        |> Map.keys()
        |> Enum.reduce_while({:ok, []}, fn option, {:ok, acc} ->
          case cast_option(option, constraints) do
            {:ok, value} -> {:cont, {:ok, [value | acc]}}
            {:error, error} -> {:halt, {:error, error}}
          end
        end)
        |> case do
          {:ok, options} -> {:ok, criteria_for(Enum.reverse(options), constraints, criteria)}
          {:error, error} -> {:error, error}
        end
    end
  end

  defp normalize_criteria(other, _constraints) do
    {:error,
     "choice criteria must be a list of options or a map of option => description, got: #{inspect(other)}"}
  end

  defp criteria_for(options, constraints, given \\ %{}) do
    given = Map.new(given, fn {k, v} -> {to_string(k), v} end)
    overrides = Map.new(constraints[:descriptions] || [], fn {k, v} -> {to_string(k), v} end)
    {:ok, type, _inner} = value_type(constraints)

    Map.new(options, fn option ->
      key = to_string(option)
      {key, Map.get(given, key) || Map.get(overrides, key) || default_description(type, option)}
    end)
  end

  defp default_description(type, option) do
    if Spark.implements_behaviour?(type, Ash.Type.Enum) do
      type.description(option)
    end
  end

  defp cast_option(option, constraints) do
    {:ok, type, inner} = value_type(constraints)

    case Ash.Type.cast_input(type, option, inner) do
      {:ok, value} when not is_nil(value) ->
        {:ok, value}

      _ ->
        {:error, "option is outside the set defined by `of`: #{inspect(option)}"}
    end
  end

  defp cast_probabilities(probabilities, constraints) do
    Enum.reduce_while(probabilities, {:ok, %{}}, fn {option, probability}, {:ok, acc} ->
      case cast_option(option, constraints) do
        {:ok, value} -> {:cont, {:ok, Map.put(acc, value, probability)}}
        {:error, error} -> {:halt, {:error, error}}
      end
    end)
  end
end
