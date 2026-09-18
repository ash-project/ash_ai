# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

if Code.ensure_loaded?(ReqLLM) do
  defmodule AshAi.Actions.Evaluate do
    @moduledoc """
    A generic action impl that asks an evaluation model typed questions about the action's inputs.

    Evaluation models such as TypeSafe's Jev do not generate text. They take a
    `state` and a map of named, typed questions and return one typed answer per
    question, each with a probability distribution. This implementation maps an
    Ash action onto one such request:

    - the **state** is the action's arguments, as a JSON object keyed by argument name
    - the **questions** are derived from the action's return type
    - the **result** is the return type, cast from the answers

    ## Return types

    The return type must be an answer type, a map of answer types, or an array of
    an answer type:

    - `AshAi.Evaluate.Choice`, `AshAi.Evaluate.Noul`, or `AshAi.Evaluate.Score` asks
      one question. The action `description` is the question's instructions.
    - `AshAi.Evaluate.Judgments` (or `:map` whose fields are all answer types) asks one
      question per field in a single request. Each field's `description` is that
      question's instructions.
    - `{:array, answer_type}` asks a runtime-sized list of questions, one per entry
      returned by the `questions` option, and returns the answers in the same order.
    - `AshAi.Actions.Result` wrapping any of the above also returns the model that
      answered, token usage, and provider metadata.

    ## Example

        action :triage, AshAi.Evaluate.Judgments do
          argument :ticket, :string, allow_nil?: false

          constraints fields: [
            department: [type: MyApp.Department, description: "Which team should handle `ticket`?"],
            urgent: [type: :boolean, description: "Does `ticket` convey urgency?"]
          ]

          run evaluate("typesafe:jev-latest")
        end

    ## Dynamic questions

    The `questions` option supplies instructions (and optionally criteria) at
    runtime. It is a function `fn input, context -> questions end`, or a static
    value, shaped like the return type:

    - single answer type: one question
    - `Judgments` or map: a map of field name to question, overriding those fields'
      descriptions; unnamed fields keep their description
    - `{:array, answer_type}`: a list of questions, one per element

    A question is either instructions (a string, or a map or list for structured
    instructions), or a map with `:instructions` and `:criteria`. Criteria are the
    options of a Choice (a list, or a map of option to description), the levels of a
    Score, or the `true`/`false` descriptions of a Noul. Runtime criteria let the
    options differ per question; a Choice with an `of` constraint requires them to be
    a subset of its options, and a Choice without `of` returns string values.

        action :rerank, {:array, AshAi.Evaluate.Score} do
          argument :query, :string, allow_nil?: false
          argument :candidates, {:array, :string}, allow_nil?: false
          constraints items: [levels: ["Irrelevant", "Partially relevant", "Answers the query"]]

          run evaluate("typesafe:jev-latest",
            questions: fn input, _ctx ->
              input.arguments.candidates
              |> Enum.with_index()
              |> Enum.map(fn {_candidate, i} -> "How well does `candidates[\#{i}]` answer `query`?" end)
            end
          )
        end

    ## Options

    - `:questions` - Runtime questions, see above.
    - `:state` - Override the state. A string, map, or list, or a function
      `fn input, context -> state end` returning one.
    - `:req_llm` - Override the ReqLLM module (useful for testing with mocks).
    - `:req_llm_opts` - Additional options passed to `ReqLLM.evaluate/4`.

    ## Model specification

    The first argument to `evaluate/2` is a ReqLLM model specification such as
    `"typesafe:jev-latest"`, or a function returning one.
    """
    use Ash.Resource.Actions.Implementation

    alias AshAi.Actions.Result
    alias AshAi.Evaluate.Answer

    @impl true
    def run(input, opts, context) do
      model = resolve_model_spec(opts[:model], input, context)
      req_llm = Keyword.get(opts, :req_llm, ReqLLM)
      req_llm_opts = Keyword.get(opts, :req_llm_opts, [])

      action = input.action
      {returns, constraints} = Result.unwrap(action.returns, action.constraints)

      with {:ok, plan} <- plan(action, returns, constraints),
           {:ok, state} <- build_state(input, opts, context),
           {:ok, specs} <- resolve_questions(plan, opts, input, context),
           {:ok, questions} <- build_questions(specs),
           {:ok, answers, response} <- evaluate(req_llm, model, state, questions, req_llm_opts),
           {:ok, result} <- collect(plan, specs, answers),
           {:ok, casted} <- cast(result, returns, constraints) do
        if Result.wrapped?(action.returns) do
          cast(Result.wrap(casted, response), action.returns, action.constraints)
        else
          {:ok, casted}
        end
      else
        {:error, %{__exception__: true} = error} -> {:error, error}
        {:error, error} -> {:error, Ash.Error.Unknown.UnknownError.exception(error: error)}
      end
    end

    defp resolve_model_spec(model, input, context) when is_function(model, 2),
      do: resolve_model_spec(model.(input, context), input, context)

    defp resolve_model_spec(model, input, context) when is_function(model, 1),
      do: resolve_model_spec(model.(input), input, context)

    defp resolve_model_spec(model, _input, _context) when is_function(model, 0), do: model.()
    defp resolve_model_spec(model, _input, _context), do: model

    # A plan describes where questions come from and how answers map back onto the
    # return type: a single answer, one answer per map field, or a list of answers.
    defp plan(_action, nil, _constraints) do
      {:error, "evaluate actions must declare a return type"}
    end

    defp plan(_action, {:array, item_type} = returns, constraints) do
      if Answer.answer_type?(item_type) do
        {:ok, {:list, Ash.Type.get_type(item_type), constraints[:items] || []}}
      else
        unsupported_return(returns)
      end
    end

    defp plan(action, returns, constraints) do
      cond do
        Answer.answer_type?(returns) ->
          {:ok,
           {:single, action.name, Ash.Type.get_type(returns), constraints, action.description}}

        Ash.Type.NewType.subtype_of(returns) == Ash.Type.Map ->
          fields = Ash.Type.NewType.constraints(returns, constraints)[:fields] || []
          plan_fields(action, fields)

        true ->
          unsupported_return(returns)
      end
    end

    defp unsupported_return(returns) do
      {:error,
       "evaluate actions must return an answer type (`AshAi.Evaluate.Choice`, `AshAi.Evaluate.Noul`, `AshAi.Evaluate.Score`), an array of one, `AshAi.Evaluate.Judgments`, or `AshAi.Actions.Result` wrapping one of those, got: #{inspect(returns)}"}
    end

    defp plan_fields(_action, []) do
      {:error, "evaluate actions returning a map need at least one field"}
    end

    defp plan_fields(action, fields) do
      Enum.reduce_while(fields, {:ok, []}, fn {name, config}, {:ok, acc} ->
        if Answer.answer_type?(config[:type]) do
          {:cont,
           {:ok,
            [
              {name, Ash.Type.get_type(config[:type]), config[:constraints] || [],
               config[:description]}
              | acc
            ]}}
        else
          {:halt,
           {:error,
            "field `#{name}` of action `#{action.name}` is not an answer type; use `AshAi.Evaluate.Judgments` to derive answer types from plain field types"}}
        end
      end)
      |> case do
        {:ok, fields} -> {:ok, {:fields, Enum.reverse(fields)}}
        {:error, error} -> {:error, error}
      end
    end

    # Question specs are `{id, type, constraints, instructions, criteria}`.
    defp resolve_questions(plan, opts, input, context) do
      given = resolve_option(opts[:questions], input, context)

      case {plan, given} do
        {{:single, name, type, constraints, description}, given} ->
          with {:ok, {instructions, criteria}} <-
                 question_spec(given, description, "action `#{name}`") do
            {:ok, [{name, type, constraints, instructions, criteria}]}
          end

        {{:fields, fields}, given} when is_nil(given) or is_map(given) or is_list(given) ->
          overrides = Map.new(given || [])
          field_names = Enum.map(fields, &elem(&1, 0))

          case Map.keys(overrides) -- field_names do
            [] ->
              Enum.reduce_while(fields, {:ok, []}, fn {name, type, constraints, description},
                                                      {:ok, acc} ->
                case question_spec(Map.get(overrides, name), description, "field `#{name}`") do
                  {:ok, {instructions, criteria}} ->
                    {:cont, {:ok, [{name, type, constraints, instructions, criteria} | acc]}}

                  {:error, error} ->
                    {:halt, {:error, error}}
                end
              end)
              |> case do
                {:ok, specs} -> {:ok, Enum.reverse(specs)}
                {:error, error} -> {:error, error}
              end

            unknown ->
              {:error,
               "`questions` names fields that are not in the return type: #{inspect(unknown)}"}
          end

        {{:fields, _}, given} ->
          {:error,
           "`questions` for a map return type must be a map of field name to question, got: #{inspect(given)}"}

        {{:list, _type, _constraints}, nil} ->
          {:error,
           "an array return type requires the `questions` option to supply one question per element"}

        {{:list, type, constraints}, given} when is_list(given) ->
          given
          |> Enum.with_index()
          |> Enum.reduce_while({:ok, []}, fn {question, index}, {:ok, acc} ->
            case question_spec(question, nil, "question #{index}") do
              {:ok, {instructions, criteria}} ->
                {:cont, {:ok, [{index, type, constraints, instructions, criteria} | acc]}}

              {:error, error} ->
                {:halt, {:error, error}}
            end
          end)
          |> case do
            {:ok, specs} -> {:ok, Enum.reverse(specs)}
            {:error, error} -> {:error, error}
          end

        {{:list, _, _}, given} ->
          {:error, "`questions` for an array return type must be a list, got: #{inspect(given)}"}
      end
    end

    defp resolve_option(value, input, context) when is_function(value, 2),
      do: value.(input, context)

    defp resolve_option(value, input, _context) when is_function(value, 1), do: value.(input)
    defp resolve_option(value, _input, _context) when is_function(value, 0), do: value.()
    defp resolve_option(value, _input, _context), do: value

    # A question is instructions, or a map with :instructions and optional :criteria.
    defp question_spec(nil, nil, subject) do
      {:error,
       "#{subject} needs a `description` or an entry in `questions`; it is sent to the model as the question's instructions"}
    end

    defp question_spec(nil, description, _subject), do: {:ok, {description, nil}}

    defp question_spec(%{instructions: instructions} = question, _default, _subject),
      do: {:ok, {instructions, Map.get(question, :criteria)}}

    defp question_spec(%{"instructions" => instructions} = question, _default, _subject),
      do: {:ok, {instructions, Map.get(question, "criteria")}}

    defp question_spec(question, _default, _subject) when is_list(question) do
      if Keyword.keyword?(question) and Keyword.has_key?(question, :instructions) do
        {:ok, {question[:instructions], question[:criteria]}}
      else
        {:ok, {question, nil}}
      end
    end

    defp question_spec(instructions, _default, _subject)
         when is_binary(instructions) or is_map(instructions),
         do: {:ok, {instructions, nil}}

    defp question_spec(other, _default, subject) do
      {:error, "#{subject} has invalid question: #{inspect(other)}"}
    end

    defp build_questions(specs) do
      Enum.reduce_while(specs, {:ok, %{}}, fn {id, type, constraints, instructions, criteria},
                                              {:ok, acc} ->
        case type.to_question(instructions, criteria, constraints) do
          {:ok, question} -> {:cont, {:ok, Map.put(acc, question_id(id), question)}}
          {:error, error} -> {:halt, {:error, "question `#{id}`: #{error}"}}
        end
      end)
    end

    defp question_id(id) when is_integer(id), do: "q#{id}"
    defp question_id(id), do: to_string(id)

    # TypeSafe rejects an empty question map; an empty list of questions has an
    # empty answer.
    defp evaluate(_req_llm, _model, _state, questions, _opts) when map_size(questions) == 0,
      do: {:ok, %{}, nil}

    defp evaluate(req_llm, model, state, questions, opts) do
      with {:ok, response} <- req_llm.evaluate(model, state, questions, opts) do
        extract_answers(response)
      end
    end

    defp extract_answers(%{object: answers} = response) when is_map(answers),
      do: {:ok, answers, response}

    defp extract_answers(answers) when is_map(answers), do: {:ok, answers, nil}

    defp extract_answers(other),
      do: {:error, "unexpected evaluation response: #{inspect(other)}"}

    defp collect({:single, _, _, _, _}, [spec], answers), do: fetch_answer(spec, answers)

    defp collect({:fields, _}, specs, answers) do
      Enum.reduce_while(specs, {:ok, %{}}, fn {name, _, _, _, _} = spec, {:ok, acc} ->
        case fetch_answer(spec, answers) do
          {:ok, answer} -> {:cont, {:ok, Map.put(acc, name, answer)}}
          {:error, error} -> {:halt, {:error, error}}
        end
      end)
    end

    defp collect({:list, _, _}, specs, answers) do
      Enum.reduce_while(specs, {:ok, []}, fn spec, {:ok, acc} ->
        case fetch_answer(spec, answers) do
          {:ok, answer} -> {:cont, {:ok, [answer | acc]}}
          {:error, error} -> {:halt, {:error, error}}
        end
      end)
      |> case do
        {:ok, list} -> {:ok, Enum.reverse(list)}
        {:error, error} -> {:error, error}
      end
    end

    defp fetch_answer({id, type, constraints, _, _}, answers) do
      key = question_id(id)

      case Map.fetch(answers, key) do
        {:ok, answer} -> type.from_answer(answer, constraints)
        :error -> {:error, "no answer returned for question `#{key}`"}
      end
    end

    defp cast(result, type, constraints) do
      with {:ok, value} <- Ash.Type.cast_input(type, result, constraints),
           {:ok, value} <- Ash.Type.apply_constraints(type, value, constraints) do
        {:ok, value}
      else
        {:error, error} ->
          {:error,
           "Failed to cast evaluation answers: #{inspect(error)}. Answers: #{inspect(result)}"}

        :error ->
          {:error, "Failed to cast evaluation answers: #{inspect(result)}"}
      end
    end

    defp build_state(input, opts, context) do
      case Keyword.get(opts, :state) do
        nil -> default_state(input)
        state -> validate_state(resolve_option(state, input, context))
      end
    end

    defp validate_state(state) when is_binary(state) or is_map(state) or is_list(state),
      do: {:ok, state}

    defp validate_state(other),
      do: {:error, "state must be a string, map, or list, got: #{inspect(other)}"}

    defp default_state(input) do
      Enum.reduce_while(input.action.arguments, {:ok, %{}}, fn argument, {:ok, acc} ->
        with {:ok, value} <- Ash.ActionInput.fetch_argument(input, argument.name),
             {:ok, dumped} <-
               Ash.Type.dump_to_embedded(argument.type, value, argument.constraints) do
          {:cont, {:ok, Map.put(acc, argument.name, dumped)}}
        else
          :error ->
            {:cont, {:ok, acc}}

          {:error, error} ->
            {:halt,
             {:error, "could not serialize argument `#{argument.name}`: #{inspect(error)}"}}
        end
      end)
    end
  end
else
  defmodule AshAi.Actions.Evaluate do
    @moduledoc "Requires the `req_llm` dependency."

    use Ash.Resource.Actions.Implementation

    @impl true
    def run(_input, _opts, _context),
      do: AshAi.Dependencies.require_req_llm!("`AshAi.Actions.Evaluate`")
  end
end
