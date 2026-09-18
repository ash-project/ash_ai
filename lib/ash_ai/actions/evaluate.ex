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

    The return type must be an answer type or a map of answer types:

    - `AshAi.Evaluate.Choice`, `AshAi.Evaluate.Noul`, or `AshAi.Evaluate.Score` asks
      one question. The action `description` is the question's instructions.
    - `AshAi.Evaluate.Judgments` (or `:map` whose fields are all answer types) asks one
      question per field in a single request. Each field's `description` is that
      question's instructions.

    ## Example

        action :triage, AshAi.Evaluate.Judgments do
          argument :ticket, :string, allow_nil?: false

          constraints fields: [
            department: [type: MyApp.Department, description: "Which team should handle `ticket`?"],
            urgent: [type: :boolean, description: "Does `ticket` convey urgency?"]
          ]

          run evaluate("typesafe:jev-latest")
        end

    ## Options

    - `:state` - Override the state. A string, map, or list, or a function
      `fn input, context -> state end` returning one.
    - `:req_llm` - Override the ReqLLM module (useful for testing with mocks).
    - `:req_llm_opts` - Additional options passed to `ReqLLM.evaluate/4`.

    ## Model specification

    The first argument to `evaluate/2` is a ReqLLM model specification such as
    `"typesafe:jev-latest"`, or a function returning one.
    """
    use Ash.Resource.Actions.Implementation

    alias AshAi.Evaluate.Answer

    @impl true
    def run(input, opts, context) do
      model = resolve_model_spec(opts[:model], input, context)
      req_llm = Keyword.get(opts, :req_llm, ReqLLM)
      req_llm_opts = Keyword.get(opts, :req_llm_opts, [])

      with {:ok, plan} <- plan(input.action),
           {:ok, state} <- build_state(input, opts, context),
           {:ok, questions} <- questions(plan),
           {:ok, response} <- req_llm.evaluate(model, state, questions, req_llm_opts),
           {:ok, answers} <- extract_answers(response),
           {:ok, result} <- collect(plan, answers),
           {:ok, casted} <- cast_result(result, input.action) do
        {:ok, casted}
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

    # A plan is either a single answer keyed by the action name, or one answer per
    # field of a map return type.
    defp plan(%{returns: nil}) do
      {:error, "evaluate actions must declare a return type"}
    end

    defp plan(%{returns: returns, constraints: constraints} = action) do
      cond do
        Answer.answer_type?(returns) ->
          case action.description do
            nil ->
              {:error,
               "action `#{action.name}` needs a `description`; it is sent to the model as the question's instructions"}

            description ->
              {:ok, {:single, action.name, description, Ash.Type.get_type(returns), constraints}}
          end

        Ash.Type.NewType.subtype_of(returns) == Ash.Type.Map ->
          fields = Ash.Type.NewType.constraints(returns, constraints)[:fields] || []
          plan_fields(action, fields)

        true ->
          {:error,
           "evaluate actions must return an answer type (`AshAi.Evaluate.Choice`, `AshAi.Evaluate.Noul`, `AshAi.Evaluate.Score`) or `AshAi.Evaluate.Judgments`, got: #{inspect(returns)}"}
      end
    end

    defp plan_fields(_action, []) do
      {:error, "evaluate actions returning a map need at least one field"}
    end

    defp plan_fields(action, fields) do
      fields
      |> Enum.reduce_while({:ok, []}, fn {name, config}, {:ok, acc} ->
        cond do
          not Answer.answer_type?(config[:type]) ->
            {:halt,
             {:error,
              "field `#{name}` of action `#{action.name}` is not an answer type; use `AshAi.Evaluate.Judgments` to derive answer types from plain field types"}}

          is_nil(config[:description]) ->
            {:halt,
             {:error,
              "field `#{name}` of action `#{action.name}` needs a `description`; it is sent to the model as the question's instructions"}}

          true ->
            {:cont,
             {:ok,
              [
                {name, config[:description], Ash.Type.get_type(config[:type]),
                 config[:constraints] || []}
                | acc
              ]}}
        end
      end)
      |> case do
        {:ok, questions} -> {:ok, {:fields, Enum.reverse(questions)}}
        {:error, error} -> {:error, error}
      end
    end

    defp questions({:single, name, instructions, type, constraints}) do
      {:ok, %{name => type.to_question(instructions, constraints)}}
    end

    defp questions({:fields, fields}) do
      {:ok,
       Map.new(fields, fn {name, instructions, type, constraints} ->
         {name, type.to_question(instructions, constraints)}
       end)}
    end

    defp extract_answers(%{object: answers}) when is_map(answers), do: {:ok, answers}
    defp extract_answers(answers) when is_map(answers), do: {:ok, answers}

    defp extract_answers(other),
      do: {:error, "unexpected evaluation response: #{inspect(other)}"}

    defp collect({:single, name, _instructions, type, constraints}, answers) do
      fetch_answer(answers, name, type, constraints)
    end

    defp collect({:fields, fields}, answers) do
      Enum.reduce_while(fields, {:ok, %{}}, fn {name, _instructions, type, constraints},
                                               {:ok, acc} ->
        case fetch_answer(answers, name, type, constraints) do
          {:ok, answer} -> {:cont, {:ok, Map.put(acc, name, answer)}}
          {:error, error} -> {:halt, {:error, error}}
        end
      end)
    end

    defp fetch_answer(answers, name, type, constraints) do
      case Map.fetch(answers, to_string(name)) do
        {:ok, answer} ->
          type.from_answer(answer, constraints)

        :error ->
          case Map.fetch(answers, name) do
            {:ok, answer} -> type.from_answer(answer, constraints)
            :error -> {:error, "no answer returned for question `#{name}`"}
          end
      end
    end

    defp cast_result(result, action) do
      with {:ok, value} <- Ash.Type.cast_input(action.returns, result, action.constraints),
           {:ok, value} <- Ash.Type.apply_constraints(action.returns, value, action.constraints) do
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
        fun when is_function(fun, 2) -> validate_state(fun.(input, context))
        fun when is_function(fun, 1) -> validate_state(fun.(input))
        fun when is_function(fun, 0) -> validate_state(fun.())
        state -> validate_state(state)
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
