# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Actions.ResultTest do
  use ExUnit.Case, async: true

  alias AshAi.Actions.Result
  alias AshAi.Evaluate.{Noul, Score}

  defmodule FakePromptReqLLM do
    def generate_object(_model, _context, _schema, _opts) do
      {:ok,
       %{
         object: %{"result" => "positive"},
         model: "gpt-4o-2026-01-01",
         usage: %{input_tokens: 10, output_tokens: 2, total_tokens: 12},
         provider_meta: %{"id" => "chatcmpl-1"}
       }}
    end
  end

  defmodule FakeEvaluateReqLLM do
    def evaluate(_model, _state, questions, _opts) do
      answers =
        Map.new(questions, fn
          {id, %{type: :boolean}} ->
            {id, %{"type" => "boolean", "probability" => 0.9}}

          {id, %{type: :score}} ->
            {id,
             %{
               "type" => "score",
               "score" => 1.0,
               "probabilities" => %{"0" => 0.0, "1" => 1.0},
               "confidence" => 1.0
             }}
        end)

      {:ok,
       %{
         object: answers,
         model: "jev-1.13.0",
         usage: %{input_tokens: 312, output_tokens: 48, total_tokens: 360},
         provider_meta: %{operation: :evaluate}
       }}
    end
  end

  defmodule TestResource do
    use Ash.Resource,
      domain: AshAi.Actions.ResultTest.Domain,
      data_layer: Ash.DataLayer.Ets,
      extensions: [AshAi]

    ets do
      private? true
    end

    attributes do
      uuid_primary_key :id
    end

    actions do
      action :sentiment, AshAi.Actions.Result do
        constraints of: :atom, constraints: [one_of: [:positive, :negative]]
        argument :text, :string, allow_nil?: false

        run prompt("openai:gpt-4o", req_llm: FakePromptReqLLM, tools: false)
      end

      action :triage, AshAi.Actions.Result do
        argument :ticket, :string, allow_nil?: false

        constraints of: AshAi.Evaluate.Judgments,
                    constraints: [fields: [urgent: [type: :boolean, description: "Urgent?"]]]

        run evaluate("typesafe:jev-latest", req_llm: FakeEvaluateReqLLM)
      end

      action :rerank, AshAi.Actions.Result do
        argument :candidates, {:array, :string}, allow_nil?: false

        constraints of: {:array, AshAi.Evaluate.Score},
                    constraints: [items: [levels: ["No", "Yes"]]]

        run evaluate("typesafe:jev-latest",
              req_llm: FakeEvaluateReqLLM,
              questions: fn input, _ ->
                Enum.map(input.arguments.candidates, &"Is #{&1} good?")
              end
            )
      end
    end
  end

  defmodule Domain do
    use Ash.Domain

    resources do
      resource TestResource
    end
  end

  describe "the type" do
    test "derives struct fields from `of` and keeps the inner type initialized" do
      assert {:ok, constraints} =
               Result.init(of: AshAi.Evaluate.Score, constraints: [levels: ["a", "b"]])

      assert constraints[:instance_of] == Result
      assert constraints[:fields][:result][:type] == AshAi.Evaluate.Score
      assert constraints[:fields][:result][:constraints][:levels] == ["a", "b"]
      assert constraints[:fields][:result][:constraints][:instance_of] == AshAi.Evaluate.Score
      assert constraints[:fields][:model][:type] == Ash.Type.String

      assert {AshAi.Evaluate.Score, inner} = Result.unwrap(Result, constraints)
      assert inner[:levels] == ["a", "b"]
      assert {:string, [max_length: 3]} = Result.unwrap(:string, max_length: 3)
    end

    test "requires `of`" do
      assert {:error, message} = Ash.Type.init(Result, [])
      assert message =~ "requires the `of` constraint"
    end
  end

  describe "prompt actions" do
    test "return the value with model and usage" do
      result =
        TestResource
        |> Ash.ActionInput.for_action(:sentiment, %{text: "great"})
        |> Ash.run_action!()

      assert %Result{result: :positive, model: "gpt-4o-2026-01-01"} = result
      assert result.usage == %{input_tokens: 10, output_tokens: 2, total_tokens: 12}
      assert result.provider_meta == %{"id" => "chatcmpl-1"}
    end
  end

  describe "evaluate actions" do
    test "wrap judgments" do
      result =
        TestResource
        |> Ash.ActionInput.for_action(:triage, %{ticket: "help"})
        |> Ash.run_action!()

      assert %Result{result: %{urgent: %Noul{probability: 0.9}}, model: "jev-1.13.0"} = result
      assert result.usage.total_tokens == 360
      assert result.provider_meta == %{operation: :evaluate}
    end

    test "wrap dynamic arrays" do
      result =
        TestResource
        |> Ash.ActionInput.for_action(:rerank, %{candidates: ["a", "b"]})
        |> Ash.run_action!()

      assert %Result{result: [%Score{level: "Yes"}, %Score{level: "Yes"}], model: "jev-1.13.0"} =
               result
    end

    test "an empty question list wraps an empty result with no metadata" do
      result =
        TestResource
        |> Ash.ActionInput.for_action(:rerank, %{candidates: []})
        |> Ash.run_action!()

      assert %Result{result: [], model: nil, usage: nil} = result
    end
  end
end
