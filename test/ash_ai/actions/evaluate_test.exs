# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Actions.EvaluateTest do
  use ExUnit.Case, async: true

  alias AshAi.Evaluate.{Choice, Noul, Score}

  defmodule Department do
    use Ash.Type.Enum,
      values: [
        billing: "Payments, invoicing, refunds",
        technical: "Bugs, outages, integrations",
        sales: "Pricing, upgrades, new accounts"
      ]
  end

  defmodule FakeReqLLM do
    @moduledoc "Fake ReqLLM that captures the request and answers every question"

    def evaluate(model, state, questions, opts) do
      send(self(), {:evaluate_called, model, state, questions, opts})

      answers =
        Map.new(questions, fn {id, question} ->
          {to_string(id), answer(question)}
        end)

      {:ok, %{object: answers}}
    end

    defp answer(%{type: :choice, criteria: criteria}) do
      [first | _] = criteria |> Map.keys() |> Enum.sort()

      %{
        "type" => "choice",
        "choice" => first,
        "probabilities" =>
          Map.new(criteria, fn {k, _} -> {k, if(k == first, do: 0.9, else: 0.05)} end),
        "confidence" => 0.88
      }
    end

    defp answer(%{type: :boolean}), do: %{"type" => "boolean", "probability" => 0.92}

    defp answer(%{type: :score, criteria: levels}) do
      %{
        "type" => "score",
        "score" => 1.6,
        "legend" => levels |> Enum.with_index() |> Map.new(fn {l, i} -> {to_string(i), l} end),
        "probabilities" => %{"0" => 0.05, "1" => 0.3, "2" => 0.65},
        "confidence" => 0.78
      }
    end
  end

  defmodule FakeReqLLMMissingAnswer do
    def evaluate(_model, _state, _questions, _opts), do: {:ok, %{object: %{}}}
  end

  defmodule FakeReqLLMError do
    def evaluate(_model, _state, _questions, _opts), do: {:error, "overloaded"}
  end

  defmodule TestResource do
    use Ash.Resource,
      domain: AshAi.Actions.EvaluateTest.TestDomain,
      data_layer: Ash.DataLayer.Ets,
      extensions: [AshAi]

    ets do
      private?(true)
    end

    attributes do
      uuid_v7_primary_key(:id)
    end

    actions do
      action :triage, AshAi.Evaluate.Judgments do
        argument(:ticket, :string, allow_nil?: false)
        argument(:refund_policy, :string)

        constraints fields: [
                      department: [
                        type: Department,
                        description: "Which team should handle `ticket`?"
                      ],
                      urgent: [type: :boolean, description: "Does `ticket` convey urgency?"],
                      frustration: [
                        type: AshAi.Evaluate.Score,
                        constraints: [levels: ["Calm", "Frustrated but civil", "Very angry"]],
                        description: "How frustrated is the customer in `ticket`?"
                      ]
                    ]

        run evaluate("typesafe:jev-latest",
              req_llm: FakeReqLLM,
              req_llm_opts: [receive_timeout: 5]
            )
      end

      action :department, AshAi.Evaluate.Choice do
        description("Which team should handle `ticket`?")
        constraints(of: Department)
        argument(:ticket, :string, allow_nil?: false)

        run evaluate(fn _input, _ctx -> "typesafe:jev-1.13.0" end, req_llm: FakeReqLLM)
      end

      action :urgent, AshAi.Evaluate.Noul do
        description("Does the text convey urgency?")
        argument(:ticket, :string, allow_nil?: false)

        run evaluate("typesafe:jev-latest",
              req_llm: FakeReqLLM,
              state: fn input, _ctx -> input.arguments.ticket end
            )
      end

      action :missing_answer, AshAi.Evaluate.Noul do
        description("Anything?")
        argument(:ticket, :string)

        run evaluate("typesafe:jev-latest", req_llm: FakeReqLLMMissingAnswer)
      end

      action :model_error, AshAi.Evaluate.Noul do
        description("Anything?")
        argument(:ticket, :string)

        run evaluate("typesafe:jev-latest", req_llm: FakeReqLLMError)
      end

      action :no_description, AshAi.Evaluate.Noul do
        argument(:ticket, :string)

        run evaluate("typesafe:jev-latest", req_llm: FakeReqLLM)
      end
    end
  end

  defmodule TestDomain do
    use Ash.Domain

    resources do
      resource(TestResource)
    end
  end

  describe "judgments return type" do
    test "sends the arguments as state and one question per field, in one request" do
      result =
        TestResource
        |> Ash.ActionInput.for_action(:triage, %{
          ticket: "Our API is down and we can't ship orders",
          refund_policy: "Duplicate charges are refundable"
        })
        |> Ash.run_action!()

      assert_receive {:evaluate_called, "typesafe:jev-latest", state, questions, opts}

      assert state == %{
               ticket: "Our API is down and we can't ship orders",
               refund_policy: "Duplicate charges are refundable"
             }

      assert opts == [receive_timeout: 5]

      assert questions == %{
               department: %{
                 type: :choice,
                 instructions: "Which team should handle `ticket`?",
                 criteria: %{
                   "billing" => "Payments, invoicing, refunds",
                   "technical" => "Bugs, outages, integrations",
                   "sales" => "Pricing, upgrades, new accounts"
                 }
               },
               urgent: %{type: :boolean, instructions: "Does `ticket` convey urgency?"},
               frustration: %{
                 type: :score,
                 instructions: "How frustrated is the customer in `ticket`?",
                 criteria: ["Calm", "Frustrated but civil", "Very angry"]
               }
             }

      assert %Choice{value: :billing, confidence: 0.88} = result.department
      assert result.department.probabilities == %{billing: 0.9, technical: 0.05, sales: 0.05}

      assert %Noul{probability: 0.92} = result.urgent

      assert %Score{value: 1.6, level: "Very angry", confidence: 0.78} = result.frustration
      assert result.frustration.probabilities == %{0 => 0.05, 1 => 0.3, 2 => 0.65}
    end
  end

  describe "single answer return types" do
    test "uses the action description as instructions and the action name as the question id" do
      result =
        TestResource
        |> Ash.ActionInput.for_action(:department, %{ticket: "refund please"})
        |> Ash.run_action!()

      assert_receive {:evaluate_called, "typesafe:jev-1.13.0", %{ticket: "refund please"},
                      %{
                        department: %{
                          type: :choice,
                          instructions: "Which team should handle `ticket`?"
                        }
                      }, []}

      assert %Choice{value: :billing} = result
    end

    test "state override" do
      result =
        TestResource
        |> Ash.ActionInput.for_action(:urgent, %{ticket: "HELP NOW"})
        |> Ash.run_action!()

      assert_receive {:evaluate_called, _, "HELP NOW", _, _}
      assert %Noul{probability: 0.92} = result
      assert Noul.yes?(result)
      refute Noul.yes?(result, 0.95)
    end
  end

  describe "errors" do
    test "missing answer" do
      assert {:error, error} =
               TestResource
               |> Ash.ActionInput.for_action(:missing_answer, %{ticket: "x"})
               |> Ash.run_action()

      assert Exception.message(error) =~ "no answer returned for question `missing_answer`"
    end

    test "model error is returned" do
      assert {:error, error} =
               TestResource
               |> Ash.ActionInput.for_action(:model_error, %{ticket: "x"})
               |> Ash.run_action()

      assert Exception.message(error) =~ "overloaded"
    end

    test "missing action description" do
      assert {:error, error} =
               TestResource
               |> Ash.ActionInput.for_action(:no_description, %{ticket: "x"})
               |> Ash.run_action()

      assert Exception.message(error) =~ "needs a `description`"
    end
  end
end
