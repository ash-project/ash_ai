# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Evaluate.TypesTest do
  use ExUnit.Case, async: true

  alias AshAi.Evaluate.{Choice, Judgments, Noul, Score}

  defmodule Department do
    use Ash.Type.Enum,
      values: [
        billing: "Payments, invoicing, refunds",
        technical: "Bugs, outages, integrations",
        sales: "Pricing, upgrades, new accounts"
      ]
  end

  describe "Choice" do
    test "init derives struct fields from an enum and keeps the custom constraints" do
      assert {:ok, constraints} = Ash.Type.init(Choice, of: Department)

      assert constraints[:of] == Department
      assert constraints[:instance_of] == Choice
      assert constraints[:fields][:value][:type] == Department
      assert constraints[:fields][:probabilities][:type] == Ash.Type.Map
      assert constraints[:fields][:confidence][:type] == Ash.Type.Float
    end

    test "init accepts :atom with one_of" do
      assert {:ok, constraints} =
               Ash.Type.init(Choice, of: :atom, constraints: [one_of: [:a, :b]])

      assert Choice.options(constraints) == [:a, :b]
    end

    test "init rejects types that do not define options" do
      assert {:error, message} = Ash.Type.init(Choice, of: :string)
      assert message =~ "must be an `Ash.Type.Enum`"

      assert {:error, _} = Ash.Type.init(Choice, of: :atom)
    end

    test "init is idempotent on already-initialized constraints" do
      assert {:ok, constraints} = Ash.Type.init(Choice, of: Department)
      assert {:ok, reinitialized} = Ash.Type.init(Choice, constraints)
      assert Enum.sort(reinitialized) == Enum.sort(constraints)
    end

    test "init rejects unknown constraints" do
      assert {:error, message} = Ash.Type.init(Choice, of: Department, levels: [])
      assert message =~ "Unknown options"
    end

    test "to_question uses enum descriptions as criteria and honors overrides" do
      {:ok, constraints} = Ash.Type.init(Choice, of: Department, descriptions: [sales: "Sales"])

      assert Choice.to_question("Which team?", constraints) == %{
               type: :choice,
               instructions: "Which team?",
               criteria: %{
                 "billing" => "Payments, invoicing, refunds",
                 "technical" => "Bugs, outages, integrations",
                 "sales" => "Sales"
               }
             }
    end

    test "from_answer casts the choice and probability keys, then casts into the struct" do
      {:ok, constraints} = Ash.Type.init(Choice, of: Department)

      answer = %{
        "type" => "choice",
        "choice" => "technical",
        "probabilities" => %{"billing" => 0.08, "technical" => 0.85, "sales" => 0.07},
        "confidence" => 0.82
      }

      assert {:ok, map} = Choice.from_answer(answer, constraints)
      assert {:ok, casted} = Ash.Type.cast_input(Choice, map, constraints)
      assert {:ok, %Choice{} = choice} = Ash.Type.apply_constraints(Choice, casted, constraints)

      assert choice.value == :technical
      assert choice.probabilities == %{billing: 0.08, technical: 0.85, sales: 0.07}
      assert choice.confidence == 0.82
    end

    test "from_answer rejects an option outside the set" do
      {:ok, constraints} = Ash.Type.init(Choice, of: Department)

      assert {:error, message} =
               Choice.from_answer(
                 %{"choice" => "legal", "probabilities" => %{}, "confidence" => 1.0},
                 constraints
               )

      assert message =~ "outside the defined set"
    end

    test "introspects as a struct NewType" do
      assert Ash.Type.NewType.new_type?(Choice)
      assert Ash.Type.NewType.subtype_of(Choice) == Ash.Type.Struct
    end
  end

  describe "Noul" do
    test "returns only the probability and never thresholds" do
      {:ok, constraints} = Ash.Type.init(Noul, [])

      assert {:ok, %{probability: 0.6}} =
               Noul.from_answer(%{"type" => "boolean", "probability" => 0.6}, constraints)

      assert {:ok, %{probability: 1.0}} = Noul.from_answer(%{"noul" => 1}, constraints)

      assert {:ok, casted} = Ash.Type.cast_input(Noul, %{probability: 0.6}, constraints)

      assert {:ok, %Noul{probability: 0.6} = noul} =
               Ash.Type.apply_constraints(Noul, casted, constraints)

      assert Noul.yes?(noul)
      refute Noul.yes?(noul, 0.7)
    end

    test "rejects a threshold constraint" do
      assert {:error, message} = Ash.Type.init(Noul, threshold: 0.7)
      assert message =~ "Unknown options"
    end

    test "to_question sends criteria when given" do
      {:ok, constraints} = Ash.Type.init(Noul, criteria: [true: "Time-sensitive", false: "Not"])

      assert Noul.to_question("Urgent?", constraints) == %{
               type: :boolean,
               instructions: "Urgent?",
               criteria: %{"true" => "Time-sensitive", "false" => "Not"}
             }

      {:ok, constraints} = Ash.Type.init(Noul, [])

      assert Noul.to_question("Urgent?", constraints) == %{
               type: :boolean,
               instructions: "Urgent?"
             }
    end
  end

  describe "Score" do
    test "requires at least two levels" do
      assert {:error, message} = Ash.Type.init(Score, levels: ["only"])
      assert message =~ "at least two"
    end

    test "resolves the nearest level and integer probability keys" do
      {:ok, constraints} = Ash.Type.init(Score, levels: ["Calm", "Frustrated", "Very angry"])

      answer = %{
        "type" => "score",
        "score" => 1.6,
        "legend" => %{"0" => "Calm", "1" => "Frustrated", "2" => "Very angry"},
        "probabilities" => %{"0" => 0.05, "1" => 0.3, "2" => 0.65},
        "confidence" => 0.78
      }

      assert {:ok, map} = Score.from_answer(answer, constraints)
      assert {:ok, casted} = Ash.Type.cast_input(Score, map, constraints)
      assert {:ok, %Score{} = score} = Ash.Type.apply_constraints(Score, casted, constraints)

      assert score.value == 1.6
      assert score.level == "Very angry"
      assert score.probabilities == %{0 => 0.05, 1 => 0.3, 2 => 0.65}
      assert score.confidence == 0.78

      assert Score.to_question("How frustrated?", constraints) == %{
               type: :score,
               instructions: "How frustrated?",
               criteria: ["Calm", "Frustrated", "Very angry"]
             }
    end
  end

  describe "Judgments" do
    test "expands plain field types into answer types and keeps descriptions" do
      assert {:ok, constraints} =
               Ash.Type.init(Judgments,
                 fields: [
                   department: [type: Department, description: "Which team?"],
                   kind: [
                     type: :atom,
                     constraints: [one_of: [:bug, :question]],
                     description: "Kind?"
                   ],
                   urgent: [type: :boolean, description: "Urgent?"],
                   frustration: [
                     type: Score,
                     constraints: [levels: ["Calm", "Angry"]],
                     description: "How frustrated?"
                   ]
                 ]
               )

      fields = constraints[:fields]

      assert fields[:department][:type] == Choice
      assert fields[:department][:constraints][:of] == Department
      assert fields[:department][:description] == "Which team?"

      assert fields[:kind][:type] == Choice
      assert fields[:kind][:constraints][:of] == Ash.Type.Atom
      assert fields[:kind][:constraints][:constraints][:one_of] == [:bug, :question]

      assert fields[:urgent][:type] == Noul
      assert fields[:urgent][:constraints][:fields][:probability][:type] == Ash.Type.Float

      assert fields[:frustration][:type] == Score
      assert fields[:frustration][:constraints][:levels] == ["Calm", "Angry"]
    end

    test "casts a full set of answers into structs" do
      {:ok, constraints} =
        Ash.Type.init(Judgments,
          fields: [
            department: [type: Department, description: "Which team?"],
            urgent: [type: :boolean, description: "Urgent?"]
          ]
        )

      value = %{
        department: %{value: :billing, probabilities: %{billing: 1.0}, confidence: 1.0},
        urgent: %{probability: 0.9}
      }

      assert {:ok, casted} = Ash.Type.cast_input(Judgments, value, constraints)
      assert {:ok, result} = Ash.Type.apply_constraints(Judgments, casted, constraints)

      assert %Choice{value: :billing} = result.department
      assert %Noul{probability: 0.9} = result.urgent
    end

    test "rejects field types it cannot derive a question for" do
      assert_raise ArgumentError, ~r/Cannot derive an evaluation question for field `name`/, fn ->
        Ash.Type.init(Judgments, fields: [name: [type: :string, description: "Name?"]])
      end
    end

    test "requires fields" do
      assert_raise ArgumentError, ~r/requires a non-empty `fields` constraint/, fn ->
        Ash.Type.init(Judgments, [])
      end
    end
  end
end
