# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.LiveLLM.StructuredOutputTest do
  @moduledoc """
  Live integration tests for structured output generation with real LLM providers.

  These tests verify that the prompt action correctly:
  - Generates JSON schemas from Ash types
  - Gets structured responses from LLMs
  - Casts responses to proper Elixir types
  """
  use AshAi.LiveLLMCase, async: true

  defmodule Sentiment do
    use Ash.Type.Enum, values: [:positive, :negative, :neutral]
  end

  defmodule ExtractedEntity do
    use Ash.Resource, data_layer: :embedded

    attributes do
      attribute :name, :string, public?: true, allow_nil?: false
      attribute :type, :string, public?: true
      attribute :confidence, :float, public?: true
    end
  end

  defmodule AnalysisResource do
    use Ash.Resource, domain: AshAi.LiveLLM.StructuredOutputTest.TestDomain

    require AshAi.Actions

    actions do
      action :analyze_sentiment, Sentiment do
        argument :text, :string, allow_nil?: false

        description """
        Analyze the sentiment of the given text and return whether it is positive, negative, or neutral.
        """

        run AshAi.Actions.prompt("openai:gpt-4o-mini",
              prompt:
                {"You are a sentiment analyzer. Respond only with the sentiment.",
                 "Analyze the sentiment of: <%= @input.arguments.text %>"}
            )
      end

      action :analyze_sentiment_anthropic, Sentiment do
        argument :text, :string, allow_nil?: false

        description """
        Analyze the sentiment of the given text and return whether it is positive, negative, or neutral.
        """

        run AshAi.Actions.prompt("anthropic:claude-3-5-haiku-latest",
              prompt:
                {"You are a sentiment analyzer. Respond only with the sentiment.",
                 "Analyze the sentiment of: <%= @input.arguments.text %>"}
            )
      end

      action :extract_number, :integer do
        argument :text, :string, allow_nil?: false

        description """
        Extract the main number mentioned in the text. Return just the integer.
        """

        run AshAi.Actions.prompt("openai:gpt-4o-mini",
              prompt:
                {"You extract numbers from text.",
                 "Extract the main number from: <%= @input.arguments.text %>"}
            )
      end

      action :extract_entities, {:array, ExtractedEntity} do
        argument :text, :string, allow_nil?: false

        description """
        Extract named entities from the text with their types and confidence scores.
        """

        run AshAi.Actions.prompt("openai:gpt-4o-mini",
              prompt:
                {"You are a named entity extractor. Extract people, organizations, and locations.",
                 "Extract entities from: <%= @input.arguments.text %>"}
            )
      end

      action :classify_topic, :atom do
        constraints one_of: [:technology, :sports, :politics, :entertainment, :science]
        argument :text, :string, allow_nil?: false

        description """
        Classify the topic of the text into one of: technology, sports, politics, entertainment, science.
        """

        run AshAi.Actions.prompt("openai:gpt-4o-mini",
              prompt:
                {"You classify text into topics.",
                 "Classify this text: <%= @input.arguments.text %>"}
            )
      end

      action :summarize, :string do
        argument :text, :string, allow_nil?: false
        argument :max_words, :integer, default: 20

        description """
        Summarize the text in the specified number of words or fewer.
        """

        run AshAi.Actions.prompt("openai:gpt-4o-mini",
              prompt: fn input, _ctx ->
                ReqLLM.Context.new([
                  ReqLLM.Context.system("You are a concise summarizer."),
                  ReqLLM.Context.user(
                    "Summarize in #{input.arguments.max_words} words or fewer: #{input.arguments.text}"
                  )
                ])
              end
            )
      end
    end
  end

  defmodule TestDomain do
    use Ash.Domain

    resources do
      resource AnalysisResource
    end
  end

  describe "OpenAI structured outputs" do
    @tag :live_llm
    @tag live_llm: :openai
    test "enum return type - sentiment analysis" do
      require_provider!(:openai)

      result =
        AnalysisResource
        |> Ash.ActionInput.for_action(:analyze_sentiment, %{
          text: "I love this product! It's amazing!"
        })
        |> Ash.run_action!(domain: TestDomain)

      assert result in [:positive, :negative, :neutral]
      assert result == :positive
    end

    @tag :live_llm
    @tag live_llm: :openai
    test "integer return type - number extraction" do
      require_provider!(:openai)

      result =
        AnalysisResource
        |> Ash.ActionInput.for_action(:extract_number, %{
          text: "There are 42 apples in the basket"
        })
        |> Ash.run_action!(domain: TestDomain)

      assert is_integer(result)
      assert result == 42
    end

    @tag :live_llm
    @tag live_llm: :openai
    test "embedded struct array return type - entity extraction" do
      require_provider!(:openai)

      result =
        AnalysisResource
        |> Ash.ActionInput.for_action(:extract_entities, %{
          text: "Apple CEO Tim Cook announced new products in Cupertino"
        })
        |> Ash.run_action!(domain: TestDomain)

      assert is_list(result)
      assert result != []

      Enum.each(result, fn entity ->
        assert is_binary(entity.name)
        assert entity.name != ""
      end)

      names = Enum.map(result, & &1.name)

      assert Enum.any?(names, &String.contains?(&1, "Apple")) or
               Enum.any?(names, &String.contains?(&1, "Tim")) or
               Enum.any?(names, &String.contains?(&1, "Cook")) or
               Enum.any?(names, &String.contains?(&1, "Cupertino"))
    end

    @tag :live_llm
    @tag live_llm: :openai
    test "constrained atom return type - topic classification" do
      require_provider!(:openai)

      result =
        AnalysisResource
        |> Ash.ActionInput.for_action(:classify_topic, %{
          text: "The new iPhone 15 features a titanium design and USB-C port"
        })
        |> Ash.run_action!(domain: TestDomain)

      assert result in [:technology, :sports, :politics, :entertainment, :science]
      assert result == :technology
    end

    @tag :live_llm
    @tag live_llm: :openai
    test "string return type with function prompt" do
      require_provider!(:openai)

      result =
        AnalysisResource
        |> Ash.ActionInput.for_action(:summarize, %{
          text:
            "The quick brown fox jumps over the lazy dog. This sentence contains every letter of the alphabet.",
          max_words: 10
        })
        |> Ash.run_action!(domain: TestDomain)

      assert is_binary(result)
      word_count = length(String.split(result))
      assert word_count <= 15
    end
  end

  describe "Anthropic structured outputs" do
    @tag :live_llm
    @tag live_llm: :anthropic
    test "enum return type - sentiment analysis" do
      require_provider!(:anthropic)

      result =
        AnalysisResource
        |> Ash.ActionInput.for_action(:analyze_sentiment_anthropic, %{
          text: "This is terrible, I hate it!"
        })
        |> Ash.run_action!(domain: TestDomain)

      assert result in [:positive, :negative, :neutral]
      assert result == :negative
    end
  end

  describe "error handling" do
    @tag :live_llm
    @tag live_llm: :openai
    test "handles negative sentiment correctly" do
      require_provider!(:openai)

      result =
        AnalysisResource
        |> Ash.ActionInput.for_action(:analyze_sentiment, %{
          text: "This is the worst experience ever. Completely disappointed."
        })
        |> Ash.run_action!(domain: TestDomain)

      assert result == :negative
    end

    @tag :live_llm
    @tag live_llm: :openai
    test "handles neutral sentiment correctly" do
      require_provider!(:openai)

      result =
        AnalysisResource
        |> Ash.ActionInput.for_action(:analyze_sentiment, %{
          text: "The meeting is scheduled for 3pm tomorrow."
        })
        |> Ash.run_action!(domain: TestDomain)

      assert result == :neutral
    end
  end
end
