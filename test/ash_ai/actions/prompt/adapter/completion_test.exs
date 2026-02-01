# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Actions.Prompt.Adapter.CompletionTest do
  use ExUnit.Case, async: true
  alias AshAi.ChatFaker
  alias __MODULE__.{TestDomain, TestResource}

  defmodule Sentiment do
    use Ash.Resource, data_layer: :embedded

    attributes do
      attribute :sentiment, :string, public?: true
      attribute :confidence, :float, public?: true
      attribute :keywords, {:array, :string}, public?: true
    end

    actions do
      default_accept([:*])
      defaults([:create, :read])
    end
  end

  defmodule Summary do
    use Ash.Resource, data_layer: :embedded

    attributes do
      attribute :summary, :string, public?: true
      attribute :word_count, :integer, public?: true
      attribute :key_points, {:array, :string}, public?: true
    end

    actions do
      default_accept([:*])
      defaults([:create, :read])
    end
  end

  defmodule TestResource do
    use Ash.Resource,
      domain: TestDomain,
      data_layer: Ash.DataLayer.Ets,
      extensions: [AshAi]

    ets do
      private?(true)
    end

    attributes do
      uuid_v7_primary_key(:id, writable?: true)
      attribute(:name, :string, public?: true)
    end

    actions do
      default_accept([:*])
      defaults([:create, :read, :update, :destroy])

      action :analyze_sentiment, Sentiment do
        description("Analyze the sentiment of a given text")
        argument(:text, :string, allow_nil?: false)

        run prompt(
              fn _input, _context ->
                ChatFaker.new!(%{
                  expect_fun: fn _model, _messages, tools ->
                    completion_tool = Enum.find(tools, &(&1.name == "complete_request"))

                    tool_call = %LangChain.Message.ToolCall{
                      status: :complete,
                      type: :function,
                      call_id: "call_123",
                      name: "complete_request",
                      arguments: %{
                        "result" => %{
                          "sentiment" => "positive",
                          "confidence" => 0.92,
                          "keywords" => ["excellent", "wonderful", "fantastic"]
                        }
                      },
                      index: 0
                    }

                    {:ok,
                     LangChain.Message.new_assistant!(%{
                       status: :complete,
                       tool_calls: [tool_call]
                     })}
                  end
                })
              end,
              adapter: {AshAi.Actions.Prompt.Adapter.CompletionTool, [max_runs: 10]}
            )
      end

      action :generate_summary, Summary do
        description("Generate a summary of a document")
        argument(:content, :string, allow_nil?: false)
        argument(:max_words, :integer, allow_nil?: true)

        run prompt(
              fn _input, _context ->
                ChatFaker.new!(%{
                  expect_fun: fn _model, _messages, tools ->
                    completion_tool = Enum.find(tools, &(&1.name == "complete_request"))

                    tool_call = %LangChain.Message.ToolCall{
                      status: :complete,
                      type: :function,
                      call_id: "call_456",
                      name: "complete_request",
                      arguments: %{
                        "result" => %{
                          "summary" => "A well-written document about machine learning concepts.",
                          "word_count" => 58,
                          "key_points" => ["AI fundamentals", "Neural networks", "Deep learning"]
                        }
                      },
                      index: 0
                    }

                    {:ok,
                     LangChain.Message.new_assistant!(%{
                       status: :complete,
                       tool_calls: [tool_call]
                     })}
                  end
                })
              end,
              adapter: {AshAi.Actions.Prompt.Adapter.CompletionTool, [max_runs: 5]}
            )
      end
    end
  end

  defmodule ValidationErrorResource do
    use Ash.Resource, domain: TestDomain, data_layer: Ash.DataLayer.Ets, extensions: [AshAi]

    ets do
      private?(true)
    end

    attributes do
      uuid_v7_primary_key(:id, writable?: true)
    end

    actions do
      default_accept([:*])
      defaults([:create, :read, :update, :destroy])

      action :test_validation, Sentiment do
        description("Test validation errors")
        argument(:text, :string, allow_nil?: false)

        run prompt(
              fn _input, _context ->
                ChatFaker.new!(%{
                  expect_fun: fn _model, _messages, _tools ->
                    # Return invalid data type (string instead of float for confidence)
                    tool_call = %LangChain.Message.ToolCall{
                      status: :complete,
                      type: :function,
                      call_id: "call_validation",
                      name: "complete_request",
                      arguments: %{
                        "result" => %{
                          "sentiment" => "positive",
                          "confidence" => "not a number",
                          "keywords" => ["good"]
                        }
                      },
                      index: 0
                    }

                    {:ok,
                     LangChain.Message.new_assistant!(%{
                       status: :complete,
                       tool_calls: [tool_call]
                     })}
                  end
                })
              end,
              adapter:
                {AshAi.Actions.Prompt.Adapter.CompletionTool,
                 [
                   max_retries: 0,
                   max_runs: 10
                 ]}
            )
      end
    end
  end

  defmodule TestDomain do
    use Ash.Domain, extensions: [AshAi]

    resources do
      resource(TestResource)
      resource(ValidationErrorResource)
    end
  end

  describe "CompletionTool adapter" do
    test "successfully executes analyze_sentiment action" do
      result =
        TestResource
        |> Ash.ActionInput.for_action(:analyze_sentiment, %{
          text: "This product is absolutely amazing!"
        })
        |> Ash.run_action!()

      assert result.sentiment == "positive"
      assert result.confidence == 0.92
      assert result.keywords == ["excellent", "wonderful", "fantastic"]
    end

    test "successfully executes generate_summary action" do
      result =
        TestResource
        |> Ash.ActionInput.for_action(:generate_summary, %{
          content: "This is a document about machine learning...",
          max_words: 100
        })
        |> Ash.run_action!()

      assert result.summary == "A well-written document about machine learning concepts."
      assert result.word_count == 58
      assert result.key_points == ["AI fundamentals", "Neural networks", "Deep learning"]
    end

    test "handles validation errors" do
      errors =
        assert_raise Ash.Error.Unknown, fn ->
          ValidationErrorResource
          |> Ash.ActionInput.for_action(:test_validation, %{text: "test"})
          |> Ash.run_action!()
        end

      assert length(errors.errors) == 1
      error = hd(errors.errors)
      assert error.error =~ "Exceeded max failure count"
    end
  end
end
