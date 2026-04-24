# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Actions.PromptTest do
  @moduledoc """
  Tests for the ReqLLM-based prompt action implementation.

  This test suite validates:
  - String model specifications
  - Various prompt formats (string, tuple, ReqLLM.Context, list, function)
  - Content part normalization
  - Backward compatibility with legacy formats
  """
  use ExUnit.Case, async: true
  alias __MODULE__.{TestDomain, TestResource}

  defp content_contains?(content, substring) when is_binary(content) do
    content =~ substring
  end

  defp content_contains?(content, substring) when is_list(content) do
    Enum.any?(content, fn
      %ReqLLM.Message.ContentPart{type: :text, text: text} -> text =~ substring
      _ -> false
    end)
  end

  defmodule FakeReqLLM do
    @moduledoc "Fake ReqLLM module for testing"

    def generate_object(model, context, _schema, _opts \\ []) do
      send(self(), {:generate_object_called, model, context})

      {:ok, %{object: %{"result" => "test_result"}}}
    end
  end

  defmodule FakeReqLLMWithOptsCapture do
    @moduledoc "Fake ReqLLM that captures model/context/opts"

    def generate_object(model, context, _schema, opts \\ []) do
      send(self(), {:generate_object_with_opts_called, model, context, opts})
      {:ok, %{object: %{"result" => "test_result"}}}
    end
  end

  defmodule FakeReqLLMWithSentiment do
    @moduledoc "Fake ReqLLM that returns sentiment data"

    def generate_object(_model, context, _schema, _opts \\ []) do
      send(self(), {:sentiment_called, context})

      {:ok,
       %{
         object: %{
           "result" => %{
             "sentiment" => "positive",
             "confidence" => 0.95,
             "keywords" => ["great", "excellent"]
           }
         }
       }}
    end
  end

  defmodule FakeReqLLMWithOcr do
    @moduledoc "Fake ReqLLM that returns OCR data"

    def generate_object(_model, context, _schema, _opts \\ []) do
      send(self(), {:ocr_called, context})

      {:ok,
       %{
         object: %{
           "result" => %{
             "image_text" => "Hello World"
           }
         }
       }}
    end
  end

  defmodule FakeReqLLMError do
    @moduledoc "Fake ReqLLM that returns an error"

    def generate_object(_model, _context, _schema, _opts \\ []) do
      {:error, "API error: rate limited"}
    end
  end

  defmodule FakeReqLLMWithMapSchema do
    @moduledoc "Fake ReqLLM that captures schema used for :map outputs"

    def generate_object(_model, _context, schema, _opts \\ []) do
      send(self(), {:map_schema, schema})
      {:ok, %{object: %{"result" => %{"foo" => "bar", "nested" => %{"n" => 1}}}}}
    end
  end

  defmodule FakeReqLLMWithNullSchema do
    @moduledoc "Fake ReqLLM that captures schema used for nil outputs"

    def generate_object(_model, _context, schema, _opts \\ []) do
      send(self(), {:null_schema, schema})
      {:ok, %{object: %{"result" => nil}}}
    end
  end

  defmodule FakeReqLLMToolLoopInfiniteToolCalls do
    @moduledoc "Fake ReqLLM that always requests a tool call while streaming"

    def stream_text(_model, _messages, _opts \\ []) do
      {:ok,
       %ReqLLM.StreamResponse{
         stream: [
           ReqLLM.StreamChunk.tool_call("read_test_resources", %{}),
           ReqLLM.StreamChunk.meta(%{finish_reason: :tool_calls})
         ],
         metadata_handle: :ignored,
         cancel: fn -> :ok end,
         model: "openai:gpt-4o",
         context: ReqLLM.Context.new([])
       }}
    end

    def generate_object(_model, _context, _schema, _opts \\ []) do
      {:ok, %{object: %{"result" => "should_not_reach_generate_object"}}}
    end
  end

  defmodule FakeReqLLMToolLoopWithOptsCapture do
    @moduledoc "Fake ReqLLM that captures tool loop opts and then returns a final object"

    def stream_text(model, messages, opts \\ []) do
      send(self(), {:prompt_tool_loop_stream_called, model, messages, opts})
      count = Process.get({__MODULE__, :call_count}, 0)
      Process.put({__MODULE__, :call_count}, count + 1)

      if count == 0 do
        {:ok,
         %ReqLLM.StreamResponse{
           stream: [
             ReqLLM.StreamChunk.tool_call(
               "prompt_extra_tool",
               %{"message" => "from extra tool"},
               %{
                 id: "call_prompt_extra",
                 index: 0
               }
             ),
             ReqLLM.StreamChunk.meta(%{finish_reason: :tool_calls})
           ],
           metadata_handle: :ignored,
           cancel: fn -> :ok end,
           model: model,
           context: ReqLLM.Context.new(messages)
         }}
      else
        {:ok,
         %ReqLLM.StreamResponse{
           stream: [
             ReqLLM.StreamChunk.text("done"),
             ReqLLM.StreamChunk.meta(%{finish_reason: :stop})
           ],
           metadata_handle: :ignored,
           cancel: fn -> :ok end,
           model: model,
           context: ReqLLM.Context.new(messages)
         }}
      end
    end

    def generate_object(model, context, _schema, opts \\ []) do
      send(self(), {:prompt_generate_object_with_opts_called, model, context, opts})
      {:ok, %{object: %{"result" => "tool_loop_result"}}}
    end
  end

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

  defmodule OcrResult do
    @moduledoc false
    use Ash.Type.NewType,
      subtype_of: :map,
      constraints: [
        fields: [
          image_text: [
            type: :string,
            allow_nil?: false,
            description: "The extracted text from the image"
          ]
        ]
      ]
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

        run prompt("openai:gpt-4o",
              prompt: {"You are a sentiment analyzer", "Analyze: <%= @input.arguments.text %>"},
              req_llm: FakeReqLLMWithSentiment
            )
      end

      action :analyze_with_string_prompt, :string do
        description("Test legacy string prompt")
        argument(:text, :string, allow_nil?: false)

        run prompt("openai:gpt-4o",
              prompt: "Process this text: <%= @input.arguments.text %>",
              req_llm: FakeReqLLM
            )
      end

      action :analyze_with_transform_flow, :string do
        description("Test ReqLLM-native flow customization")
        argument(:text, :string, allow_nil?: false)

        run prompt("openai:gpt-4o",
              prompt: "Process this text: <%= @input.arguments.text %>",
              req_llm: FakeReqLLMWithOptsCapture,
              transform_flow: fn flow_state, _context ->
                %{
                  flow_state
                  | model: "openai:gpt-4o-mini",
                    req_llm_opts:
                      Keyword.put(flow_state.req_llm_opts, :trace_id, "from_transform_flow"),
                    messages:
                      flow_state.messages ++ [ReqLLM.Context.user("transform_flow_marker")]
                }
              end
            )
      end

      action :analyze_with_transform_flow_extra_tool, :string do
        description("Test transform_flow with extra_tools and req_llm_opts")
        argument(:text, :string, allow_nil?: false)

        run prompt("openai:gpt-4o",
              prompt: "Use the extra tool for: <%= @input.arguments.text %>",
              tools: [],
              req_llm: FakeReqLLMToolLoopWithOptsCapture,
              transform_flow: fn flow_state, _context ->
                %{
                  flow_state
                  | extra_tools:
                      flow_state.extra_tools ++ [AshAi.Actions.PromptTest.prompt_extra_tool()],
                    req_llm_opts:
                      Keyword.put(
                        flow_state.req_llm_opts,
                        :trace_id,
                        "from_transform_flow_tool_loop"
                      )
                }
              end
            )
      end

      action :analyze_with_function_prompt, :string do
        description("Test function-based prompt")
        argument(:text, :string, allow_nil?: false)

        run prompt("openai:gpt-4o",
              prompt: fn input, _context ->
                {"You are a text processor", "Process: #{input.arguments.text}"}
              end,
              req_llm: FakeReqLLM
            )
      end

      action :analyze_with_messages_list, :string do
        description("Test message list prompt")
        argument(:text, :string, allow_nil?: false)

        run prompt("openai:gpt-4o",
              prompt: [
                %{role: "system", content: "You are a helpful assistant"},
                %{role: "user", content: "Process: <%= @input.arguments.text %>"}
              ],
              req_llm: FakeReqLLM
            )
      end

      action :analyze_with_reqllm_context, :string do
        description("Test ReqLLM.Context prompt")
        argument(:text, :string, allow_nil?: false)

        run prompt("openai:gpt-4o",
              prompt: fn input, _context ->
                ReqLLM.Context.new([
                  ReqLLM.Context.system("You are a helpful assistant"),
                  ReqLLM.Context.user("Process: #{input.arguments.text}")
                ])
              end,
              req_llm: FakeReqLLM
            )
      end

      action :ocr_with_context_api, OcrResult do
        description("OCR using ReqLLM.Context API")
        argument(:image_url, :string, allow_nil?: false)

        run prompt("openai:gpt-4o",
              prompt: fn input, _context ->
                ReqLLM.Context.new([
                  ReqLLM.Context.system("You are an OCR expert"),
                  ReqLLM.Context.user([
                    ReqLLM.Message.ContentPart.text("Extract text from this image"),
                    ReqLLM.Message.ContentPart.image_url(input.arguments.image_url)
                  ])
                ])
              end,
              req_llm: FakeReqLLMWithOcr
            )
      end

      action :test_error_handling, :string do
        description("Test error handling")
        argument(:text, :string, allow_nil?: false)

        run prompt("openai:gpt-4o",
              prompt: "Analyze: <%= @input.arguments.text %>",
              req_llm: FakeReqLLMError
            )
      end

      action :analyze_with_map_return, :map do
        description("Test unconstrained map return handling")
        argument(:text, :string, allow_nil?: false)

        run prompt("openai:gpt-4o",
              prompt: "Return a map for: <%= @input.arguments.text %>",
              req_llm: FakeReqLLMWithMapSchema
            )
      end

      action :perform_without_return do
        description("Test nil return handling")
        argument(:text, :string, allow_nil?: false)

        run prompt("openai:gpt-4o",
              prompt: "Perform the action for: <%= @input.arguments.text %>",
              req_llm: FakeReqLLMWithNullSchema
            )
      end

      action :tool_loop_failure_returns_error, :string do
        description("Test tool loop failure propagation")
        argument(:text, :string, allow_nil?: false)

        run prompt("openai:gpt-4o",
              prompt: "Use tools forever",
              tools: true,
              max_iterations: 1,
              req_llm: FakeReqLLMToolLoopInfiniteToolCalls
            )
      end
    end
  end

  defmodule TestDomain do
    use Ash.Domain, extensions: [AshAi]

    resources do
      resource(TestResource)
    end

    tools do
      tool(:read_test_resources, TestResource, :read)
    end
  end

  defmodule NoDomainResource do
    use Ash.Resource, domain: nil, data_layer: Ash.DataLayer.Ets

    ets do
      private?(true)
    end

    actions do
      default_accept([:*])

      action :tool_requires_resolution_context, :string do
        argument(:text, :string, allow_nil?: false)

        run fn _input, _ctx -> {:ok, "noop"} end
      end
    end
  end

  describe "prompt with tuple format" do
    test "successfully executes with {system, user} tuple prompt" do
      result =
        TestResource
        |> Ash.ActionInput.for_action(:analyze_sentiment, %{text: "This is amazing!"})
        |> Ash.run_action!()

      assert result.sentiment == "positive"
      assert result.confidence == 0.95
      assert result.keywords == ["great", "excellent"]
    end

    test "EEx template in tuple user message substitutes correctly" do
      TestResource
      |> Ash.ActionInput.for_action(:analyze_sentiment, %{text: "substituted value"})
      |> Ash.run_action!()

      assert_receive {:sentiment_called, context}
      user_message = Enum.find(context.messages, &(&1.role == :user))
      assert content_contains?(user_message.content, "substituted value")
    end
  end

  describe "prompt with string format" do
    test "successfully executes with string prompt" do
      result =
        TestResource
        |> Ash.ActionInput.for_action(:analyze_with_string_prompt, %{text: "test input"})
        |> Ash.run_action!()

      assert result == "test_result"

      assert_receive {:generate_object_called, "openai:gpt-4o", context}
      assert %ReqLLM.Context{} = context
      assert length(context.messages) == 2
    end

    test "EEx template substitutes input arguments correctly" do
      TestResource
      |> Ash.ActionInput.for_action(:analyze_with_string_prompt, %{text: "hello world"})
      |> Ash.run_action!()

      assert_receive {:generate_object_called, _model, context}
      system_message = Enum.find(context.messages, &(&1.role == :system))
      assert content_contains?(system_message.content, "hello world")
    end

    test "transform_flow customizes model, req_llm opts, and messages" do
      result =
        TestResource
        |> Ash.ActionInput.for_action(:analyze_with_transform_flow, %{text: "hello world"})
        |> Ash.run_action!()

      assert result == "test_result"

      assert_receive {:generate_object_with_opts_called, "openai:gpt-4o-mini", context, opts}
      assert Keyword.get(opts, :trace_id) == "from_transform_flow"

      marker_message =
        Enum.find(context.messages, fn message ->
          message.role == :user && content_contains?(message.content, "transform_flow_marker")
        end)

      assert marker_message
    end

    test "transform_flow can append extra_tools and forward req_llm_opts into tool loops" do
      Process.delete({FakeReqLLMToolLoopWithOptsCapture, :call_count})

      result =
        TestResource
        |> Ash.ActionInput.for_action(:analyze_with_transform_flow_extra_tool, %{text: "hello"})
        |> Ash.run_action!()

      assert result == "tool_loop_result"

      assert_receive {:prompt_tool_loop_stream_called, %{model: "gpt-4o"}, _messages, opts}
      assert Keyword.get(opts, :trace_id) == "from_transform_flow_tool_loop"
      assert Enum.map(Keyword.fetch!(opts, :tools), & &1.name) == ["prompt_extra_tool"]
      assert_receive {:prompt_extra_tool_called, "from extra tool"}

      assert_receive {:prompt_generate_object_with_opts_called, "openai:gpt-4o", context, opts}
      assert Keyword.get(opts, :trace_id) == "from_transform_flow_tool_loop"

      assert Enum.any?(context.messages, fn message ->
               message.role == :tool &&
                 ReqLLM.ToolResult.output_from_message(message) == %{"echo" => "from extra tool"}
             end)
    end
  end

  describe "prompt with function format" do
    test "successfully executes with function prompt returning tuple" do
      result =
        TestResource
        |> Ash.ActionInput.for_action(:analyze_with_function_prompt, %{text: "test input"})
        |> Ash.run_action!()

      assert result == "test_result"
    end

    test "successfully executes with function prompt returning ReqLLM.Context" do
      result =
        TestResource
        |> Ash.ActionInput.for_action(:analyze_with_reqllm_context, %{text: "test input"})
        |> Ash.run_action!()

      assert result == "test_result"

      assert_receive {:generate_object_called, "openai:gpt-4o", context}
      assert %ReqLLM.Context{} = context
    end
  end

  describe "prompt with messages list" do
    test "successfully executes with list of message maps" do
      result =
        TestResource
        |> Ash.ActionInput.for_action(:analyze_with_messages_list, %{text: "test input"})
        |> Ash.run_action!()

      assert result == "test_result"
    end

    test "EEx template in message list content substitutes correctly" do
      TestResource
      |> Ash.ActionInput.for_action(:analyze_with_messages_list, %{text: "list template value"})
      |> Ash.run_action!()

      assert_receive {:generate_object_called, _model, context}
      user_message = Enum.find(context.messages, &(&1.role == :user))
      assert content_contains?(user_message.content, "list template value")
    end
  end

  describe "prompt with ReqLLM.Context API" do
    test "supports ReqLLM.Context with content parts for images" do
      result =
        TestResource
        |> Ash.ActionInput.for_action(:ocr_with_context_api, %{
          image_url: "https://example.com/image.jpg"
        })
        |> Ash.run_action!()

      assert result.image_text == "Hello World"

      assert_receive {:ocr_called, context}
      assert %ReqLLM.Context{} = context

      user_message = Enum.find(context.messages, &(&1.role == :user))
      assert user_message != nil
      assert is_list(user_message.content)
    end
  end

  describe "error handling" do
    test "propagates ReqLLM errors" do
      error =
        assert_raise Ash.Error.Unknown, fn ->
          TestResource
          |> Ash.ActionInput.for_action(:test_error_handling, %{text: "test"})
          |> Ash.run_action!()
        end

      assert length(error.errors) == 1
      assert hd(error.errors).error =~ "rate limited"
    end

    test "tool loop failures return action errors with reason details" do
      assert {:error, %Ash.Error.Unknown{} = error} =
               TestResource
               |> Ash.ActionInput.for_action(:tool_loop_failure_returns_error, %{text: "loop"})
               |> Ash.run_action()

      assert Enum.any?(error.errors, fn detail ->
               inspect(detail) =~ "Tool loop failed in prompt action" &&
                 inspect(detail) =~ "max_iterations_reached"
             end)
    end

    test "tool setup precondition failure returns action errors instead of raising" do
      action = Ash.Resource.Info.action(NoDomainResource, :tool_requires_resolution_context)

      input = %Ash.ActionInput{
        resource: NoDomainResource,
        action: action,
        arguments: %{text: "hi"}
      }

      assert {:error, error} =
               AshAi.Actions.Prompt.run(
                 input,
                 [
                   model: "openai:gpt-4o",
                   prompt: "Say hi",
                   tools: true,
                   req_llm: FakeReqLLM
                 ],
                 %{}
               )

      assert inspect(error) =~ "Prompt action tool use requires either"
    end
  end

  describe "map returns" do
    test "uses permissive schema for unconstrained map return values" do
      result =
        TestResource
        |> Ash.ActionInput.for_action(:analyze_with_map_return, %{text: "map please"})
        |> Ash.run_action!()

      assert result == %{"foo" => "bar", "nested" => %{"n" => 1}}

      assert_receive {:map_schema, schema}
      assert schema["properties"]["result"] in [%{"type" => "object"}, %{type: :object}]
    end
  end

  describe "nil returns" do
    test "uses the legacy null result wrapper for actions without declared returns" do
      result =
        TestResource
        |> Ash.ActionInput.for_action(:perform_without_return, %{text: "do it"})
        |> Ash.run_action!()

      assert result == :ok

      assert_receive {:null_schema, schema}

      assert schema == %{
               "type" => "object",
               "properties" => %{"result" => %{"type" => "null"}},
               "required" => ["result"],
               "additionalProperties" => false
             }
    end
  end

  def prompt_extra_tool do
    ReqLLM.Tool.new!(
      name: "prompt_extra_tool",
      description: "Prompt-only extra tool",
      parameter_schema: [
        message: [type: :string, required: true]
      ],
      callback: fn arguments ->
        message = arguments[:message] || arguments["message"]
        send(self(), {:prompt_extra_tool_called, message})
        {:ok, %{"echo" => message}}
      end
    )
  end
end
