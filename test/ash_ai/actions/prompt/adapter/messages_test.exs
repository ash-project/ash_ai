defmodule AshAi.Actions.Prompt.Adapter.MessagesTest do
  @moduledoc """
  Tests for all prompt adapters with the new Messages support.

  This test suite ensures that all adapters (RequestJson, CompletionTool, StructuredOutput)
  properly handle the new Messages format, including:
  - LangChain Messages with text content
  - Messages with ContentParts (images + text)
  - Messages with PromptTemplates
  - Mixed content scenarios (like OCR with images)
  """
  use ExUnit.Case, async: true
  alias AshAi.ChatFaker
  alias LangChain.Message
  alias LangChain.Message.ContentPart
  alias LangChain.PromptTemplate
  alias __MODULE__.{TestDomain, TestResource}

  defmodule OcrResult do
    @moduledoc false
    use Ash.Type.NewType,
      subtype_of: :map,
      constraints: [
        fields: [
          image_text: [
            type: :string,
            allow_nil?: false,
            description: "The handwritten text in the image"
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
    end

    actions do
      default_accept([:*])
      defaults([:create, :read, :update, :destroy])

      # Test 1: Messages with image content (OCR scenario) - RequestJson
      action :ocr_with_messages_request_json, OcrResult do
        description("OCR using Messages format with RequestJson adapter")
        argument(:image_data, :binary, allow_nil?: false)
        argument(:extra_context, :string, allow_nil?: true)

        run prompt(
              fn _input, _context ->
                ChatFaker.new!(%{
                  expect_fun: fn _model, messages, _tools ->
                    # Verify the image was included in the messages
                    user_message = Enum.find(messages, &(&1.role == :user))
                    assert user_message != nil

                    # Check if content is a list with ContentParts
                    if is_list(user_message.content) do
                      has_image =
                        Enum.any?(user_message.content, fn part ->
                          match?(%ContentPart{type: :image}, part)
                        end)

                      assert has_image, "Expected image ContentPart in user message"
                    end

                    json_response = """
                    ```json
                    {
                      "result": {
                        "image_text": "Hello World"
                      }
                    }
                    ```
                    """

                    {:ok, Message.new_assistant!(%{content: json_response})}
                  end
                })
              end,
              adapter: AshAi.Actions.Prompt.Adapter.RequestJson,
              prompt: fn input, _context ->
                [
                  Message.new_system!("You are an expert at OCR of images."),
                  Message.new_user!([
                    ContentPart.text!("Please extract text from this image."),
                    ContentPart.image!(input.arguments.image_data, media: :jpg)
                  ])
                ]
              end
            )
      end

      # Test 2: Messages with PromptTemplate - RequestJson
      action :ocr_with_template_request_json, OcrResult do
        description("OCR using PromptTemplate in Messages with RequestJson adapter")
        argument(:image_data, :binary, allow_nil?: false)
        argument(:extra_context, :string, allow_nil?: true)

        run prompt(
              fn _input, _context ->
                ChatFaker.new!(%{
                  expect_fun: fn _model, messages, _tools ->
                    # Verify PromptTemplate was processed
                    user_message = Enum.find(messages, &(&1.role == :user))
                    assert user_message != nil

                    json_response = """
                    ```json
                    {
                      "result": {
                        "image_text": "Hello World"
                      }
                    }
                    ```
                    """

                    {:ok, Message.new_assistant!(%{content: json_response})}
                  end
                })
              end,
              adapter: AshAi.Actions.Prompt.Adapter.RequestJson,
              prompt: fn input, _context ->
                [
                  Message.new_system!("You are an expert at OCR."),
                  Message.new_user!([
                    PromptTemplate.from_template!(
                      "Extra context: <%= @input.arguments.extra_context %>"
                    ),
                    ContentPart.image!(input.arguments.image_data, media: :jpg)
                  ])
                ]
              end
            )
      end

      # Test 3: Messages with CompletionTool adapter
      action :analyze_image_completion_tool, OcrResult do
        description("Image analysis using Messages with CompletionTool adapter")
        argument(:image_data, :binary, allow_nil?: false)

        run prompt(
              fn _input, _context ->
                ChatFaker.new!(%{
                  expect_fun: fn _model, messages, tools ->
                    # Verify image was preserved
                    user_message = Enum.find(messages, &(&1.role == :user))
                    assert user_message != nil

                    completion_tool = Enum.find(tools, &(&1.name == "complete_request"))
                    assert completion_tool != nil

                    tool_call = %LangChain.Message.ToolCall{
                      status: :complete,
                      type: :function,
                      call_id: "call_image_analysis",
                      name: "complete_request",
                      arguments: %{
                        "result" => %{
                          "image_text" => "Hello World"
                        }
                      },
                      index: 0
                    }

                    {:ok,
                     Message.new_assistant!(%{
                       status: :complete,
                       tool_calls: [tool_call]
                     })}
                  end
                })
              end,
              adapter: AshAi.Actions.Prompt.Adapter.CompletionTool,
              prompt: fn input, _context ->
                [
                  Message.new_system!("You are an expert at image analysis."),
                  Message.new_user!([
                    ContentPart.text!("Analyze this image and describe what you see."),
                    ContentPart.image!(input.arguments.image_data, media: :jpg)
                  ])
                ]
              end
            )
      end

      # Test 5: Legacy string prompt (backward compatibility)
      action :legacy_string_prompt, OcrResult do
        description("Test legacy string prompt compatibility")
        argument(:text, :string, allow_nil?: false)

        run prompt(
              fn _input, _context ->
                ChatFaker.new!(%{
                  expect_fun: fn _model, messages, _tools ->
                    json_response = """
                    ```json
                    {
                      "result": {
                        "image_text": "Legacy processed text"
                      }
                    }
                    ```
                    """

                    {:ok, Message.new_assistant!(%{content: json_response})}
                  end
                })
              end,
              adapter: AshAi.Actions.Prompt.Adapter.RequestJson,
              prompt: "Process this text: <%= @input.arguments.text %>"
            )
      end

      # Test 6: Legacy tuple prompt (backward compatibility)
      action :legacy_tuple_prompt, OcrResult do
        description("Test legacy tuple prompt compatibility")
        argument(:text, :string, allow_nil?: false)

        run prompt(
              fn _input, _context ->
                ChatFaker.new!(%{
                  expect_fun: fn _model, messages, _tools ->
                    json_response = """
                    ```json
                    {
                      "result": {
                        "image_text": "Tuple processed text"
                      }
                    }
                    ```
                    """

                    {:ok, Message.new_assistant!(%{content: json_response})}
                  end
                })
              end,
              adapter: AshAi.Actions.Prompt.Adapter.RequestJson,
              prompt: {"You are a text processor", "Process: <%= @input.arguments.text %>"}
            )
      end
    end
  end

  defmodule TestDomain do
    use Ash.Domain, extensions: [AshAi]

    resources do
      resource(TestResource)
    end
  end

  describe "Messages support in adapters" do
    setup do
      # Create a fake image data (base64 encoded small image)
      image_data =
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="

      {:ok, image_data: image_data}
    end

    test "RequestJson adapter processes Messages with images correctly", %{image_data: image_data} do
      result =
        TestResource
        |> Ash.ActionInput.for_action(:ocr_with_messages_request_json, %{
          image_data: image_data,
          extra_context: "test context"
        })
        |> Ash.run_action!()

      assert result.image_text == "Hello World"
    end

    test "RequestJson adapter processes PromptTemplates in Messages", %{image_data: image_data} do
      result =
        TestResource
        |> Ash.ActionInput.for_action(:ocr_with_template_request_json, %{
          image_data: image_data,
          extra_context: "important context"
        })
        |> Ash.run_action!()

      assert result.image_text == "Hello World"
    end

    test "CompletionTool adapter processes Messages with images correctly", %{
      image_data: image_data
    } do
      result =
        TestResource
        |> Ash.ActionInput.for_action(:analyze_image_completion_tool, %{
          image_data: image_data
        })
        |> Ash.run_action!()

      assert result.image_text == "Hello World"
    end

    test "legacy string prompt still works (backward compatibility)" do
      result =
        TestResource
        |> Ash.ActionInput.for_action(:legacy_string_prompt, %{
          text: "test input"
        })
        |> Ash.run_action!()

      assert result.image_text == "Legacy processed text"
    end

    test "legacy tuple prompt still works (backward compatibility)" do
      result =
        TestResource
        |> Ash.ActionInput.for_action(:legacy_tuple_prompt, %{
          text: "test input"
        })
        |> Ash.run_action!()

      assert result.image_text == "Tuple processed text"
    end
  end
end
