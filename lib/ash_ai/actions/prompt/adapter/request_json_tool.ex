defmodule AshAi.Actions.Prompt.Adapter.RequestJsonTool do
  @moduledoc """
  An adapter for prompt-backed actions that requests JSON output directly in the prompt.

  This adapter is designed for LLMs that don't support native tool calling or structured outputs.
  It embeds the JSON schema in the system prompt and uses LangChain's JsonProcessor to extract
  the JSON response from markdown code blocks.

  ## Adapter Options

  - `:max_retries` - Maximum number of retry attempts for invalid JSON (default: 3)
  - `:json_format` - Format to request JSON in (:markdown, :xml) (default: :markdown)
  - `:include_examples` - Whether to include example JSON in the prompt (default: true)
  """
  @behaviour AshAi.Actions.Prompt.Adapter

  alias AshAi.Actions.Prompt.Adapter.Data
  alias LangChain.Chains.LLMChain
  alias LangChain.Message
  alias LangChain.MessageProcessors.JsonProcessor

  @default_max_retries 2
  @json_markdown_regex ~r/```json\s*(.*?)\s*```/s

  def run(%Data{} = data, opts) do
    max_retries = opts[:max_retries] || @default_max_retries
    json_format = opts[:json_format] || :markdown
    include_examples = Keyword.get(opts, :include_examples, true)

    enhanced_system_prompt = build_enhanced_prompt(data, json_format, include_examples)

    messages = [
      Message.new_system!(enhanced_system_prompt),
      Message.new_user!(data.user_message)
    ]

    json_processor = JsonProcessor.new!(@json_markdown_regex)

    chain =
      %{
        llm: data.llm,
        verbose: data.verbose?,
        custom_context: Map.new(Ash.Context.to_opts(data.context))
      }
      |> LLMChain.new!()
      |> LLMChain.add_messages(messages)
      |> LLMChain.add_tools(data.tools)
      |> LLMChain.message_processors([json_processor])

    run_with_retries(chain, data, max_retries, 0)
  end

  defp run_with_retries(chain, data, max_retries, attempt) do
    case LLMChain.run(chain, mode: :while_needs_response) do
      {:ok, %LLMChain{last_message: %Message{role: :assistant} = message} = updated_chain} ->
        case process_response(message, data, attempt) do
          {:ok, result} ->
            {:ok, result}

          {:error, validation_error} when attempt < max_retries ->
            retry_message = create_retry_message(validation_error)

            updated_chain
            |> LLMChain.add_message(retry_message)
            |> run_with_retries(data, max_retries, attempt + 1)

          {:error, error} ->
            {:error, "Failed after #{attempt + 1} attempts: #{error}"}
        end

      {:error, _, error} ->
        {:error, error}
    end
  end

  defp process_response(%Message{processed_content: content}, data, _attempt)
       when is_map(content) do
    # JsonProcessor successfully extracted JSON
    validate_and_cast_result(content, data)
  end

  defp process_response(%Message{content: content}, data, _attempt) when is_binary(content) do
    # Fallback: try to parse raw content as JSON
    case Jason.decode(content) do
      {:ok, decoded} ->
        validate_and_cast_result(decoded, data)

      {:error, _} ->
        {:error,
         "Response did not contain valid JSON. Please format your response as a JSON code block."}
    end
  end

  defp process_response(_, _, _) do
    {:error, "Invalid response format"}
  end

  defp validate_and_cast_result(content, data) do
    result = Map.get(content, "result", content)

    with {:ok, value} <-
           Ash.Type.cast_input(
             data.input.action.returns,
             result,
             data.input.action.constraints
           ),
         {:ok, value} <-
           Ash.Type.apply_constraints(
             data.input.action.returns,
             value,
             data.input.action.constraints
           ) do
      {:ok, value}
    else
      {:error, error} ->
        {:error, format_validation_error(error, data.json_schema)}
    end
  end

  defp build_enhanced_prompt(data, format, include_examples) do
    schema_json = Jason.encode!(data.json_schema, pretty: true)

    format_instructions =
      case format do
        :xml ->
          """
          <json>
          {
            "result": <your response matching the schema>
          }
          </json>
          """

        _ ->
          """
          ```json
          {
            "result": <your response matching the schema>
          }
          ```
          """
      end

    example_section =
      if include_examples do
        example = generate_example_for_schema(data.json_schema)

        """

        Example of a valid response:
        #{format_example(example, format)}
        """
      else
        ""
      end

    """
    #{data.system_prompt}

    IMPORTANT INSTRUCTIONS:
    You MUST respond with valid JSON that matches the following schema:

    #{schema_json}

    Your response MUST be formatted as:
    #{format_instructions}

    The JSON must be valid and parseable. Do not include any text before or after the JSON block.#{example_section}
    """
  end

  defp create_retry_message(error) do
    Message.new_user!("""
    Your previous response contained invalid JSON or did not match the required schema.

    Error: #{error}

    Please provide a valid JSON response in a markdown code block (```json ... ```) that matches the required schema.
    Remember to wrap your entire response in the "result" field.
    """)
  end

  defp format_validation_error(error, schema) do
    """
    Validation failed: #{inspect(error)}

    Expected schema:
    #{Jason.encode!(schema, pretty: true)}
    """
  end

  defp generate_example_for_schema(schema) do
    example_content = generate_example_value(schema)

    %{
      "result" => example_content
    }
  end

  defp generate_example_value(%{"type" => "object", "properties" => props}) do
    Enum.into(props, %{}, fn {key, prop_schema} ->
      {key, generate_example_value(prop_schema)}
    end)
  end

  defp generate_example_value(%{"type" => "string", "enum" => [first | _]}), do: first
  defp generate_example_value(%{"type" => "string"}), do: "example string"
  defp generate_example_value(%{"type" => "number"}), do: 42
  defp generate_example_value(%{"type" => "integer"}), do: 42
  defp generate_example_value(%{"type" => "boolean"}), do: true

  defp generate_example_value(%{"type" => "array", "items" => item_schema}) do
    [generate_example_value(item_schema)]
  end

  defp generate_example_value(_), do: "example"

  defp format_example(example, :xml) do
    """
    <json>
    #{Jason.encode!(example, pretty: true)}
    </json>
    """
  end

  defp format_example(example, _) do
    """
    ```json
    #{Jason.encode!(example, pretty: true)}
    ```
    """
  end
end
