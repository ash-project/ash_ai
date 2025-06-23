defmodule AshAi.Actions.Prompt.Adapter.RequestJson do
  @moduledoc """
  An adapter for prompt-backed actions that requests JSON output directly in the prompt.

  This adapter is designed for LLMs that don't support native tool calling or structured outputs.
  It embeds the JSON schema in the system prompt and uses LangChain's JsonProcessor to extract
  the JSON response from markdown code blocks.

  ## Adapter Options

  - `:max_retries` - Maximum number of retry attempts for invalid JSON (default: 3)
  - `:json_format` - Format to request JSON in (:markdown, :xml) (default: :markdown)
  - `:include_examples` - Examples to include in prompt. Options:
    - `true` - Generate examples using Ash.Type.generator (default)
    - `false` - No examples
    - `%{"result" => example_data}` - Use provided example data
    - `[%{"result" => example1}, %{"result" => example2}]` - Multiple examples
  """
  @behaviour AshAi.Actions.Prompt.Adapter

  alias AshAi.Actions.Prompt.Adapter.Data
  alias LangChain.Chains.LLMChain
  alias LangChain.Message
  alias LangChain.MessageProcessors.JsonProcessor

  @default_max_retries 2

  def run(%Data{} = data, opts) do
    max_retries = opts[:max_retries] || @default_max_retries
    json_format = opts[:json_format] || :markdown
    include_examples = Keyword.get(opts, :include_examples, true)

    messages = enhance_messages_with_schema(data.messages, data, json_format, include_examples)

    regex =
      case json_format do
        :xml -> ~r/<json>\s*(.*?)\s*<\/json>/s
        _ -> ~r/```json\s*(.*?)\s*```/s
      end

    json_processor = JsonProcessor.new!(regex)

    %{
      llm: data.llm,
      verbose: data.verbose?,
      custom_context: Map.new(Ash.Context.to_opts(data.context))
    }
    |> LLMChain.new!()
    |> AshAi.Actions.Prompt.Adapter.Helpers.add_messages_with_templates(messages, data)
    |> LLMChain.add_tools(data.tools)
    |> LLMChain.message_processors([json_processor])
    |> run_with_retries(data, max_retries, 0)
  end

  defp enhance_messages_with_schema(messages, data, json_format, include_examples) do
    # Find the first system message and enhance only that one with schema instructions
    {enhanced_messages, schema_added?} =
      Enum.map_reduce(messages, false, fn message, schema_added? ->
        case {message.role, schema_added?} do
          {:system, false} ->
            enhanced_content =
              enhance_system_content(message.content, data, json_format, include_examples)

            {%{message | content: enhanced_content}, true}

          _ ->
            {message, schema_added?}
        end
      end)

    # If no system message found, add one at the beginning
    if schema_added? do
      enhanced_messages
    else
      schema_instructions = build_schema_instructions(data, json_format, include_examples)
      [Message.new_system!(schema_instructions) | enhanced_messages]
    end
  end

  defp enhance_system_content(content, data, json_format, include_examples)
       when is_binary(content) do
    schema_instructions = build_schema_instructions(data, json_format, include_examples)

    """
    #{content}

    #{schema_instructions}
    """
  end

  defp enhance_system_content(content, data, json_format, include_examples)
       when is_list(content) do
    # For ContentPart lists, add schema instructions as a text part
    schema_instructions = build_schema_instructions(data, json_format, include_examples)
    content ++ [LangChain.Message.ContentPart.text!(schema_instructions)]
  end

  defp build_schema_instructions(data, json_format, include_examples) do
    schema_json = Jason.encode!(data.json_schema, pretty: true)

    format_instructions =
      case json_format do
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

    example_section = generate_example_section(data, include_examples, json_format)

    """

    IMPORTANT INSTRUCTIONS:
    You MUST respond with valid JSON that matches the following schema:

    #{schema_json}

    Your response MUST be formatted as:
    #{format_instructions}

    The JSON must be valid and parseable. Do not include any text before or after the JSON block.#{example_section}
    """
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

  defp process_response(message, data, attempt) do
    {:error,
     "Invalid response format: Got: #{inspect(message)}, data: #{inspect(data)}, attempt: #{attempt}"}
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

  defp generate_example_section(data, include_examples, format) do
    case include_examples do
      false ->
        ""

      true ->
        example = generate_enhanced_example(data)
        format_example_section([example], format)

      %{"result" => _} = user_example ->
        format_example_section([user_example], format)

      examples when is_list(examples) ->
        format_example_section(examples, format)

      _ ->
        ""
    end
  end

  defp format_example_section(examples, format) do
    formatted_examples =
      examples
      |> Enum.with_index(1)
      |> Enum.map_join("\n\n", fn {example, index} ->
        case length(examples) do
          1 -> format_example(example, format)
          _ -> "Example #{index}:\n#{format_example(example, format)}"
        end
      end)

    """

    Example#{if length(examples) > 1, do: "s", else: ""} of valid response#{if length(examples) > 1, do: "s", else: ""}:
    #{formatted_examples}
    """
  end

  defp generate_enhanced_example(data) do
    return_type = data.input.action.returns
    constraints = data.input.action.constraints

    generator =
      try do
        Ash.Type.generator(return_type, constraints)
      rescue
        _ -> nil
      end

    if generator do
      # Generate a single example value using Enum.take
      [generated_value] = Enum.take(generator, 1)

      case Ash.Type.dump_to_embedded(return_type, generated_value, constraints) do
        {:ok, dumped_value} ->
          %{"result" => dumped_value}

        {:error, _} ->
          # Fallback to simple value if dumping fails
          %{"result" => generated_value}
      end
    else
      # Fallback to schema-based generation if type generator fails
      example_content = generate_example_value(data.json_schema)
      %{"result" => example_content}
    end
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
