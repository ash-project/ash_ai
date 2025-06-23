defmodule AshAi.Actions.Prompt.Adapter.StructuredOutput do
  @moduledoc """
  An adapter for prompt-backed actions that leverages structured output from LLMs.

  The only currently known service that supports this is OpenAI.
  """
  @behaviour AshAi.Actions.Prompt.Adapter

  alias AshAi.Actions.Prompt.Adapter.Data
  alias LangChain.Chains.LLMChain

  def run(%Data{} = data, _opts) do
    if !Map.has_key?(data.llm, :json_schema) do
      raise "Only LLMs that have a `json_schema` field can currently be used with the #{inspect(__MODULE__)} adapter"
    end

    llm =
      Map.merge(data.llm, %{
        json_schema: %{
          "strict" => true,
          "schema" => %{
            "type" => "object",
            "properties" => %{"result" => data.json_schema},
            "required" => ["result"],
            "additionalProperties" => false
          },
          "name" => "result"
        },
        json_response: true
      })

    messages = data.messages

    %{
      llm: llm,
      verbose: data.verbose?,
      custom_context: Map.new(Ash.Context.to_opts(data.context))
    }
    |> LLMChain.new!()
    |> AshAi.Actions.Prompt.Adapter.Helpers.add_messages_with_templates(messages, data)
    |> LLMChain.add_tools(data.tools)
    |> LLMChain.run(mode: :while_needs_response)
    |> case do
      {:ok,
       %LangChain.Chains.LLMChain{
         last_message: %{content: content}
       }}
      when is_binary(content) ->
        process_llm_response(content, data)

      {:error, _, error} ->
        {:error, error}
    end
  end

  defp process_llm_response(content, data) do
    with {:json_decode, {:ok, decoded}} <- {:json_decode, Jason.decode(content)},
         {:cast_input, {:ok, value}} <- cast_to_type(decoded["result"], data),
         {:apply_constraints, {:ok, value}} <- validate_constraints(value, data) do
      {:ok, value}
    else
      error ->
        {:error, format_error(error, content)}
    end
  end

  defp cast_to_type(result, data) do
    {:cast_input,
     Ash.Type.cast_input(
       data.input.action.returns,
       result,
       data.input.action.constraints
     )}
  end

  defp validate_constraints(value, data) do
    {:apply_constraints,
     Ash.Type.apply_constraints(
       data.input.action.returns,
       value,
       data.input.action.constraints
     )}
  end

  defp format_error({:json_decode, {:error, %Jason.DecodeError{} = decode_error}}, content) do
    "Failed to decode JSON response: #{Exception.message(decode_error)}. Raw LLM Response: #{inspect(content)}"
  end

  defp format_error({:cast_input, {:error, error}}, content) do
    "Failed to cast LLM response to expected type: #{format_type_error(error)}. Raw LLM Response: #{inspect(content)}"
  end

  defp format_error({:apply_constraints, {:error, error}}, content) do
    "LLM response failed constraint validation: #{format_type_error(error)}. Raw LLM Response: #{inspect(content)}"
  end

  defp format_error(error, content) do
    "Invalid LLM response: #{inspect(error)}. Raw LLM Response: #{inspect(content)}"
  end

  defp format_type_error(error) when is_binary(error), do: error
  defp format_type_error(error), do: inspect(error)
end
