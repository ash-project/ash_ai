defmodule AshAi.Actions.Prompt.Adapter.Raw do
  @moduledoc """
  An adapter for prompt-backed actions that returns the raw llm response

  Useful for example for llama-guard3 which returns either:
   - "safe"
   - "unsafe\ncategory"
  as a response.
  """
  @behaviour AshAi.Actions.Prompt.Adapter

  alias AshAi.Actions.Prompt.Adapter.Data
  alias LangChain.Chains.LLMChain
  alias LangChain.Message.ContentPart

  def run(%Data{} = data, _opts) do
    %{
      llm: data.llm,
      verbose: data.verbose?,
      custom_context: Map.new(Ash.Context.to_opts(data.context))
    }
    |> LLMChain.new!()
    |> AshAi.Actions.Prompt.Adapter.Helpers.add_messages_with_templates(data.messages, data)
    |> LLMChain.add_tools(data.tools)
    |> LLMChain.run(mode: :while_needs_response)
    |> case do
      {:ok, %LLMChain{last_message: %{content: content}}}
      when is_binary(content) ->
        process_llm_response(content, data)

      {:ok, %LLMChain{last_message: %{content: [%ContentPart{type: :text, content: content}]}}}
      when is_binary(content) ->
        process_llm_response(content, data)

      {:error, _, error} ->
        {:error, error}
    end
  end

  defp process_llm_response(content, data) do
    with {:cast_input, {:ok, value}} <- cast_to_type(content, data),
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
