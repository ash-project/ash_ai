defmodule AshAi.Actions.Prompt.Adapter.Helpers do
  @moduledoc """
  Helpers for processing `LangChain.PromptTemplate`s in messages.

  This module resolves templates with runtime data from the action's input
  and context before the prompt is sent to an LLM.

  ### Example

  Given a prompt with a template:

  ```elixir
  messages = [
    Message.new_user!([
      PromptTemplate.from_template!("Context: <%= @input.arguments.extra_info %>"),
      ContentPart.text!("Analyze the following text.")
    ])
  ]
  ```

  Adapters use `add_messages_with_templates/3` to resolve such templates,
  injecting variables from the action input and context.
  """

  alias LangChain.Chains.LLMChain

  @doc """
  Adds messages to a chain, applying prompt templates if any are present.

  This function checks if any messages contain PromptTemplate structs and if so,
  uses LLMChain.apply_prompt_templates to resolve them with the provided template variables.
  Otherwise, it adds messages directly to the chain.
  """
  def add_messages_with_templates(chain, messages, data) do
    if has_prompt_templates?(messages) do
      template_vars = build_template_variables(data)
      LLMChain.apply_prompt_templates(chain, messages, template_vars)
    else
      LLMChain.add_messages(chain, messages)
    end
  end

  @doc """
  Checks if any messages contain PromptTemplate structs in their content.
  """
  def has_prompt_templates?(messages) do
    Enum.any?(messages, fn message ->
      case message.content do
        content when is_list(content) ->
          Enum.any?(content, &match?(%LangChain.PromptTemplate{}, &1))

        _ ->
          false
      end
    end)
  end

  @doc """
  Builds template variables from adapter data, including input, context, and action arguments.
  """
  def build_template_variables(data) do
    Map.merge(
      %{
        input: data.input,
        context: data.context
      },
      # Extract additional variables that might be passed through arguments
      extract_template_args(data.input)
    )
  end

  defp extract_template_args(%{arguments: args}) when is_map(args) do
    # Extract common template variables from action arguments
    args
    |> Map.take([:extra_image_info, :template_vars, :context_vars])
    |> Enum.into(%{})
  end

  defp extract_template_args(_), do: %{}
end
