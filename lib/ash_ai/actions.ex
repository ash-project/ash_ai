# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Actions do
  @moduledoc """
  Builtin generic action implementations.

  ## ReqLLM-based Prompt Actions

  The `prompt/2` macro accepts ReqLLM-compatible model specifications and uses
  ReqLLM for structured output generation.

  ### Examples

      action :analyze_sentiment, Sentiment do
        argument :text, :string, allow_nil?: false

        run prompt("openai:gpt-4o",
          prompt: [
            %{role: "system", content: "You analyze sentiment."},
            %{role: "user", content: "Analyze: <%= @input.arguments.text %>"}
          ]
        )
      end

  ### Prompt Formats

  The `:prompt` option supports multiple formats:

  1. **String (EEx template)**: `"Analyze this: <%= @input.arguments.text %>"`
  2. **{System, User} tuple**: `{"You are an expert", "Analyze: <%= @input.arguments.text %>"}`
  3. **ReqLLM.Context**: Pass a context directly (canonical format)
  4. **List of messages**: Maps, ReqLLM.Message structs, or mixed
  5. **Function returning any of the above**: `fn input, context -> ... end`

  ### Using ReqLLM.Context (Recommended)

      import ReqLLM.Context

      run prompt("openai:gpt-4o",
        prompt: fn input, _ctx ->
          ReqLLM.Context.new([
            system("You are an OCR expert"),
            user([
              ReqLLM.Message.ContentPart.text("Extract text"),
              ReqLLM.Message.ContentPart.image_url(input.arguments.image_url)
            ])
          ])
        end
      )
  """

  @doc """
  Configures an evaluation action backed by `AshAi.Actions.Evaluate`.

  Evaluation models such as TypeSafe's Jev answer typed questions about the
  action's inputs instead of generating text. The return type must be an
  answer type (`AshAi.Evaluate.Choice`, `AshAi.Evaluate.Noul`,
  `AshAi.Evaluate.Score`) or `AshAi.Evaluate.Judgments`.

      action :urgent, AshAi.Evaluate.Noul do
        description "Does `ticket` convey urgency?"
        argument :ticket, :string, allow_nil?: false

        run evaluate("typesafe:jev-latest")
      end
  """
  defmacro evaluate(model, opts \\ []) do
    {model, lifted_model} =
      Spark.CodeHelpers.lift_functions(model, :ash_ai_evaluate_model, __CALLER__)

    {opts, lifted_functions} =
      Spark.CodeHelpers.lift_functions(opts, :ash_ai_evaluate_opts, __CALLER__)

    quote do
      unquote(lifted_model)
      unquote(lifted_functions)

      {AshAi.Actions.Evaluate, Keyword.merge(unquote(opts), model: unquote(model))}
    end
  end

  defmacro prompt(model, opts \\ []) do
    {model, lifted_model} =
      Spark.CodeHelpers.lift_functions(model, :ash_ai_prompt_model, __CALLER__)

    {opts, lifted_functions} =
      Spark.CodeHelpers.lift_functions(opts, :ash_ai_prompt_opts, __CALLER__)

    quote do
      unquote(lifted_model)
      unquote(lifted_functions)

      {AshAi.Actions.Prompt, Keyword.merge(unquote(opts), model: unquote(model))}
    end
  end
end
