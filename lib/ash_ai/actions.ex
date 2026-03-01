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

  defmacro prompt(model, opts \\ []) do
    {opts, lifted_functions} =
      Spark.CodeHelpers.lift_functions(opts, :ash_ai_prompt_opts, __CALLER__)

    quote do
      unquote(lifted_functions)

      {AshAi.Actions.Prompt, Keyword.merge(unquote(opts), model: unquote(model))}
    end
  end
end
