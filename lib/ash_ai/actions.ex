# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Actions do
  @moduledoc "Builtin generic action implementations"

  defmacro prompt(llm, opts \\ []) do
    {llm, function1} =
      Spark.CodeHelpers.lift_functions(llm, :ash_ai_prompt_llm, __CALLER__)

    {opts, function3} =
      Spark.CodeHelpers.lift_functions(opts, :ash_ai_prompt_opts, __CALLER__)

    quote do
      unquote(function1)
      unquote(function3)

      {AshAi.Actions.Prompt, Keyword.merge(unquote(opts), llm: unquote(llm))}
    end
  end
end
