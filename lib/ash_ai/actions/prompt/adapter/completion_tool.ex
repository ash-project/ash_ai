defmodule AshAi.Actions.Prompt.Adapter.CompletionTool do
  @moduledoc """
  An adapter that provides a "complete_request" tool that the LLM must call within `max_runs` messages to complete the request.

  ## Adapter Options

  - `:max_runs` - The maximum number of times to allow the LLM to repeatedly generate responses/call tools
    before the action is considered failed.
  """
  @behaviour AshAi.Actions.Prompt.Adapter
  # ignoring dialyzer warning on Message.new_system! as it will be fixed in next release: https://github.com/brainlid/langchain/pull/315
  @dialyzer {:nowarn_function, [run: 2]}

  alias AshAi.Actions.Prompt.Adapter.Data
  alias LangChain.Chains.LLMChain

  def run(%Data{} = data, opts) do
    messages = data.messages

    max_runs = opts[:max_runs] || 25

    {llm, deterministic?} =
      if Map.has_key?(data.llm, :tool_choice) && Enum.empty?(data.tools) do
        {%{data.llm | tool_choice: %{"type" => "tool", "name" => "complete_request"}}, true}
      else
        {data.llm, false}
      end

    description =
      if deterministic? do
        "Use this tool to complete the request."
      else
        """
        Use this tool to complete the request.
        This tool must be called after #{opts[:max_runs] || 25} messages or tool calls from you.
        """
      end

    completion_tool =
      LangChain.Function.new!(%{
        name: "complete_request",
        description: description,
        parameters_schema: %{
          "type" => "object",
          "properties" => %{"result" => data.json_schema},
          "required" => ["result"],
          "additionalProperties" => false
        },
        strict: true,
        function: fn arguments, _context ->
          with {:ok, value} <-
                 Ash.Type.cast_input(
                   data.input.action.returns,
                   arguments["result"],
                   data.input.action.constraints
                 ),
               {:ok, value} <-
                 Ash.Type.apply_constraints(
                   data.input.action.returns,
                   value,
                   data.input.action.constraints
                 ) do
            {:ok, "complete", value}
          else
            _error ->
              {:error,
               """
               Invalid response. Expected to match schema:

               #{inspect(data.json_schema, pretty: true)}
               """}
          end
        end
      })

    %{
      llm: llm,
      verbose: data.verbose?,
      custom_context: Map.new(Ash.Context.to_opts(data.context))
    }
    |> LLMChain.new!()
    |> AshAi.Actions.Prompt.Adapter.Helpers.add_messages_with_templates(messages, data)
    |> LLMChain.add_tools([completion_tool | data.tools])
    |> LLMChain.run_until_tool_used("complete_request", max_runs: max_runs)
    |> case do
      {:ok, _chain, message} ->
        {:ok, message.processed_content}

      {:error, _chain, error} ->
        {:error, error}
    end
  end
end
