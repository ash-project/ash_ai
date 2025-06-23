defmodule AshAi.Actions.Prompt.Adapter do
  @moduledoc """
  Behavior for prompt-backed-action adapters.

  These adapters allow for different methodologies of handling prompt-based actions.
  For example, OpenAI supports "structured outputs", which will guarantee a response
  matching a requested JSON Schema. Other services however can still be used with prompt-based
  actions by providing them a tool that should be called when the action is complete.

  ## Built in Adapters

  - `AshAi.Actions.Prompt.Adapter.StructuredOutput` - Use an LLM that is guaranteed to return the requested JSON Schema.
  - `AshAi.Actions.Prompt.Adapter.CompletionTool` - Use an LLM and run it until it calls a "completion" tool, up to `max_runs` times.
  - `AshAi.Actions.Prompt.Adapter.RequestJson` - Use an LLM and request that it responds with a specific JSON format, and attempt to parse it.

  See the adapter's documentation for more.

  ## Custom Adapters & Adapter Options

  If you want to provide a custom adapter, or customize the options for an adapter,
  you can specify the `adapter` option in your `prompt/2` call.

  ```elixir

  run prompt(%{...}, adapter: {AshAi.Actions.Prompt.Adapter.CompletionTool, max_runs: 5})

  ```
  """

  defmodule Data do
    @moduledoc """
    Data structure containing all the information needed for a prompt request.
    """

    defstruct [
      :llm,
      :input,
      :messages,
      :verbose?,
      :json_schema,
      :tools,
      :context
    ]

    @type t :: %__MODULE__{
            llm: term(),
            input: Ash.ActionInput.t(),
            messages: list(),
            json_schema: map(),
            tools: list(),
            verbose?: boolean(),
            context: Ash.Resource.Actions.Implementation.Context.t()
          }
  end

  @doc """
  Execute a prompt request with the given data and adapter options.

  ## Parameters

  - `data` - An `AshAi.Actions.Prompt.Data` struct containing all the prompt information
  - `opts` - Adapter-specific options

  ## Returns

  - `{:ok, result}` - On successful completion
  - `{:error, reason}` - On failure
  """
  @callback run(data :: Data.t(), opts :: Keyword.t()) ::
              {:ok, term()} | {:error, term()}
end
