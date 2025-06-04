defmodule AshAi.Actions.Prompt do
  @prompt_template {"""
                    You are responsible for performing the `<%= @input.action.name %>` action.

                    <%= if @input.action.description do %>
                    # Description
                    <%= @input.action.description %>
                    <% end %>

                    ## Inputs
                    <%= for argument <- @input.action.arguments do %>
                    - <%= argument.name %><%= if argument.description do %>: <%= argument.description %>
                    <% end %>
                    <% end %>
                    """,
                    """
                    # Action Inputs

                    <%= for argument <- @input.action.arguments,
                        {:ok, value} = Ash.ActionInput.fetch_argument(@input, argument.name),
                        {:ok, value} = Ash.Type.dump_to_embedded(argument.type, value, argument.constraints) do %>
                      - <%= argument.name %>: <%= Jason.encode!(value) %>
                    <% end %>
                    """}
  @moduledoc """
  A generic action impl that returns structured outputs from an LLM matching the action return.

  Typically used via `prompt/2`, for example:

  ```elixir
  action :analyze_sentiment, :atom do
    constraints one_of: [:positive, :negative]

    description \"""
    Analyzes the sentiment of a given piece of text to determine if it is overall positive or negative.

    Does not consider swear words as inherently negative.
    \"""

    argument :text, :string do
      allow_nil? false
      description "The text for analysis."
    end

    run prompt(
      LangChain.ChatModels.ChatOpenAI.new!(%{ model: "gpt-4o"}),
      # setting `tools: true` allows it to use all exposed tools in your app
      tools: true
      # alternatively you can restrict it to only a set of tools
      # tools: [:list, :of, :tool, :names]
      # provide an optional prompt, which is an EEx template
      # prompt: "Analyze the sentiment of the following text: <%= @input.arguments.description %>"
    )
  end
  ```

  The first argument to `prompt/2` is the `LangChain` model. It can also be a 2-arity function which will be invoked
  with the input and the context, useful for dynamically selecting the model.

  ## Dynamic Configuration (using 2-arity function)

  For runtime configuration (like using environment variables), pass a function
  as the first argument to `prompt/2`:

      run prompt(
        fn _input, _context ->
          LangChain.ChatModels.ChatOpenAI.new!(%{
            model: "gpt-4o",
            # this can also be configured in application config, see langchain docs for more.
            api_key: System.get_env("OPENAI_API_KEY"),
            endpoint: System.get_env("OPENAI_ENDPOINT")
          })
        end,
        tools: false
      )

  This function will be executed just before the prompt is sent to the LLM.

  ## Options

  - `:tools`: A list of tool names to expose to the agent call.
  - `:verbose?`: Set to `true` for more output to be logged.
  - `:prompt`: A custom prompt as an `EEx` template. See the prompt section below.

  ## Prompt

  The prompt by default is generated using the action and input descriptions. You can provide your own prompt
  via the `prompt` option which will be able to reference `@input` and `@context`.

  The prompt can be a string or a tuple of two strings. The first string is the system prompt and the second string is the user message.
  If no user message is provided, the user message will be "perform the action". Both are treated as EEx templates.

  We have found that the "3rd party" style description writing paired with the format we provide by default to be
  a good basis point for LLMs who are meant to accomplish a task. With this in mind, for refining your prompt,
  first try describing via the action description that desired outcome or operating basis of the action, as well
  as how the LLM is meant to use them. State these passively as facts. For example, above we used: "Does not consider swear
  words as inherently negative" instead of instructing the LLM via "Do not consider swear words as inherently negative".

  You are of course free to use any prompting pattern you prefer, but the end result of the above prompting pattern
  leads to having a great description of your actual logic, acting both as documentation and instructions to the
  LLM that executes the action.

  The default prompt template is:

  ```elixir
  #{inspect(@prompt_template, pretty: true)}
  ```
  """
  use Ash.Resource.Actions.Implementation

  def run(input, opts, context) do
    llm = get_llm(opts, input, context)
    json_schema = get_json_schema(input)
    {adapter, adapter_opts} = get_adapter(opts, llm)
    {system_prompt, user_message} = get_prompts(input, opts, context)
    tools = get_tools(opts, input, context)

    data = %AshAi.Actions.Prompt.Adapter.Data{
      llm: llm,
      input: input,
      system_prompt: system_prompt,
      user_message: user_message,
      json_schema: json_schema,
      tools: tools,
      verbose?: opts[:verbose?] || false,
      context: context
    }

    adapter.run(data, adapter_opts)
  end

  defp get_tools(opts, input, context) do
    case opts[:tools] do
      nil ->
        []

      true ->
        otp_app =
          Spark.otp_app(input.domain) ||
            Spark.otp_app(input.resource) ||
            raise "otp_app must be configured on the domain or the resource to get access to all tools"

        AshAi.functions(
          otp_app: otp_app,
          exclude_actions: [{input.resource, input.action.name}],
          actor: context.actor,
          tenant: context.tenant
        )

      tools ->
        otp_app =
          Spark.otp_app(input.domain) ||
            Spark.otp_app(input.resource) ||
            raise "otp_app must be configured on the domain or the resource to get access to all tools"

        AshAi.functions(
          tools: List.wrap(tools),
          otp_app: otp_app,
          exclude_actions: [{input.resource, input.action.name}],
          actor: context.actor,
          tenant: context.tenant
        )
    end
  end

  defp get_llm(opts, input, context) do
    case opts[:llm] do
      function when is_function(function) ->
        function.(input, context)

      llm ->
        llm
    end
  end

  defp get_json_schema(input) do
    if input.action.returns do
      schema =
        AshJsonApi.OpenApi.resource_write_attribute_type(
          %{name: :result, type: input.action.returns, constraints: input.action.constraints},
          nil,
          :create
        )

      if input.action.allow_nil? do
        %{"anyOf" => [%{"type" => "null"}, schema]}
      else
        schema
      end
    else
      %{"type" => "null"}
    end
    |> Jason.encode!()
    |> Jason.decode!()
  end

  defp get_adapter(opts, llm) do
    adapter =
      opts[:adapter] ||
        case llm do
          %LangChain.ChatModels.ChatOpenAI{endpoint: endpoint}
          when endpoint != "https://api.openai.com" ->
            AshAi.Actions.Prompt.Adapter.RequestJsonTool

          %LangChain.ChatModels.ChatOpenAI{} ->
            AshAi.Actions.Prompt.Adapter.StructuredOutput

          %LangChain.ChatModels.ChatAnthropic{} ->
            AshAi.Actions.Prompt.Adapter.CompletionTool

          _ ->
            raise """
            No default adapter found for the given LLM.
            Please provide an adapter or use a supported LLM.

            #{inspect(llm)}
            """
        end

    case adapter do
      {adapter, adapter_opts} -> {adapter, adapter_opts}
      adapter -> {adapter, []}
    end
  end

  # sobelow_skip ["RCE.EEx"]
  defp get_prompts(input, opts, context) do
    case Keyword.get(opts, :prompt, @prompt_template) do
      {prompt, user_message} ->
        prompt = EEx.eval_string(prompt, assigns: [input: input, context: context])

        user_message =
          EEx.eval_string(user_message, assigns: [input: input, context: context])

        {prompt, user_message}

      prompt ->
        prompt = EEx.eval_string(prompt, assigns: [input: input, context: context])
        {prompt, "Perform the action"}
    end
  end
end
