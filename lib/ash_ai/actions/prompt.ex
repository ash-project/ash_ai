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
  - `:prompt`: A custom prompt. Supports multiple formats - see the prompt section below.

  ## Prompt

  The prompt by default is generated using the action and input descriptions. You can provide your own prompt
  via the `prompt` option which supports multiple formats based on the type of data provided:

  ### Supported Formats

  1. **String (EEx template)**: `"Analyze this: <%= @input.arguments.text %>"`
  2. **{System, User} tuple**: `{"You are an expert", "Analyze the sentiment"}`
  3. **Function**: `fn input, context -> {"Dynamic system", "Dynamic user"} end`
  4. **List of LangChain Messages**: `[Message.new_system!("..."), Message.new_user!("...")]`
  5. **Function returning Messages**: `fn input, context -> [Message.new_system!("...")] end`

  ### Examples

  #### Basic String Template
  ```elixir
  run prompt(
    ChatOpenAI.new!(%{model: "gpt-4o"}),
    prompt: "Analyze the sentiment of: <%= @input.arguments.text %>"
  )
  ```

  #### System/User Tuple
  ```elixir
  run prompt(
    ChatOpenAI.new!(%{model: "gpt-4o"}),
    prompt: {"You are a sentiment analyzer", "Analyze: <%= @input.arguments.text %>"}
  )
  ```

  #### LangChain Messages for Multi-turn Conversations
  ```elixir
  run prompt(
    ChatOpenAI.new!(%{model: "gpt-4o"}),
    prompt: [
      Message.new_system!("You are an expert assistant"),
      Message.new_user!("Hello, how can you help me?"),
      Message.new_assistant!("I can help with various tasks"),
      Message.new_user!("Great! Please analyze this data")
    ]
  )
  ```

  #### Image Analysis with Templates
  ```elixir
  run prompt(
    ChatOpenAI.new!(%{model: "gpt-4o"}),
    prompt: [
      Message.new_system!("You are an expert at image analysis"),
      Message.new_user!([
        PromptTemplate.from_template!("Extra context: <%= @input.arguments.context %>"),
        ContentPart.image!("<%= @input.arguments.image_data %>", media: :jpg, detail: "low")
      ])
    ]
  )
  ```

  #### Dynamic Messages via Function
  ```elixir
  run prompt(
    ChatOpenAI.new!(%{model: "gpt-4o"}),
    prompt: fn input, context ->
      base = [Message.new_system!("You are helpful")]

      history = input.arguments.conversation_history
      |> Enum.map(fn %{"role" => role, "content" => content} ->
        case role do
          "user" -> Message.new_user!(content)
          "assistant" -> Message.new_assistant!(content)
        end
      end)

      base ++ history
    end
  )
  ```

  ### Template Processing

  - **String prompts**: Processed as EEx templates with `@input` and `@context`
  - **Messages with PromptTemplate**: Processed using LangChain's `apply_prompt_templates`
  - **Functions**: Can return any supported format for dynamic generation

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

    tools = get_tools(opts, input, context)

    messages = get_messages(input, opts, context)

    data = %AshAi.Actions.Prompt.Adapter.Data{
      llm: llm,
      input: input,
      messages: messages,
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
          %LangChain.ChatModels.ChatOpenAI{endpoint: "https://api.openai.com" <> _rest} ->
            AshAi.Actions.Prompt.Adapter.StructuredOutput

          %LangChain.ChatModels.ChatOpenAI{endpoint: endpoint} when not is_nil(endpoint) ->
            # For non-OpenAI endpoints, use RequestJson
            AshAi.Actions.Prompt.Adapter.RequestJson

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
  defp get_messages(input, opts, context) do
    template_vars = %{input: input, context: context}

    case Keyword.get(opts, :prompt, @prompt_template) do
      # Format 1: String (EEx template)
      prompt when is_binary(prompt) ->
        system_prompt = EEx.eval_string(prompt, assigns: [input: input, context: context])

        [
          LangChain.Message.new_system!(system_prompt),
          LangChain.Message.new_user!("Perform the action")
        ]

      # Format 2: Tuple {system, user} (EEx templates)
      {system, user} when is_binary(system) and is_binary(user) ->
        system_prompt = EEx.eval_string(system, assigns: [input: input, context: context])
        user_message = EEx.eval_string(user, assigns: [input: input, context: context])

        [
          LangChain.Message.new_system!(system_prompt),
          LangChain.Message.new_user!(user_message)
        ]

      # Format 3: Messages list (LangChain Messages)
      messages when is_list(messages) ->
        process_message_templates(messages, template_vars)

      # Format 4: Function returning any of the above
      func when is_function(func, 2) ->
        result = func.(input, context)
        get_messages_from_result(result, input, context)
    end
  end

  defp get_messages_from_result(result, input, context) do
    case result do
      prompt when is_binary(prompt) ->
        get_messages(input, [prompt: prompt], context)

      {system, user} when is_binary(system) and is_binary(user) ->
        get_messages(input, [prompt: {system, user}], context)

      messages when is_list(messages) ->
        get_messages(input, [prompt: messages], context)

      _ ->
        raise ArgumentError,
              "Function must return string, {system, user} tuple, or list of Messages. Got: #{inspect(result)}"
    end
  end

  defp process_message_templates(messages, template_vars) do
    if AshAi.Actions.Prompt.Adapter.Helpers.has_prompt_templates?(messages) do
      temp_chain = LangChain.Chains.LLMChain.new!(%{llm: create_dummy_llm()})

      processed_chain =
        LangChain.Chains.LLMChain.apply_prompt_templates(temp_chain, messages, template_vars)

      processed_chain.messages
    else
      messages
    end
  end

  defp create_dummy_llm do
    LangChain.ChatModels.ChatOpenAI.new!(%{model: "gpt-3.5-turbo"})
  end
end
