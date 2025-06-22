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

  alias AshAi.Actions.Prompt.Adapter.Helpers

  require Logger

  def run(input, opts, context) do
    llm = get_llm(opts, input, context)

    json_schema = get_json_schema(input)
    {adapter, adapter_opts} = get_adapter(opts, llm)

    tools = get_tools(opts, input, context)

    # Extract system_prompt and user_message from prompt processing
    {_messages, system_prompt, user_message} = get_messages_and_prompts(input, opts, context)

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
  defp get_messages_and_prompts(input, opts, context) do
    try do
      opts
      |> Keyword.get(:prompt, @prompt_template)
      |> log_prompt_type()
      |> process_prompt_option(input, context)
      |> finalize_prompt_result()
    rescue
      error ->
        Logger.warning("Error in get_messages_and_prompts: #{inspect(error)}")
        raise error
    end
  end

  defp log_prompt_type(prompt_option) do
    Logger.debug("Processing prompt type: #{get_prompt_type(prompt_option)}")
    prompt_option
  end

  # Handle {system, user} tuple format
  defp process_prompt_option({system, user}, input, context)
       when is_binary(system) and is_binary(user) do
    Logger.debug("Processing {system, user} tuple format")

    {system, user}
    |> process_eex_templates(input, context)
    |> tuple_to_messages()
  end

  # Handle string format
  defp process_prompt_option(prompt, input, context) when is_binary(prompt) do
    prompt
    |> process_string_prompt(input, context)
    |> tuple_to_messages()
  end

  # Handle function format
  defp process_prompt_option(func, input, context) when is_function(func, 2) do
    with {:ok, result} <- safe_function_call(func, input, context),
         {:ok, messages} <- validate_function_result(result, input, context) do
      messages
    else
      {:error, reason} ->
        Logger.warning("Function processing failed: #{reason}")
        raise ArgumentError, reason
    end
  end

  # Handle message list format
  defp process_prompt_option(messages, input, context) when is_list(messages) do
    Logger.debug("Processing list of #{length(messages)} messages")
    process_messages_with_templates(messages, input, context)
  end

  # Helper functions for data transformation
  defp process_eex_templates({system, user}, input, context) do
    assigns = [input: input, context: context]

    {
      EEx.eval_string(system, assigns: assigns),
      EEx.eval_string(user, assigns: assigns)
    }
  end

  defp process_string_prompt(prompt, input, context) do
    assigns = [input: input, context: context]
    processed_prompt = EEx.eval_string(prompt, assigns: assigns)
    {processed_prompt, "Perform the action"}
  end

  defp tuple_to_messages({system, user}) do
    [
      LangChain.Message.new_system!(system),
      LangChain.Message.new_user!(user)
    ]
  end

  defp safe_function_call(func, input, context) do
    try do
      result = func.(input, context)
      Logger.debug("Function returned: #{get_prompt_type(result)}")
      {:ok, result}
    rescue
      error ->
        {:error, "Function execution failed: #{inspect(error)}"}
    end
  end

  defp validate_function_result({system, user}, _input, _context)
       when is_binary(system) and is_binary(user) do
    Logger.debug("Function returned {system, user} tuple")
    messages = tuple_to_messages({system, user})
    {:ok, messages}
  end

  defp validate_function_result(messages, input, context) when is_list(messages) do
    Logger.debug("Function returned list of #{length(messages)} messages")
    processed_messages = process_messages_with_templates(messages, input, context)
    {:ok, processed_messages}
  end

  defp validate_function_result(other, _input, _context) do
    error =
      "Function must return either {system, user} tuple or list of LangChain Messages. " <>
        "Examples: {\"system_message\", \"user_message\"} or " <>
        "[Message.new_system!(\"Hello\"), Message.new_user!(\"Hi\")]. " <>
        "Got: #{inspect(other)}"

    {:error, error}
  end

  defp finalize_prompt_result(messages) when is_list(messages) do
    {system_prompt, user_message} = extract_legacy_prompts(messages)

    Logger.debug(
      "Extracted legacy prompts - system: #{String.length(system_prompt)} chars, user: #{String.length(user_message)} chars"
    )

    {messages, system_prompt, user_message}
  end

  defp extract_legacy_prompts(messages) do
    system_prompt =
      case Enum.find(messages, &(&1.role == :system)) do
        %LangChain.Message{content: content} when is_binary(content) -> content
        _ -> ""
      end

    user_message =
      case Enum.find(messages, &(&1.role == :user)) do
        %LangChain.Message{content: content} when is_binary(content) ->
          content

        %LangChain.Message{content: content} when is_list(content) ->
          # Extract only text content parts, safely handling PromptTemplates and other types
          content
          |> Enum.filter(fn part ->
            case part do
              %LangChain.Message.ContentPart{type: :text} -> true
              # Include PromptTemplates for legacy extraction
              %LangChain.PromptTemplate{} -> true
              _ -> false
            end
          end)
          |> Enum.map(fn
            %LangChain.Message.ContentPart{type: :text, content: text_content} ->
              # Only process text content parts, ensuring content is actually text
              if is_binary(text_content) and String.valid?(text_content),
                do: text_content,
                else: ""

            %LangChain.PromptTemplate{text: text} ->
              # For legacy extraction, just use the raw template text (don't process it)
              if is_binary(text) and String.valid?(text), do: text, else: ""

            _ ->
              ""
          end)
          |> Enum.join(" ")

        _ ->
          ""
      end

    {system_prompt, user_message}
  end

  defp process_messages_with_templates(messages, input, context) do
    case Helpers.has_prompt_templates?(messages) do
      true ->
        Logger.debug("Processing PromptTemplates using LangChain")
        apply_prompt_templates(messages, input, context)

      false ->
        Logger.debug("No templates to process, returning messages as-is")
        messages
    end
  end

  defp apply_prompt_templates(messages, input, context) do
    template_vars =
      %{input: input, context: context}
      |> Helpers.build_template_variables()

    Logger.debug("Template variables: #{inspect(Map.keys(template_vars))}")
    Logger.debug("Messages before template processing: #{length(messages)}")

    try do
      with {:ok, temp_chain} <- create_temp_chain() do
        # apply_prompt_templates returns the chain directly, not {:ok, chain}
        processed_chain =
          LangChain.Chains.LLMChain.apply_prompt_templates(temp_chain, messages, template_vars)

        Logger.debug(
          "Template processing successful, extracted #{length(processed_chain.messages)} messages"
        )

        processed_chain.messages
      else
        {:error, error} ->
          Logger.warning("Failed to create temp chain: #{inspect(error)}")
          raise ArgumentError, "Template processing failed: #{inspect(error)}"
      end
    rescue
      error ->
        Logger.warning("Template processing failed: #{inspect(error)}")
        raise ArgumentError, "Template processing failed: #{inspect(error)}"
    end
  end

  defp create_temp_chain do
    try do
      # Create a minimal dummy LLM for template processing only
      dummy_llm = LangChain.ChatModels.ChatOpenAI.new!(%{model: "gpt-3.5-turbo"})
      chain = LangChain.Chains.LLMChain.new!(%{llm: dummy_llm})
      {:ok, chain}
    rescue
      error -> {:error, error}
    end
  end

  defp get_prompt_type(prompt) do
    cond do
      is_binary(prompt) -> :string
      is_function(prompt, 2) -> :function
      is_list(prompt) -> :message_list
      match?({_, _}, prompt) -> :tuple
      true -> :unknown
    end
  end
end
