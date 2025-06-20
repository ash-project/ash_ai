defmodule AshAi.Mcp.Capabilities.Sampling do
  @moduledoc """
  MCP Sampling capability implementation for AshAi.

  This capability exposes AshAi's LLM functionality through the MCP sampling protocol,
  allowing MCP clients to perform text generation using configured chat models.
  """

  @behaviour AshAi.Mcp.Capability

  require Logger

  @impl true
  def capability_name, do: "sampling"

  @impl true
  def capability_config do
    %{
      "sampling" => %{}
    }
  end

  @impl true
  def list_items(_session_id, _opts) do
    # Sampling capability doesn't have listable items
    {:ok, []}
  end

  @impl true
  def handle_method("sampling/createMessage", params, session_id, opts) do
    Logger.debug("Handling sampling request for session #{session_id}")

    with {:ok, validated_params} <- validate_sampling_params(params),
         {:ok, response} <- create_message(validated_params, opts) do
      {:ok, response}
    else
      {:error, reason} ->
        Logger.warning("Sampling request failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  def handle_method(_method, _params, _session_id, _opts) do
    :not_handled
  end

  # Private functions

  defp validate_sampling_params(params) do
    required_fields = ["messages"]
    optional_fields = ["modelPreferences", "systemPrompt", "includeContext", "maxTokens", "temperature"]

    case validate_required_fields(params, required_fields) do
      :ok ->
        validated = Map.take(params, required_fields ++ optional_fields)
        {:ok, validated}

      {:error, missing_fields} ->
        {:error, {:invalid_params, "Missing required fields: #{Enum.join(missing_fields, ", ")}"}}
    end
  end

  defp validate_required_fields(params, required_fields) do
    missing_fields = 
      required_fields
      |> Enum.reject(&Map.has_key?(params, &1))

    if Enum.empty?(missing_fields) do
      :ok
    else
      {:error, missing_fields}
    end
  end

  defp create_message(params, opts) do
    messages = params["messages"]
    model_preferences = params["modelPreferences"] || %{}
    system_prompt = params["systemPrompt"]
    max_tokens = params["maxTokens"]
    temperature = params["temperature"]

    # Build the chat model configuration
    chat_model_opts = build_chat_model_opts(model_preferences, max_tokens, temperature)

    # Create the message chain
    case build_message_chain(messages, system_prompt, chat_model_opts, opts) do
      {:ok, response_message} ->
        {:ok, %{
          "model" => get_model_name(chat_model_opts),
          "role" => "assistant", 
          "content" => %{
            "type" => "text",
            "text" => response_message
          }
        }}

      {:error, reason} ->
        {:error, {:sampling_failed, reason}}
    end
  end

  defp build_chat_model_opts(model_preferences, max_tokens, temperature) do
    base_opts = %{}

    base_opts
    |> maybe_put(:model, model_preferences["hints"]["name"])
    |> maybe_put(:max_tokens, max_tokens)
    |> maybe_put(:temperature, temperature)
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp build_message_chain(messages, system_prompt, chat_model_opts, opts) do
    try do
      # Get the default chat model from configuration or use OpenAI as fallback
      chat_model = get_chat_model(chat_model_opts, opts)
      
      # Build LangChain messages
      langchain_messages = build_langchain_messages(messages, system_prompt)

      # Create and execute the chain
      chain_opts = %{
        llm: chat_model,
        verbose: false
      }

      case LangChain.Chains.LLMChain.new(chain_opts) do
        {:ok, chain} ->
          # Add messages to the chain
          updated_chain = Enum.reduce(langchain_messages, chain, fn message, acc ->
            LangChain.Chains.LLMChain.add_message(acc, message)
          end)

          # Execute the chain
          case LangChain.Chains.LLMChain.run(updated_chain, mode: :while_needs_response) do
            {:ok, %LangChain.Chains.LLMChain{last_message: %{content: content}}} 
            when is_binary(content) ->
              {:ok, content}

            {:ok, _chain} ->
              {:error, :no_response_content}

            {:error, _chain, reason} ->
              {:error, {:chain_execution_failed, reason}}
          end

        {:error, reason} ->
          {:error, {:chain_creation_failed, reason}}
      end
    rescue
      error ->
        {:error, {:sampling_error, error}}
    end
  end

  defp get_chat_model(chat_model_opts, opts) do
    # Try to get configured model from opts first
    case opts[:chat_model] do
      model when not is_nil(model) ->
        model

      nil ->
        # Fallback to default OpenAI model
        model_name = chat_model_opts[:model] || "gpt-4o"
        
        openai_opts = %{model: model_name}
        |> maybe_put(:max_tokens, chat_model_opts[:max_tokens])
        |> maybe_put(:temperature, chat_model_opts[:temperature])

        LangChain.ChatModels.ChatOpenAI.new!(openai_opts)
    end
  end

  defp build_langchain_messages(messages, system_prompt) do
    langchain_messages = []

    # Add system prompt if provided
    langchain_messages = 
      if system_prompt do
        [LangChain.Message.new_system!(system_prompt) | langchain_messages]
      else
        langchain_messages
      end

    # Convert MCP messages to LangChain messages
    mcp_messages = Enum.map(messages, &convert_mcp_message_to_langchain/1)
    
    Enum.reverse(langchain_messages) ++ mcp_messages
  end

  defp convert_mcp_message_to_langchain(mcp_message) do
    role = mcp_message["role"]
    content = extract_message_content(mcp_message["content"])

    case role do
      "user" ->
        LangChain.Message.new_user!(content)
      
      "assistant" ->
        LangChain.Message.new_assistant!(content)
      
      "system" ->
        LangChain.Message.new_system!(content)
      
      _ ->
        # Default to user for unknown roles
        LangChain.Message.new_user!(content)
    end
  end

  defp extract_message_content(content) when is_binary(content) do
    content
  end

  defp extract_message_content(%{"type" => "text", "text" => text}) do
    text
  end

  defp extract_message_content(%{"text" => text}) do
    text
  end

  defp extract_message_content(content) when is_list(content) do
    # Handle content arrays by joining text parts
    content
    |> Enum.map(fn
      %{"type" => "text", "text" => text} -> text
      %{"text" => text} -> text
      text when is_binary(text) -> text
      _ -> ""
    end)
    |> Enum.join(" ")
  end

  defp extract_message_content(_content) do
    ""
  end


  defp get_model_name(chat_model_opts) do
    chat_model_opts[:model] || "gpt-4o"
  end
end