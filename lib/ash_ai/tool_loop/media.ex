# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

if Code.ensure_loaded?(ReqLLM) do
  defmodule AshAi.ToolLoop.Media do
    @moduledoc false
    # Tool results can carry images, such as those from
    # `AshAi.Mcp.Client.format_result/1`. They reach the model only when it
    # accepts image input and its provider's API carries images in tool
    # results; otherwise each is described in text. The conversation keeps the
    # images, so a later request to a model that accepts them still sends them.

    alias ReqLLM.Message
    alias ReqLLM.Message.ContentPart

    @doc """
    The messages to send `model`, with tool result images described when
    `images` (the `:tool_result_images` option) is `false`, or `:auto` and
    `model` can't receive them.
    """
    @spec prepare([Message.t()], LLMDB.Model.t(), :auto | boolean()) :: [Message.t()]
    def prepare(messages, model, images) do
      if images == true or (images == :auto and images_in_tool_results?(model)),
        do: messages,
        else: Enum.map(messages, &describe_images/1)
    end

    defp describe_images(%Message{role: :tool, content: content} = message)
         when is_list(content) do
      if Enum.any?(content, &image?/1),
        do: %{message | content: Enum.map(content, &describe/1)},
        else: message
    end

    defp describe_images(message), do: message

    # The APIs ReqLLM sends tool result images through: Anthropic's, Google's,
    # and OpenAI's Responses API. Chat Completions style APIs take only text
    # in tool messages, and the APIs left out haven't been checked.
    defp images_in_tool_results?(%LLMDB.Model{} = model) do
      accepts_images?(model) and
        case model.provider do
          provider when provider in [:anthropic, :google] -> true
          :openai -> openai_responses?(model)
          _provider -> false
        end
    end

    defp images_in_tool_results?(_model), do: false

    defp accepts_images?(%{modalities: %{input: input}}) when is_list(input), do: :image in input
    defp accepts_images?(_model), do: false

    defp openai_responses?(model) do
      match?({:ok, :openai_responses, _api, _warnings}, ReqLLM.RequestPlan.openai_surface(model))
    rescue
      _error -> false
    end

    defp image?(%ContentPart{type: type}), do: type in [:image, :image_url]
    defp image?(_part), do: false

    defp describe(%ContentPart{type: :image, media_type: type}),
      do: description(%{"type" => "image", "mimeType" => type})

    defp describe(%ContentPart{type: :image_url, url: url}),
      do: description(%{"type" => "image", "url" => url})

    defp describe(part), do: part

    defp description(image) do
      image
      |> Map.put("note", "image omitted: this model can't receive images in tool results")
      |> Jason.encode!()
      |> ContentPart.text()
    end
  end
end
