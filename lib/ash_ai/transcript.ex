# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

if Code.ensure_loaded?(ReqLLM) do
  defmodule AshAi.Transcript do
    @moduledoc """
    Converts the assistant and tool messages of a tool loop to and from
    JSON-safe "parts", so they can be stored on a message row and replayed
    exactly.

    A stored reply is an ordered list of parts:

        [%{"type" => "step"},
         %{"type" => "reasoning", "text" => "...", "metadata" => ...},
         %{"type" => "text", "text" => "Let me check."},
         %{"type" => "tool_call", "id" => "c1", "name" => "list_items", "arguments" => "{}"},
         %{"type" => "tool_result", "id" => "c1", "content" => "[...]"},
         %{"type" => "step"},
         %{"type" => "text", "text" => "You have 3 items."}]

    Each assistant message starts with a `"step"` part, which carries its
    message-level metadata. Tool results follow their assistant message. Parts
    of consecutive messages concatenate, so `to_parts(a) ++ to_parts(b)` equals
    `to_parts(a ++ b)`, which lets callers append the parts of each
    `{:message, message}` event from `AshAi.ToolLoop.stream/2` as it arrives.

    Reasoning (thinking blocks, signatures, encrypted reasoning) is opaque
    provider data. Pass `reasoning: false` to leave it out. Replaying a turn
    without its reasoning is accepted by current providers, but the model loses
    that reasoning, and a paused tool round resumes without it.

    Provider-specific values are encoded losslessly with `AshAi.Transcript.Codec`,
    so stores only need a JSON (or jsonb) column. Encrypt it if tool results or
    reasoning are sensitive.
    """

    alias AshAi.Transcript.Codec
    alias ReqLLM.Message
    alias ReqLLM.Message.ContentPart

    @reasoning_block_types ["thinking", "redacted_thinking"]

    @doc """
    Converts assistant and tool messages to parts.

    ## Options

    - `:reasoning` - keep thinking and reasoning data. Defaults to `true`.
    """
    @spec to_parts([Message.t()], keyword()) :: [map()]
    def to_parts(messages, opts \\ []) do
      reasoning? = Keyword.get(opts, :reasoning, true)
      Enum.flat_map(List.wrap(messages), &message_to_parts(&1, reasoning?))
    end

    @doc """
    Rebuilds messages from parts created by `to_parts/2`.
    """
    @spec from_parts([map()]) :: [Message.t()]
    def from_parts(parts) do
      parts
      |> List.wrap()
      |> Enum.reduce({[], nil}, &add_part/2)
      |> close_assistant()
      |> elem(0)
      |> Enum.reverse()
    end

    @doc """
    Removes reasoning from messages.

    Use it before replaying a turn whose reasoning can no longer be sent, for
    example when the system prompt or tools changed since it was produced.
    """
    @spec strip_reasoning([Message.t()]) :: [Message.t()]
    def strip_reasoning(messages) do
      Enum.map(messages, fn
        %Message{role: :assistant} = message ->
          %{
            message
            | content: Enum.reject(message.content, &reasoning_part?/1),
              reasoning_details: nil
          }

        message ->
          message
      end)
    end

    @doc """
    Returns the text the assistant wrote, joined across steps.
    """
    @spec text([map()]) :: String.t()
    def text(parts) do
      parts
      |> Enum.filter(&(&1["type"] == "text"))
      |> Enum.map_join("", & &1["text"])
    end

    @doc """
    Returns the tool calls in `parts` that have no result yet, in call order.
    """
    @spec pending_tool_calls([map()]) :: [map()]
    def pending_tool_calls(parts) do
      answered =
        for %{"type" => "tool_result", "id" => id} <- parts, into: MapSet.new(), do: id

      Enum.filter(parts, &(&1["type"] == "tool_call" and not MapSet.member?(answered, &1["id"])))
    end

    @doc """
    A stable hash of a system prompt and tool list.

    Store it with a turn that keeps reasoning. If the hash differs when the turn
    is replayed, call `strip_reasoning/1` first: reasoning is bound to the
    system prompt and tools it was produced with.
    """
    @spec fingerprint(String.t() | nil, [ReqLLM.Tool.t()]) :: String.t()
    def fingerprint(system_prompt, tools) do
      tools =
        Enum.map(tools, fn
          %ReqLLM.Tool{} = tool ->
            {tool.name, tool.description, tool.parameter_schema, tool.strict,
             tool.provider_options}

          other ->
            other
        end)

      :sha256
      |> :crypto.hash(:erlang.term_to_binary({system_prompt, tools}, [:deterministic]))
      |> Base.url_encode64(padding: false)
    end

    defp message_to_parts(%Message{role: :assistant} = message, reasoning?) do
      step =
        %{"type" => "step"}
        |> put_encoded("metadata", message.metadata)
        |> put_encoded("reasoning_details", reasoning? && message.reasoning_details)

      content =
        message.content
        |> Enum.reject(&(not reasoning? and reasoning_part?(&1)))
        |> Enum.map(&content_part_to_part/1)

      calls = Enum.map(message.tool_calls || [], &tool_call_to_part/1)

      [step | content] ++ calls
    end

    defp message_to_parts(%Message{role: :tool} = message, _reasoning?) do
      part =
        %{
          "type" => "tool_result",
          "id" => message.tool_call_id,
          "content" => result_content(message)
        }
        |> put_present("name", message.name)
        |> put_encoded("metadata", message.metadata)

      [part]
    end

    defp message_to_parts(%Message{role: role}, _reasoning?) do
      raise ArgumentError,
            "AshAi.Transcript stores assistant and tool messages, got a #{role} message"
    end

    defp content_part_to_part(%ContentPart{type: :text, text: text, metadata: metadata}) do
      put_encoded(%{"type" => "text", "text" => text}, "metadata", metadata)
    end

    defp content_part_to_part(%ContentPart{type: :thinking, text: text, metadata: metadata}) do
      put_encoded(%{"type" => "reasoning", "text" => text}, "metadata", metadata)
    end

    defp content_part_to_part(%ContentPart{type: :provider_block} = part) do
      %{"type" => "provider_block", "data" => Codec.encode(part.data)}
      |> put_encoded("metadata", part.metadata)
    end

    defp content_part_to_part(%ContentPart{} = part) do
      %{"type" => "content", "part" => Codec.encode(part)}
    end

    # Arguments stay the JSON string the model produced, so a replayed call is
    # byte-identical. Other function fields (provider signatures, builtin
    # markers) are kept in "extra".
    defp tool_call_to_part(%ReqLLM.ToolCall{id: id, function: function} = call) do
      %{
        "type" => "tool_call",
        "id" => id,
        "name" => function[:name] || function["name"],
        "arguments" => function[:arguments] || function["arguments"] || "{}"
      }
      |> put_encoded("extra", Map.drop(function, [:name, :arguments, "name", "arguments"]))
      |> put_present("call_type", if(call.type != "function", do: call.type))
    end

    # A single plain text part is stored as a string, which is what most tools
    # return and what UIs want to show. Anything else is stored losslessly.
    defp result_content(%Message{content: [%ContentPart{type: :text, text: text, metadata: m}]})
         when m == %{},
         do: text

    defp result_content(%Message{content: content}), do: Codec.encode(content)

    defp reasoning_part?(%ContentPart{type: :thinking}), do: true

    defp reasoning_part?(%ContentPart{type: :provider_block, data: data}) when is_map(data),
      do: (data["type"] || data[:type]) in @reasoning_block_types

    defp reasoning_part?(_part), do: false

    defp add_part(%{"type" => "step"} = part, acc) do
      {messages, _current} = close_assistant(acc)

      assistant = %Message{
        role: :assistant,
        content: [],
        tool_calls: [],
        metadata: decode(part["metadata"]) || %{},
        reasoning_details: decode(part["reasoning_details"])
      }

      {messages, assistant}
    end

    defp add_part(%{"type" => "tool_result"} = part, acc) do
      {messages, nil} = close_assistant(acc)

      content =
        case part["content"] do
          text when is_binary(text) -> [ContentPart.text(text)]
          encoded -> Codec.decode(encoded)
        end

      message = %Message{
        role: :tool,
        tool_call_id: part["id"],
        name: part["name"],
        content: content,
        metadata: decode(part["metadata"]) || %{}
      }

      {[message | messages], nil}
    end

    defp add_part(part, {messages, nil}) do
      add_part(part, add_part(%{"type" => "step"}, {messages, nil}))
    end

    defp add_part(%{"type" => "tool_call"} = part, {messages, assistant}) do
      call = ReqLLM.ToolCall.new(part["id"], part["name"], part["arguments"] || "{}")

      call = %{
        call
        | type: part["call_type"] || call.type,
          function: Map.merge(call.function, decode(part["extra"]) || %{})
      }

      {messages, %{assistant | tool_calls: [call | assistant.tool_calls]}}
    end

    defp add_part(part, {messages, assistant}) do
      {messages, %{assistant | content: [part_to_content_part(part) | assistant.content]}}
    end

    defp part_to_content_part(%{"type" => "text"} = part),
      do: ContentPart.text(part["text"], decode(part["metadata"]) || %{})

    defp part_to_content_part(%{"type" => "reasoning"} = part),
      do: ContentPart.thinking(part["text"], decode(part["metadata"]) || %{})

    defp part_to_content_part(%{"type" => "provider_block"} = part) do
      %ContentPart{
        type: :provider_block,
        data: Codec.decode(part["data"]),
        metadata: decode(part["metadata"]) || %{}
      }
    end

    defp part_to_content_part(%{"type" => "content", "part" => part}), do: Codec.decode(part)

    defp close_assistant({messages, nil}), do: {messages, nil}

    defp close_assistant({messages, assistant}) do
      tool_calls =
        case assistant.tool_calls do
          [] -> nil
          calls -> Enum.reverse(calls)
        end

      assistant = %{assistant | content: Enum.reverse(assistant.content), tool_calls: tool_calls}
      {[assistant | messages], nil}
    end

    defp put_encoded(map, _key, value) when value in [nil, false, [], %{}], do: map
    defp put_encoded(map, key, value), do: Map.put(map, key, Codec.encode(value))

    defp put_present(map, _key, nil), do: map
    defp put_present(map, key, value), do: Map.put(map, key, value)

    defp decode(nil), do: nil
    defp decode(value), do: Codec.decode(value)
  end
end
