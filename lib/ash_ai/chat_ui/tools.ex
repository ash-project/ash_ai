# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.ChatUI.Tools do
  @moduledoc """
  Normalizes tool call and tool result data for generated chat UIs.

  `mix ash_ai.gen.chat` templates delegate to `extract/1` so the generated modules
  stay small and the parsing behavior is centralized in AshAi.

  Advanced apps can override the generated delegation seam:

      @chat_ui_tools MyApp.ChatUITools
  """

  alias Ash.Error.Unknown.UnknownError

  @type tool_call :: %{
          required(:id) => String.t(),
          required(:name) => String.t(),
          required(:arguments) => map(),
          required(:arguments_preview) => String.t()
        }

  @type tool_result :: %{
          required(:id) => String.t(),
          required(:name) => String.t() | nil,
          required(:content) => term(),
          required(:is_error) => boolean(),
          required(:content_preview) => String.t()
        }

  @type extracted_tool_data :: %{
          required(:tool_calls) => [tool_call()],
          required(:tool_results) => [tool_result()]
        }

  @spec extract(map() | struct()) :: {:ok, extracted_tool_data()} | {:error, Ash.Error.t()}
  def extract(message) when is_map(message) do
    with {:ok, raw_tool_calls} <- fetch_list_field(message, :tool_calls),
         {:ok, raw_tool_results} <- fetch_list_field(message, :tool_results) do
      tool_calls = normalize_tool_calls(raw_tool_calls)
      calls_by_id = Map.new(tool_calls, fn call -> {call.id, call.name} end)
      tool_results = normalize_tool_results(raw_tool_results, calls_by_id)

      {:ok, %{tool_calls: tool_calls, tool_results: tool_results}}
    end
  end

  def extract(message) do
    {:error, invalid_payload_error("message", message, "a map or struct")}
  end

  defp fetch_list_field(message, field) do
    case map_field(message, field) do
      nil ->
        {:ok, []}

      value when is_list(value) ->
        {:ok, value}

      value ->
        {:error, invalid_payload_error(Atom.to_string(field), value, "a list or nil")}
    end
  end

  defp normalize_tool_calls(tool_calls) when is_list(tool_calls) do
    Enum.flat_map(tool_calls, fn
      call when is_map(call) ->
        case normalize_tool_call(call) do
          nil -> []
          normalized -> [normalized]
        end

      _ ->
        []
    end)
  end

  defp normalize_tool_call(call) when is_map(call) do
    req_llm_call = safe_req_llm_tool_call_from_map(call)
    id = req_llm_call[:id] || map_field(call, :id) || map_field(call, :call_id)

    name =
      req_llm_call[:name] || map_field(call, :name) ||
        map_field(map_field(call, :function), :name)

    arguments =
      req_llm_call[:arguments]
      |> normalize_tool_call_arguments(call)

    if is_binary(name) do
      %{
        id: if(is_binary(id), do: id, else: "call_unknown"),
        name: name,
        arguments: arguments,
        arguments_preview: tool_call_arguments_preview(arguments)
      }
    end
  end

  defp safe_req_llm_tool_call_from_map(call) do
    ReqLLM.ToolCall.from_map(call)
  rescue
    _ -> %{}
  end

  defp normalize_tool_call_arguments(nil, call) do
    call
    |> call_arguments()
    |> normalize_raw_tool_call_arguments()
  end

  defp normalize_tool_call_arguments(arguments, call) when is_map(arguments) do
    if arguments == %{} do
      call
      |> call_arguments()
      |> normalize_raw_tool_call_arguments()
    else
      arguments
    end
  end

  defp normalize_tool_call_arguments(arguments, _call),
    do: normalize_raw_tool_call_arguments(arguments)

  defp call_arguments(call) do
    map_field(call, :arguments) ||
      call
      |> map_field(:function)
      |> map_field(:arguments)
  end

  defp normalize_raw_tool_call_arguments(nil), do: %{}
  defp normalize_raw_tool_call_arguments(arguments) when is_map(arguments), do: arguments

  defp normalize_raw_tool_call_arguments(arguments) when is_binary(arguments) do
    case Jason.decode(arguments) do
      {:ok, decoded} when is_map(decoded) -> decoded
      _ -> %{"raw" => arguments}
    end
  end

  defp normalize_raw_tool_call_arguments(arguments), do: %{"raw" => inspect(arguments)}

  defp tool_call_arguments_preview(arguments) do
    arguments
    |> safe_json_encode()
    |> String.slice(0, 80)
  end

  defp normalize_tool_results(tool_results, calls_by_id) when is_list(tool_results) do
    Enum.flat_map(tool_results, fn
      result when is_map(result) ->
        case normalize_tool_result(result, calls_by_id) do
          nil -> []
          normalized -> [normalized]
        end

      _ ->
        []
    end)
  end

  defp normalize_tool_result(result, calls_by_id) when is_map(result) do
    id = map_field(result, :tool_call_id) || map_field(result, :id) || map_field(result, :call_id)
    name = map_field(result, :name)
    content = map_field(result, :content)

    if is_binary(id) || not is_nil(content) do
      %{
        id: if(is_binary(id), do: id, else: "tool_result"),
        name:
          if(is_binary(name),
            do: name,
            else: if(is_binary(id), do: Map.get(calls_by_id, id), else: nil)
          ),
        content: content,
        is_error: normalize_is_error(map_field(result, :is_error)),
        content_preview: tool_result_preview(content)
      }
    end
  end

  defp normalize_is_error(true), do: true
  defp normalize_is_error("true"), do: true
  defp normalize_is_error(_), do: false

  defp tool_result_preview(content) do
    content
    |> normalize_text_content()
    |> String.replace(~r/\s+/, " ")
    |> String.trim()
    |> String.slice(0, 180)
  end

  defp normalize_text_content(nil), do: ""

  defp normalize_text_content(content) when is_binary(content) do
    case Jason.decode(content) do
      {:ok, decoded} -> normalize_text_content(decoded)
      {:error, _} -> content
    end
  end

  defp normalize_text_content(content) when is_map(content) or is_list(content) do
    safe_json_encode(content)
  end

  defp normalize_text_content(content), do: inspect(content)

  defp safe_json_encode(content) do
    case Jason.encode(content) do
      {:ok, encoded} -> encoded
      {:error, _} -> inspect(content)
    end
  end

  defp map_field(message, key) when is_map(message) do
    case message do
      %{^key => value} ->
        value

      %{} ->
        Map.get(message, Atom.to_string(key))
    end
  end

  defp map_field(_message, _key), do: nil

  defp invalid_payload_error(field, value, expected) do
    Ash.Error.to_error_class(
      UnknownError.exception(
        error: "Invalid #{field}: expected #{expected}, got #{inspect(value_type(value))}"
      )
    )
  end

  defp value_type(value) when is_map(value) and not is_struct(value), do: :map
  defp value_type(value) when is_map(value), do: {:struct, value.__struct__}
  defp value_type(value) when is_list(value), do: :list
  defp value_type(value) when is_binary(value), do: :binary
  defp value_type(value) when is_boolean(value), do: :boolean
  defp value_type(value) when is_integer(value), do: :integer
  defp value_type(value) when is_float(value), do: :float
  defp value_type(nil), do: nil
  defp value_type(value) when is_atom(value), do: :atom
  defp value_type(_value), do: :term
end
