# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Tool.Errors do
  @moduledoc """
  Formats Ash errors as JSON:API error objects for tool responses.

  This module handles error transformation to ensure that tool execution
  errors are returned in a consistent, parseable format that LLMs can
  understand and react to appropriately.
  """

  @doc """
  Formats an error as a JSON-encoded string of JSON:API errors.
  """
  def format(domain, resource, error, action_type) do
    error
    |> Ash.Error.to_error_class()
    |> then(&AshAi.to_json_api_errors(domain, resource, &1, action_type))
    |> serialize_errors()
    |> Jason.encode!()
  end

  @doc """
  Serializes a list of JSON:API error structs to maps.
  """
  def serialize_errors(errors) do
    errors
    |> List.wrap()
    |> Enum.map(fn error ->
      %{}
      |> add_if_defined(:id, error.id)
      |> add_if_defined(:status, to_string(error.status_code))
      |> add_if_defined(:code, error.code)
      |> add_if_defined(:title, error.title)
      |> add_if_defined(:detail, error.detail)
      |> add_if_defined([:source, :pointer], error.source_pointer)
      |> add_if_defined([:source, :parameter], error.source_parameter)
      |> add_if_defined(:meta, parse_error_meta(error.meta))
    end)
  end

  defp add_if_defined(params, _, :undefined), do: params

  defp add_if_defined(params, [key1, key2], value) do
    params
    |> Map.put_new(key1, %{})
    |> Map.update!(key1, &Map.put(&1, key2, value))
  end

  defp add_if_defined(params, key, value) do
    Map.put(params, key, value)
  end

  defp parse_error_meta(%{match: %Regex{} = match} = error) do
    %{error | match: Regex.source(match)}
  end

  defp parse_error_meta(error), do: error
end
