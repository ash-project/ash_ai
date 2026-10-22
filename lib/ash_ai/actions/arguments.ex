# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Actions.Arguments do
  @moduledoc false

  alias Ash.Error.Action.InvalidArgument

  @doc """
  Dumps each argument set on the input to its JSON-safe embedded form, in
  definition order. Arguments that were never set are omitted, and arguments
  that cannot be dumped are returned as `Ash.Error.Action.InvalidArgument`s.
  """
  @spec dump(Ash.ActionInput.t()) :: {:ok, [{atom(), term()}]} | {:error, Exception.t()}
  def dump(input) do
    {dumped, errors} =
      Enum.reduce(input.action.arguments, {[], []}, fn argument, {dumped, errors} ->
        case Ash.ActionInput.fetch_argument(input, argument.name) do
          {:ok, value} ->
            case Ash.Type.dump_to_embedded(argument.type, value, argument.constraints) do
              {:ok, embedded} -> {[{argument.name, embedded} | dumped], errors}
              error -> {dumped, [invalid_argument(argument, value, error) | errors]}
            end

          :error ->
            {dumped, errors}
        end
      end)

    case errors do
      [] -> {:ok, Enum.reverse(dumped)}
      errors -> {:error, errors |> Enum.reverse() |> Ash.Error.to_error_class()}
    end
  end

  defp invalid_argument(argument, value, error) do
    opts =
      case error do
        {:error, opts} when is_list(opts) -> opts
        _ -> []
      end

    InvalidArgument.exception(
      field: argument.name,
      value: value,
      message: opts[:message] || "could not be serialized",
      vars: opts
    )
  end
end
