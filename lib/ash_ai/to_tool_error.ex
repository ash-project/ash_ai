# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defprotocol AshAi.ToToolError do
  @moduledoc """
  Converts Ash errors into concise readable tool error messages.

  Implementations should return a concise error description.

  ## Example

      defimpl AshAi.ToToolError, for: MyApp.CustomError do
        def to_tool_error(error) do
          "custom error: \#{error.message}"
        end
      end
  """

  @doc """
  Returns a human-readable error message string for tool responses.
  """
  @spec to_tool_error(t()) :: String.t()
  def to_tool_error(error)
end

defimpl AshAi.ToToolError, for: Ash.Error.Changes.Required do
  def to_tool_error(_error) do
    "is required"
  end
end

defimpl AshAi.ToToolError, for: Ash.Error.Query.Required do
  def to_tool_error(_error) do
    "is required"
  end
end

defimpl AshAi.ToToolError, for: Ash.Error.Changes.InvalidAttribute do
  def to_tool_error(error) do
    error.message || "is invalid"
  end
end

defimpl AshAi.ToToolError, for: Ash.Error.Changes.InvalidChanges do
  def to_tool_error(error) do
    error.message || "is invalid"
  end
end

defimpl AshAi.ToToolError, for: Ash.Error.Changes.InvalidArgument do
  def to_tool_error(error) do
    error.message || "is invalid"
  end
end

defimpl AshAi.ToToolError, for: Ash.Error.Query.InvalidArgument do
  def to_tool_error(error) do
    error.message || "is invalid"
  end
end

defimpl AshAi.ToToolError, for: Ash.Error.Action.InvalidArgument do
  def to_tool_error(error) do
    error.message || "is invalid"
  end
end

defimpl AshAi.ToToolError, for: Ash.Error.Query.NotFound do
  def to_tool_error(_error) do
    "could not be found"
  end
end

defimpl AshAi.ToToolError, for: Ash.Error.Query.InvalidQuery do
  def to_tool_error(error) do
    error.message || "invalid query"
  end
end

defimpl AshAi.ToToolError, for: Ash.Error.Invalid.NoSuchInput do
  def to_tool_error(error) do
    if error.input do
      "no such input: #{error.input}"
    else
      "no such input"
    end
  end
end

defimpl AshAi.ToToolError, for: Ash.Error.Query.NoSuchField do
  def to_tool_error(error) do
    "no such field: #{error.field}"
  end
end

defimpl AshAi.ToToolError, for: Ash.Error.Query.NoSuchFilterPredicate do
  def to_tool_error(error) do
    "no such filter predicate: #{inspect(error.key)}"
  end
end

defimpl AshAi.ToToolError, for: Ash.Error.Query.InvalidFilterValue do
  def to_tool_error(%{value: value, message: message}) do
    ["invalid filter value #{inspect(value)}", message]
    |> Enum.reject(&(&1 in [nil, ""]))
    |> Enum.join(": ")
  end
end

defimpl AshAi.ToToolError, for: Ash.Error.Query.InvalidFilterReference do
  def to_tool_error(%{field: field, simple_equality?: true}) do
    "#{field} cannot be referenced in filters, except by simple equality"
  end

  def to_tool_error(%{field: field}) do
    "#{field} cannot be referenced in filters"
  end
end

defimpl AshAi.ToToolError, for: Ash.Error.Invalid.InvalidPrimaryKey do
  def to_tool_error(_error) do
    "invalid primary key provided"
  end
end

defimpl AshAi.ToToolError, for: Ash.Error.Page.InvalidKeyset do
  def to_tool_error(_error) do
    "invalid keyset"
  end
end

defimpl AshAi.ToToolError, for: Ash.Error.Forbidden.Policy do
  def to_tool_error(_error) do
    "forbidden"
  end
end

defimpl AshAi.ToToolError, for: Ash.Error.Forbidden.ForbiddenField do
  def to_tool_error(_error) do
    "forbidden"
  end
end

defimpl AshAi.ToToolError,
  for: [Ash.Error.Forbidden, Ash.Error.Framework, Ash.Error.Invalid, Ash.Error.Unknown] do
  def to_tool_error(error) do
    to_string(error.class)
  end
end
