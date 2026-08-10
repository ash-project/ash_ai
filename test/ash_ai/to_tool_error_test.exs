# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.ToToolErrorTest do
  use ExUnit.Case, async: true

  describe "Ash.Error.Changes.Required" do
    test "returns is required" do
      error =
        Ash.Error.Changes.Required.exception(field: :title, type: :attribute, resource: Res)

      assert AshAi.ToToolError.to_tool_error(error) == "is required"
    end
  end

  describe "Ash.Error.Query.Required" do
    test "returns is required" do
      error =
        Ash.Error.Query.Required.exception(field: :name, type: :argument, resource: Res)

      assert AshAi.ToToolError.to_tool_error(error) == "is required"
    end
  end

  describe "Ash.Error.Changes.InvalidAttribute" do
    test "returns the message when present" do
      error =
        Ash.Error.Changes.InvalidAttribute.exception(
          field: :email,
          message: "must be a valid email"
        )

      assert AshAi.ToToolError.to_tool_error(error) == "must be a valid email"
    end

    test "returns fallback when message is nil" do
      error = Ash.Error.Changes.InvalidAttribute.exception(field: :email)
      assert AshAi.ToToolError.to_tool_error(error) == "is invalid"
    end
  end

  describe "Ash.Error.Changes.InvalidChanges" do
    test "returns the message when present" do
      error = Ash.Error.Changes.InvalidChanges.exception(message: "dates must not overlap")
      assert AshAi.ToToolError.to_tool_error(error) == "dates must not overlap"
    end

    test "returns fallback when message is nil" do
      error = Ash.Error.Changes.InvalidChanges.exception([])
      assert AshAi.ToToolError.to_tool_error(error) == "is invalid"
    end
  end

  describe "Ash.Error.Changes.InvalidArgument" do
    test "returns the message when present" do
      error =
        Ash.Error.Changes.InvalidArgument.exception(field: :limit, message: "must be positive")

      assert AshAi.ToToolError.to_tool_error(error) == "must be positive"
    end

    test "returns fallback when message is nil" do
      error = Ash.Error.Changes.InvalidArgument.exception(field: :limit)
      assert AshAi.ToToolError.to_tool_error(error) == "is invalid"
    end
  end

  describe "Ash.Error.Query.InvalidArgument" do
    test "returns the message when present" do
      error =
        Ash.Error.Query.InvalidArgument.exception(field: :sort, message: "unsupported sort")

      assert AshAi.ToToolError.to_tool_error(error) == "unsupported sort"
    end

    test "returns fallback when message is nil" do
      error = Ash.Error.Query.InvalidArgument.exception(field: :sort)
      assert AshAi.ToToolError.to_tool_error(error) == "is invalid"
    end
  end

  describe "Ash.Error.Action.InvalidArgument" do
    test "returns the message when present" do
      error =
        Ash.Error.Action.InvalidArgument.exception(field: :input, message: "bad format")

      assert AshAi.ToToolError.to_tool_error(error) == "bad format"
    end

    test "returns fallback when message is nil" do
      error = Ash.Error.Action.InvalidArgument.exception(field: :input)
      assert AshAi.ToToolError.to_tool_error(error) == "is invalid"
    end
  end

  describe "Ash.Error.Query.NotFound" do
    test "returns could not be found" do
      error = Ash.Error.Query.NotFound.exception(primary_key: %{id: "abc"}, resource: Res)
      assert AshAi.ToToolError.to_tool_error(error) == "could not be found"
    end
  end

  describe "Ash.Error.Query.InvalidQuery" do
    test "returns the message when present" do
      error = Ash.Error.Query.InvalidQuery.exception(message: "bad filter")
      assert AshAi.ToToolError.to_tool_error(error) == "bad filter"
    end

    test "returns fallback when message is nil" do
      error = Ash.Error.Query.InvalidQuery.exception([])
      assert AshAi.ToToolError.to_tool_error(error) == "invalid query"
    end
  end

  describe "Ash.Error.Invalid.NoSuchInput" do
    test "includes the input name" do
      error =
        Ash.Error.Invalid.NoSuchInput.exception(
          input: :foo,
          resource: Res,
          action: :create,
          inputs: []
        )

      assert AshAi.ToToolError.to_tool_error(error) == "no such input: foo"
    end

    test "returns fallback when input is nil" do
      error =
        Ash.Error.Invalid.NoSuchInput.exception(resource: Res, action: :create, inputs: [])

      assert AshAi.ToToolError.to_tool_error(error) == "no such input"
    end
  end

  describe "Ash.Error.Invalid.InvalidPrimaryKey" do
    test "returns invalid primary key" do
      error = Ash.Error.Invalid.InvalidPrimaryKey.exception(resource: Res)
      assert AshAi.ToToolError.to_tool_error(error) == "invalid primary key provided"
    end
  end

  describe "Ash.Error.Page.InvalidKeyset" do
    test "returns invalid keyset" do
      error = Ash.Error.Page.InvalidKeyset.exception([])
      assert AshAi.ToToolError.to_tool_error(error) == "invalid keyset"
    end
  end

  describe "Ash.Error.Forbidden.Policy" do
    test "returns forbidden" do
      error =
        Ash.Error.Forbidden.Policy.exception(
          facts: %{},
          policies: [],
          resource: Res,
          action: :read,
          actor: nil
        )

      assert AshAi.ToToolError.to_tool_error(error) == "forbidden"
    end
  end

  describe "Ash.Error.Forbidden.ForbiddenField" do
    test "returns forbidden" do
      error = Ash.Error.Forbidden.ForbiddenField.exception(resource: Res, field: :secret)
      assert AshAi.ToToolError.to_tool_error(error) == "forbidden"
    end
  end

  describe "Ash.Error.Query.NoSuchField" do
    test "names the field without leaking the resource module" do
      error = Ash.Error.Query.NoSuchField.exception(field: :nickname, resource: Res)

      assert AshAi.ToToolError.to_tool_error(error) == "no such field: nickname"
    end
  end

  describe "Ash.Error.Query.NoSuchFilterPredicate" do
    test "names the predicate without leaking the resource module" do
      error =
        Ash.Error.Query.NoSuchFilterPredicate.exception(key: "contains", resource: Res)

      assert AshAi.ToToolError.to_tool_error(error) == "no such filter predicate: \"contains\""
    end
  end

  describe "Ash.Error.Query.InvalidFilterValue" do
    test "returns the value and message" do
      error =
        Ash.Error.Query.InvalidFilterValue.exception(
          value: "abc",
          message: "must be an integer"
        )

      assert AshAi.ToToolError.to_tool_error(error) ==
               "invalid filter value \"abc\": must be an integer"
    end

    test "returns just the value when there is no message" do
      error = Ash.Error.Query.InvalidFilterValue.exception(value: "abc")

      assert AshAi.ToToolError.to_tool_error(error) == "invalid filter value \"abc\""
    end

    test "does not leak the internal filter context" do
      error =
        Ash.Error.Query.InvalidFilterValue.exception(
          value: "abc",
          context: %{resource: Res, public?: true, relationship_path: [:author]}
        )

      message = AshAi.ToToolError.to_tool_error(error)

      assert message == "invalid filter value \"abc\""
      refute message =~ "resource"
      refute message =~ "relationship_path"
    end
  end

  describe "Ash.Error.Query.InvalidFilterReference" do
    test "explains that the field cannot be filtered on" do
      error = Ash.Error.Query.InvalidFilterReference.exception(field: :full_name)

      assert AshAi.ToToolError.to_tool_error(error) ==
               "full_name cannot be referenced in filters"
    end

    test "notes when only simple equality is allowed" do
      error =
        Ash.Error.Query.InvalidFilterReference.exception(
          field: :full_name,
          simple_equality?: true
        )

      assert AshAi.ToToolError.to_tool_error(error) ==
               "full_name cannot be referenced in filters, except by simple equality"
    end
  end

  describe "error class wrappers" do
    test "Ash.Error.Invalid returns class name" do
      error = Ash.Error.Invalid.exception(errors: [])
      assert AshAi.ToToolError.to_tool_error(error) == "invalid"
    end

    test "Ash.Error.Forbidden returns class name" do
      error = Ash.Error.Forbidden.exception(errors: [])
      assert AshAi.ToToolError.to_tool_error(error) == "forbidden"
    end
  end
end
