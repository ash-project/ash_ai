defmodule AshAi.Tool.ErrorsTest do
  use ExUnit.Case, async: true

  alias AshAi.Tool.Errors

  describe "format/1" do
    test "formats a single required field error" do
      error =
        Ash.Error.Changes.Required.exception(
          field: :title,
          type: :attribute,
          resource: SomeResource
        )

      result = Errors.format(error)

      assert result =~ "title"
      assert result =~ "required"
    end

    test "formats multiple errors separated by newlines" do
      error1 =
        Ash.Error.Changes.Required.exception(
          field: :title,
          type: :attribute,
          resource: SomeResource
        )

      error2 =
        Ash.Error.Changes.Required.exception(
          field: :body,
          type: :attribute,
          resource: SomeResource
        )

      combined = Ash.Error.to_error_class([error1, error2])
      result = Errors.format(combined)

      assert result =~ "title"
      assert result =~ "body"
      assert result =~ "\n"
    end

    test "returns a string for any error input" do
      result = Errors.format("something went wrong")
      assert is_binary(result)
      refute result == ""
    end

    test "excludes bread crumbs from output" do
      error =
        Ash.Error.Changes.Required.exception(
          field: :name,
          type: :attribute,
          resource: SomeResource
        )

      error = %{error | bread_crumbs: ["Error returned from: SomeResource.create"]}
      result = Errors.format(error)

      refute result =~ "Bread Crumbs"
      refute result =~ "Error returned from"
      assert result =~ "name"
    end

    test "expands fields into multiple lines" do
      error =
        Ash.Error.Changes.InvalidChanges.exception(
          fields: [:start_date, :end_date],
          message: "must not overlap"
        )

      result = Errors.format(error)

      assert result =~ "start_date: must not overlap"
      assert result =~ "end_date: must not overlap"
      assert result =~ "\n"
    end

    test "joins path with field using dot notation" do
      error =
        Ash.Error.Changes.Required.exception(
          field: :city,
          type: :attribute,
          resource: SomeResource
        )

      error = %{error | path: [:address]}
      result = Errors.format(error)

      assert result =~ "address.city:"
    end

    test "joins nested path with field using dot notation" do
      error =
        Ash.Error.Changes.Required.exception(
          field: :zip,
          type: :attribute,
          resource: SomeResource
        )

      error = %{error | path: [:user, :address]}
      result = Errors.format(error)

      assert result =~ "user.address.zip:"
    end

    test "handles errors without a field" do
      error =
        Ash.Error.Query.NotFound.exception(primary_key: %{id: "abc"}, resource: SomeResource)

      result = Errors.format(error)

      assert is_binary(result)
      refute result == ""
    end
  end
end
