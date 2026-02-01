# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Actions.Prompt.Adapter.RequestJsonTest do
  use ExUnit.Case, async: true
  alias AshAi.ChatFaker
  alias __MODULE__.{TestDomain, TestResource}

  defmodule Person do
    use Ash.Resource, data_layer: :embedded

    attributes do
      attribute :name, :string, public?: true
      attribute :age, :integer, public?: true
      attribute :occupation, :string, public?: true
      attribute :location, :string, public?: true
    end

    actions do
      default_accept([:*])
      defaults([:create, :read])
    end
  end

  defmodule Weather do
    use Ash.Resource, data_layer: :embedded

    attributes do
      attribute :temperature, :integer, public?: true
      attribute :condition, :string, public?: true
      attribute :humidity, :integer, public?: true
    end

    actions do
      default_accept([:*])
      defaults([:create, :read])
    end
  end

  defmodule TestResource do
    use Ash.Resource,
      domain: TestDomain,
      data_layer: Ash.DataLayer.Ets,
      extensions: [AshAi]

    ets do
      private?(true)
    end

    attributes do
      uuid_v7_primary_key(:id, writable?: true)
      attribute(:name, :string, public?: true)
    end

    actions do
      default_accept([:*])
      defaults([:create, :read, :update, :destroy])

      action :get_person_info, Person do
        description("Get information about a person")
        argument(:name, :string, allow_nil?: false)

        run prompt(
              fn _input, _args ->
                ChatFaker.new!(%{
                  expect_fun: fn _model, _messages, _tools ->
                    json_response = """
                    Here is your response.

                    ```json
                    {
                      "result": {
                        "name": "John Doe",
                        "age": 35,
                        "occupation": "Data Scientist",
                        "location": "New York"
                      }
                    }
                    ```
                    """

                    {:ok,
                     LangChain.Message.new_assistant!(%{
                       content: json_response
                     })}
                  end
                })
              end,
              adapter:
                {AshAi.Actions.Prompt.Adapter.RequestJson,
                 [
                   max_retries: 2,
                   json_format: :markdown,
                   include_examples: true
                 ]}
            )
      end

      action :get_weather, Weather do
        description("Get weather information for a location")
        argument(:location, :string, allow_nil?: false)

        run prompt(
              fn _input, _context ->
                ChatFaker.new!(%{
                  expect_fun: fn _model, _messages, _tools ->
                    json_response = """
                    <json>
                    {
                      "result": {
                        "temperature": 75,
                        "condition": "partly cloudy",
                        "humidity": 60
                      }
                    }
                    </json>
                    """

                    {:ok, LangChain.Message.new_assistant!(%{content: json_response})}
                  end
                })
              end,
              adapter:
                {AshAi.Actions.Prompt.Adapter.RequestJson,
                 [
                   max_retries: 1,
                   json_format: :xml,
                   include_examples: false
                 ]}
            )
      end
    end
  end

  defmodule RetryResource do
    use Ash.Resource, domain: TestDomain, data_layer: Ash.DataLayer.Ets, extensions: [AshAi]

    ets do
      private?(true)
    end

    attributes do
      uuid_v7_primary_key(:id, writable?: true)
    end

    actions do
      default_accept([:*])
      defaults([:create, :read, :update, :destroy])

      action :test_retry, Person do
        description("Test retry functionality")
        argument(:text, :string, allow_nil?: false)

        run prompt(
              fn _input, _context ->
                ChatFaker.new!(%{
                  expect_fun: fn _model, messages, _tools ->
                    # First call: invalid JSON, second call: valid JSON
                    if length(messages) <= 2 do
                      {:ok,
                       LangChain.Message.new_assistant!(%{content: "This is not valid JSON"})}
                    else
                      json_response = """
                      ```json
                      {
                        "result": {
                          "name": "Jane Smith",
                          "age": 28,
                          "occupation": "Designer",
                          "location": "Portland"
                        }
                      }
                      ```
                      """

                      {:ok, LangChain.Message.new_assistant!(%{content: json_response})}
                    end
                  end
                })
              end,
              adapter:
                {AshAi.Actions.Prompt.Adapter.RequestJson,
                 [
                   max_retries: 2,
                   json_format: :markdown,
                   include_examples: true
                 ]}
            )
      end
    end
  end

  defmodule ValidationErrorResource do
    use Ash.Resource, domain: TestDomain, data_layer: Ash.DataLayer.Ets, extensions: [AshAi]

    ets do
      private?(true)
    end

    attributes do
      uuid_v7_primary_key(:id, writable?: true)
    end

    actions do
      default_accept([:*])
      defaults([:create, :read, :update, :destroy])

      action :test_validation, Person do
        description("Test validation errors")
        argument(:text, :string, allow_nil?: false)

        run prompt(
              fn _input, _context ->
                ChatFaker.new!(%{
                  expect_fun: fn _model, _messages, _tools ->
                    # Return invalid data type (string instead of integer for age)
                    json_response = """
                    ```json
                    {
                      "result": {
                        "name": "Bob Wilson",
                        "age": "not a number",
                        "occupation": "Teacher",
                        "location": "Chicago"
                      }
                    }
                    ```
                    """

                    {:ok, LangChain.Message.new_assistant!(%{content: json_response})}
                  end
                })
              end,
              adapter:
                {AshAi.Actions.Prompt.Adapter.RequestJson,
                 [
                   max_retries: 0,
                   json_format: :markdown,
                   include_examples: true
                 ]}
            )
      end
    end
  end

  defmodule TestDomain do
    use Ash.Domain, extensions: [AshAi]

    resources do
      resource(TestResource)
      resource(RetryResource)
      resource(ValidationErrorResource)
    end
  end

  describe "RequestJson adapter" do
    test "successfully executes get_person_info action" do
      result =
        TestResource
        |> Ash.ActionInput.for_action(:get_person_info, %{name: "John Doe"})
        |> Ash.run_action!()

      assert result.name == "John Doe"
      assert result.age == 35
      assert result.occupation == "Data Scientist"
      assert result.location == "New York"
    end

    test "successfully executes get_weather action with XML format" do
      result =
        TestResource
        |> Ash.ActionInput.for_action(:get_weather, %{location: "San Francisco"})
        |> Ash.run_action!()

      assert result.temperature == 75
      assert result.condition == "partly cloudy"
      assert result.humidity == 60
    end

    test "handles retry scenarios with invalid JSON" do
      result =
        RetryResource
        |> Ash.ActionInput.for_action(:test_retry, %{text: "test"})
        |> Ash.run_action!()

      assert result.name == "Jane Smith"
      assert result.age == 28
      assert result.occupation == "Designer"
      assert result.location == "Portland"
    end

    test "handles validation errors" do
      errors =
        assert_raise Ash.Error.Unknown, fn ->
          ValidationErrorResource
          |> Ash.ActionInput.for_action(:test_validation, %{text: "test"})
          |> Ash.run_action!()
        end

      # Check for specific error details
      assert length(errors.errors) == 1
      error = hd(errors.errors)

      # Validate error message
      assert error.error =~ "field: :age"
    end
  end
end
