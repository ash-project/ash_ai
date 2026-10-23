# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.ToolErrorInterpolationTest do
  use ExUnit.Case, async: true

  alias __MODULE__.{Domain, Item}

  defmodule Item do
    use Ash.Resource, domain: Domain, data_layer: Ash.DataLayer.Ets

    ets do
      private? true
    end

    attributes do
      uuid_v7_primary_key :id
      attribute :name, :string, public?: true
      attribute :quantity, :integer, public?: true
    end

    actions do
      defaults [:read]

      create :create do
        accept [:name, :quantity]
        argument :limit, :integer, constraints: [max: 200], allow_nil?: false

        validate string_length(:name, max: 5)
        validate compare(:quantity, less_than_or_equal_to: 10)
        validate AshAi.ToolErrorInterpolationTest.CustomValidation
      end
    end
  end

  defmodule CustomValidation do
    use Ash.Resource.Validation

    @impl true
    def validate(changeset, _opts, _context) do
      case Ash.Changeset.get_attribute(changeset, :name) do
        "taken" ->
          {:error,
           field: :name,
           message: "%{name} is already used %{times} times",
           name: "taken",
           times: 3}

        _ ->
          :ok
      end
    end
  end

  defmodule Domain do
    use Ash.Domain, extensions: [AshAi]

    resources do
      resource Item
    end

    tools do
      tool :create_item, Item, :create
    end
  end

  setup do
    {_tools, registry} =
      AshAi.build_tools_and_registry(
        actions: [{Item, [:create]}],
        tools: [:create_item],
        strict: false
      )

    %{run: registry["create_item"]}
  end

  test "interpolates vars of an argument constraint failure", %{run: run} do
    assert {:error, message} =
             run.(%{"input" => %{"name" => "ok", "quantity" => 1, "limit" => 500}}, context())

    assert message =~ "must be less than or equal to 200"
    refute message =~ "%{"
  end

  test "interpolates vars of built-in validations raised inside an action", %{run: run} do
    assert {:error, message} =
             run.(
               %{"input" => %{"name" => "too long name", "quantity" => 50, "limit" => 1}},
               context()
             )

    assert message =~ "name: must have length of no more than 5"
    assert message =~ "quantity: must be less than or equal to 10"
    refute message =~ "%{"
  end

  test "interpolates vars of a custom validation", %{run: run} do
    assert {:error, message} =
             run.(%{"input" => %{"name" => "taken", "quantity" => 1, "limit" => 1}}, context())

    assert message =~ "name: taken is already used 3 times"
  end

  defp context do
    %{actor: nil, tenant: nil, context: %{}, tool_callbacks: %{}}
  end
end
