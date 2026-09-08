# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.ToolAggregateFieldPolicyTest do
  use ExUnit.Case, async: true

  alias __MODULE__.{FpDomain, FpResource}

  defmodule FpResource do
    use Ash.Resource,
      domain: FpDomain,
      data_layer: Ash.DataLayer.Ets,
      authorizers: [Ash.Policy.Authorizer]

    ets do
      private?(true)
    end

    attributes do
      uuid_v7_primary_key(:id, writable?: true)

      attribute(:public_name, :string, public?: true)
      attribute(:secret_score, :integer, public?: true)
    end

    actions do
      defaults([:read, :create])
      default_accept([:public_name, :secret_score])
    end

    policies do
      policy always() do
        authorize_if(always())
      end
    end

    field_policies do
      field_policy :secret_score do
        authorize_if(actor_attribute_equals(:admin, true))
      end

      field_policy :* do
        authorize_if(always())
      end
    end
  end

  defmodule FpDomain do
    use Ash.Domain, extensions: [AshAi]

    resources do
      resource(FpResource)
    end

    tools do
      tool(:read_fp, FpResource, :read)
    end
  end

  defp context(actor), do: %{actor: actor, tenant: nil, context: %{}, tool_callbacks: %{}}

  defp max_secret_score(actor) do
    {_tools, registry} =
      AshAi.build_tools_and_registry(
        actions: [{FpResource, [:read]}],
        tools: [:read_fp],
        strict: false
      )

    registry["read_fp"].(
      %{"result_type" => %{"aggregate" => "max", "field" => "secret_score"}},
      context(actor)
    )
  end

  setup do
    for score <- [10, 20] do
      FpResource
      |> Ash.Changeset.for_create(:create, %{public_name: "n", secret_score: score})
      |> Ash.create!(authorize?: false)
    end

    :ok
  end

  test "a non-admin cannot read a field-policy-forbidden field via a max aggregate" do
    assert {:error, _} = max_secret_score(%{admin: false})
  end

  test "an admin can read it via a max aggregate" do
    assert {:ok, json, value} = max_secret_score(%{admin: true})
    assert value == 20
    assert json == "20"
  end
end
