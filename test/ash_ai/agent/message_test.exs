# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Agent.MessageTest do
  use ExUnit.Case, async: true

  alias __MODULE__.{Domain, Message}

  defmodule Domain do
    use Ash.Domain, validate_config_inclusion?: false

    resources do
      resource AshAi.Agent.MessageTest.Message
    end
  end

  defmodule Message do
    use Ash.Resource,
      domain: Domain,
      extensions: [AshAi.Agent.Message],
      data_layer: Ash.DataLayer.Ets,
      validate_domain_inclusion?: false

    actions do
      default_accept :*
      defaults [:read, :create]
    end
  end

  describe "schema injection" do
    test "injects all required attributes" do
      attribute_names =
        Message
        |> Ash.Resource.Info.attributes()
        |> Enum.map(& &1.name)
        |> MapSet.new()

      expected =
        MapSet.new([
          :id,
          :agent_id,
          :sender_id,
          :role,
          :message,
          :data,
          :tool_call_id,
          :token_count,
          :pending,
          :generation,
          :metadata,
          :inserted_at
        ])

      assert MapSet.subset?(expected, attribute_names),
             "missing: #{inspect(MapSet.difference(expected, attribute_names))}"
    end

    test ":id is the uuid_v7 primary key" do
      attr = Ash.Resource.Info.attribute(Message, :id)
      assert attr.primary_key?
      assert attr.type == Ash.Type.UUIDv7
      refute attr.allow_nil?
    end

    test ":role constrains to the documented set" do
      attr = Ash.Resource.Info.attribute(Message, :role)
      refute attr.allow_nil?
      assert {:one_of, roles} = List.keyfind(attr.constraints, :one_of, 0)

      assert Enum.sort(roles) ==
               Enum.sort([
                 :system,
                 :user,
                 :assistant,
                 :tool_call,
                 :tool_result,
                 :event,
                 :summary,
                 :agent
               ])
    end

    test ":pending defaults to false and is non-nullable" do
      attr = Ash.Resource.Info.attribute(Message, :pending)
      refute attr.allow_nil?
      assert attr.default == false
    end

    test ":metadata defaults to an empty map and is non-nullable" do
      attr = Ash.Resource.Info.attribute(Message, :metadata)
      refute attr.allow_nil?
      assert attr.default == %{}
    end

    test "nullable fields are nullable" do
      for name <- [:sender_id, :data, :tool_call_id, :token_count, :generation] do
        attr = Ash.Resource.Info.attribute(Message, name)
        assert attr.allow_nil?, "#{name} should be nullable"
      end
    end

    test ":message is required" do
      attr = Ash.Resource.Info.attribute(Message, :message)
      refute attr.allow_nil?
    end
  end

  describe "round-trip" do
    test "creates and reads a message row" do
      agent_id = Ash.UUIDv7.generate()

      {:ok, created} =
        Message
        |> Ash.Changeset.for_create(:create, %{
          agent_id: agent_id,
          role: :user,
          message: "hello",
          data: %{"foo" => "bar"}
        })
        |> Ash.create()

      assert created.agent_id == agent_id
      assert created.role == :user
      assert created.message == "hello"
      assert created.data == %{"foo" => "bar"}
      assert created.pending == false
      assert created.metadata == %{}
      assert is_nil(created.generation)

      [read] = Ash.read!(Message)
      assert read.id == created.id
    end

    test "rejects unknown role" do
      assert {:error, _} =
               Message
               |> Ash.Changeset.for_create(:create, %{
                 agent_id: Ash.UUIDv7.generate(),
                 role: :nonsense
               })
               |> Ash.create()
    end
  end
end
