# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.ToolReadActionTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias __MODULE__.{Domain, Note, SecretNote}

  defmodule Note do
    use Ash.Resource, domain: Domain, data_layer: Ash.DataLayer.Ets

    ets do
      private? true
    end

    attributes do
      integer_primary_key :id, writable?: true
      attribute :org_id, :integer, public?: true, allow_nil?: false
      attribute :body, :string, public?: true
    end

    actions do
      defaults [:read, :create, :destroy]
      default_accept [:id, :org_id, :body]

      update :update do
        primary? true
        accept [:body]
      end

      read :read_in_org do
        filter expr(org_id == ^actor(:org_id))
      end
    end
  end

  # The primary read is closed by policy: records are only reachable through `:read_in_org`.
  defmodule SecretNote do
    use Ash.Resource,
      domain: Domain,
      data_layer: Ash.DataLayer.Ets,
      authorizers: [Ash.Policy.Authorizer]

    ets do
      private? true
    end

    attributes do
      integer_primary_key :id, writable?: true
      attribute :org_id, :integer, public?: true, allow_nil?: false
      attribute :body, :string, public?: true
    end

    actions do
      defaults [:read, :create, :destroy]
      default_accept [:id, :org_id, :body]

      update :update do
        primary? true
        accept [:body]
      end

      read :read_in_org
    end

    policies do
      policy action(:read_in_org) do
        authorize_if expr(org_id == ^actor(:org_id))
      end

      policy action_type([:create, :update, :destroy]) do
        authorize_if always()
      end
    end
  end

  defmodule Domain do
    use Ash.Domain, extensions: [AshAi]

    resources do
      resource Note
      resource SecretNote
    end

    tools do
      tool :update_note, Note, :update
      tool :destroy_note, Note, :destroy
      tool :update_note_in_org, Note, :update, read_action: :read_in_org
      tool :destroy_note_in_org, Note, :destroy, read_action: :read_in_org

      tool :update_secret_note, SecretNote, :update
      tool :update_secret_note_in_org, SecretNote, :update, read_action: :read_in_org
      tool :destroy_secret_note_in_org, SecretNote, :destroy, read_action: :read_in_org
    end
  end

  setup do
    for resource <- [Note, SecretNote], {id, org_id} <- [{1, 1}, {2, 2}] do
      resource
      |> Ash.Changeset.for_create(:create, %{id: id, org_id: org_id, body: "Note #{id}"},
        authorize?: false
      )
      |> Ash.create!()
    end

    {_tools, registry} =
      AshAi.build_tools_and_registry(actions: [{Note, :*}, {SecretNote, :*}], strict: false)

    %{registry: registry}
  end

  describe "update tools with read_action" do
    test "update a record the read action can see", %{registry: registry} do
      assert {:ok, _json, %{id: 1, body: "Renamed"}} =
               registry["update_note_in_org"].(
                 %{"id" => 1, "input" => %{"body" => "Renamed"}},
                 context()
               )
    end

    test "report a record the read action filters out as not found", %{registry: registry} do
      assert {:error, message} =
               registry["update_note_in_org"].(
                 %{"id" => 2, "input" => %{"body" => "Renamed"}},
                 context()
               )

      assert message =~ "could not be found"
      assert body(Note, 2) == "Note 2"
    end

    test "apply the read action's filter under the atomic strategy", %{registry: registry} do
      log =
        capture_log([level: :debug], fn ->
          assert {:error, _} =
                   registry["update_note_in_org"].(
                     %{"id" => 2, "input" => %{"body" => "Renamed"}},
                     context()
                   )
        end)

      # The ETS data layer logs this only when it runs an atomic `update_query`
      assert log =~ ~r/ETS: Updating 1 #{inspect(Note)} matching filter `.*org_id == 1/
    end

    test "find records through the read action's policies", %{registry: registry} do
      assert {:ok, _json, %{id: 1, body: "Renamed"}} =
               registry["update_secret_note_in_org"].(
                 %{"id" => 1, "input" => %{"body" => "Renamed"}},
                 context()
               )

      assert {:error, message} =
               registry["update_secret_note_in_org"].(
                 %{"id" => 2, "input" => %{"body" => "Renamed"}},
                 context()
               )

      assert message =~ "could not be found"
      assert body(SecretNote, 2) == "Note 2"
    end

    test "without read_action, find records through the primary read", %{registry: registry} do
      assert {:ok, _json, %{id: 2, body: "Renamed"}} =
               registry["update_note"].(
                 %{"id" => 2, "input" => %{"body" => "Renamed"}},
                 context()
               )

      assert {:error, _} =
               registry["update_secret_note"].(
                 %{"id" => 1, "input" => %{"body" => "Renamed"}},
                 context()
               )

      assert body(SecretNote, 1) == "Note 1"
    end
  end

  describe "destroy tools with read_action" do
    test "destroy a record the read action can see", %{registry: registry} do
      assert {:ok, _json, %{id: 1}} = registry["destroy_note_in_org"].(%{"id" => 1}, context())
      assert body(Note, 1) == nil
    end

    test "report a record the read action filters out as not found", %{registry: registry} do
      log =
        capture_log([level: :debug], fn ->
          assert {:error, message} = registry["destroy_note_in_org"].(%{"id" => 2}, context())
          assert message =~ "could not be found"
        end)

      assert log =~ ~r/ETS: Destroying 1 #{inspect(Note)} where `.*org_id == 1/
      assert body(Note, 2) == "Note 2"
    end

    test "find records through the read action's policies", %{registry: registry} do
      assert {:error, _} = registry["destroy_secret_note_in_org"].(%{"id" => 2}, context())
      assert body(SecretNote, 2) == "Note 2"

      assert {:ok, _json, %{id: 1}} =
               registry["destroy_secret_note_in_org"].(%{"id" => 1}, context())

      assert body(SecretNote, 1) == nil
    end

    test "without read_action, find records through the primary read", %{registry: registry} do
      assert {:ok, _json, %{id: 2}} = registry["destroy_note"].(%{"id" => 2}, context())
      assert body(Note, 2) == nil
    end
  end

  describe "compile-time validation" do
    test "rejects a read_action that is not a read action", %{test: test} do
      assert_raise Spark.Error.DslError, ~r/must name a read action/, fn ->
        define_resource(test, quote(do: tool(:update_thing, :update, read_action: :destroy)))
      end

      assert_raise Spark.Error.DslError, ~r/must name a read action/, fn ->
        define_resource(
          Module.concat(test, Missing),
          quote(do: tool(:update_thing, :update, read_action: :missing))
        )
      end
    end

    test "rejects read_action on tools other than update and destroy", %{test: test} do
      assert_raise Spark.Error.DslError, ~r/only be used with update and destroy tools/, fn ->
        define_resource(test, quote(do: tool(:read_things, :read, read_action: :read)))
      end
    end
  end

  defp define_resource(test, tool) do
    domain = Module.concat([__MODULE__, test, Domain])
    resource = Module.concat([__MODULE__, test, Resource])

    Module.create(
      resource,
      quote do
        use Ash.Resource,
          domain: unquote(domain),
          extensions: [AshAi],
          data_layer: Ash.DataLayer.Ets,
          validate_domain_inclusion?: false

        attributes do
          uuid_v7_primary_key(:id, writable?: true)
        end

        actions do
          defaults([:read, :destroy, update: :*])
        end

        tools do
          unquote(tool)
        end
      end,
      Macro.Env.location(__ENV__)
    )
  end

  defp body(resource, id) do
    case Ash.get(resource, id, authorize?: false) do
      {:ok, record} -> record.body
      {:error, _} -> nil
    end
  end

  defp context do
    %{actor: %{org_id: 1}, tenant: nil, context: %{}, tool_callbacks: %{}}
  end
end
