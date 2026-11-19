# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.ToolArgumentsTest do
  use ExUnit.Case, async: true

  alias __MODULE__.{Domain, Project}

  defmodule Project do
    @moduledoc false
    use Ash.Resource, domain: Domain, data_layer: Ash.DataLayer.Ets

    ets do
      private? true
    end

    attributes do
      uuid_v7_primary_key :id, writable?: true
      attribute :name, :string, public?: true
    end

    actions do
      defaults [:read, :create]
      default_accept [:name]
    end
  end

  defmodule Domain do
    @moduledoc false
    use Ash.Domain, extensions: [AshAi]

    resources do
      resource Project
    end

    tools do
      tool :create_project, Project, :create do
        # The tool's own arguments reach the `load` function with the input.
        load fn input ->
          send(self(), {:tool_input, input})
          []
        end

        argument :project_id, :string, description: "The project to change."
        argument :code, :string, constraints: [max_length: 8]
        argument :limit, :integer, constraints: [min: 1]
        argument :dry_run, :boolean
        argument :note, Ash.Type.String
        argument :tags, {:array, :string}
      end
    end
  end

  defp tool do
    [otp_app: :ash_ai, actions: [{Project, [:create]}], strict: false]
    |> AshAi.list_tools()
    |> Enum.find(&(&1.name == "create_project"))
  end

  test "a tool argument declared with a short type name is resolved to its Ash type" do
    [tool_definition] = AshAi.Info.tools(Domain)

    types = Map.new(tool_definition.arguments, &{&1.name, &1.type})

    assert types == %{
             project_id: Ash.Type.String,
             code: Ash.Type.String,
             limit: Ash.Type.Integer,
             dry_run: Ash.Type.Boolean,
             note: Ash.Type.String,
             tags: {:array, Ash.Type.String}
           }
  end

  test "the input schema gives each tool argument its JSON type" do
    properties = tool().parameter_schema["properties"]["input"]["properties"]

    assert properties["project_id"] == %{
             "type" => "string",
             "description" => "The project to change."
           }

    assert properties["code"] == %{"type" => "string", "maxLength" => 8}
    assert properties["limit"] == %{"type" => "integer", "minimum" => 1}
    assert properties["dry_run"] == %{"type" => "boolean"}
    assert properties["note"] == %{"type" => "string"}
    assert properties["tags"] == %{"type" => "array", "items" => %{"type" => "string"}}
  end

  test "calling the tool still passes the tool's arguments through" do
    input = %{
      "name" => "Acme",
      "project_id" => "proj_1",
      "code" => "ABC",
      "limit" => 5,
      "dry_run" => true,
      "note" => "hi",
      "tags" => ["a"]
    }

    {_tools, registry} =
      AshAi.build_tools_and_registry(actions: [{Project, [:create]}], strict: false)

    assert {:ok, _json, %Project{name: "Acme"}} =
             registry["create_project"].(%{"input" => input}, %{
               actor: nil,
               tenant: nil,
               context: %{},
               tool_callbacks: %{}
             })

    assert_received {:tool_input, ^input}
  end
end
