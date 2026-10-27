# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.OutputSchemaTest do
  use ExUnit.Case, async: true
  import Plug.{Conn, Test}

  alias AshAi.Mcp.Router
  alias __MODULE__.{Domain, Part, Summary, Widget}

  defmodule Summary do
    use Ash.TypedStruct

    typed_struct do
      field :label, :string, allow_nil?: false
      field :total, :integer, allow_nil?: false
      field :note, :string
      field :tags, {:array, :string}
    end
  end

  defmodule Widget do
    use Ash.Resource,
      domain: Domain,
      data_layer: Ash.DataLayer.Ets,
      validate_domain_inclusion?: false

    ets do
      private? true
    end

    attributes do
      uuid_primary_key :id
      attribute :name, :string, public?: true, allow_nil?: false
      attribute :cost, :decimal, public?: true
      attribute :notes, :string
    end

    relationships do
      has_many :parts, Part, public?: true
    end

    calculations do
      calculate :label, :string, expr(name <> "!"), public?: true
    end

    aggregates do
      count :part_count, :parts, public?: true
    end

    actions do
      default_accept [:name, :cost, :notes]
      defaults [:read, :create, :destroy]

      action :summary, Summary do
        run fn _input, _context ->
          {:ok, %Summary{label: "widgets", total: 2, note: nil, tags: ["a"]}}
        end
      end

      action :stats, :map do
        constraints fields: [
                      count: [type: :integer, allow_nil?: false],
                      label: [type: :string]
                    ]

        # `label` is declared but left out, which a map result may do
        run fn _input, _context -> {:ok, %{count: 1}} end
      end
    end
  end

  defmodule Part do
    use Ash.Resource,
      domain: Domain,
      data_layer: Ash.DataLayer.Ets,
      validate_domain_inclusion?: false

    ets do
      private? true
    end

    attributes do
      uuid_primary_key :id
      attribute :sku, :string, public?: true, allow_nil?: false
    end

    relationships do
      belongs_to :widget, Widget, public?: true, attribute_public?: false
    end

    actions do
      default_accept [:sku, :widget_id]
      defaults [:read, :create]
    end
  end

  defmodule Domain do
    use Ash.Domain, extensions: [AshAi], validate_config_inclusion?: false

    resources do
      resource Widget
      resource Part
    end

    tools do
      tool :summary, Widget, :summary, output_schema?: true
      tool :summary_plain, Widget, :summary
      tool :stats, Widget, :stats, output_schema?: true
      tool :get_widget, Widget, :read, get_by: :id, load: [:label], output_schema?: true

      tool :get_widget_with_parts, Widget, :read,
        get_by: :id,
        load: [:part_count, parts: [:widget]],
        output_schema?: true

      tool :create_widget, Widget, :create, output_schema?: true
      tool :destroy_widget, Widget, :destroy, output_schema?: true
    end
  end

  setup do
    otp_app = :"ash_ai_output_schema_#{System.unique_integer([:positive])}"
    Application.put_env(otp_app, :ash_domains, [Domain])
    on_exit(fn -> Application.delete_env(otp_app, :ash_domains) end)

    %{opts: [otp_app: otp_app]}
  end

  describe "tools/list" do
    test "typed struct results publish their fields", %{opts: opts} do
      assert output_schema("summary", opts) == %{
               "type" => "object",
               "properties" => %{
                 "label" => %{"type" => "string"},
                 "total" => %{"type" => "integer"},
                 "note" => %{"type" => ["string", "null"]},
                 "tags" => %{"type" => ["array", "null"], "items" => %{"type" => "string"}}
               },
               "required" => ["label", "total", "note", "tags"]
             }
    end

    test "map results require none of their fields", %{opts: opts} do
      schema = output_schema("stats", opts)

      assert schema["properties"] == %{
               "count" => %{"type" => "integer"},
               "label" => %{"type" => ["string", "null"]}
             }

      refute Map.has_key?(schema, "required")
    end

    test "record results list public attributes and loads, all optional", %{opts: opts} do
      schema = output_schema("get_widget", opts)

      assert schema["properties"] == %{
               "id" => %{"type" => "string"},
               "name" => %{"type" => "string"},
               "cost" => %{"type" => "string"},
               "label" => %{"type" => "string"}
             }

      refute Map.has_key?(schema, "required")
    end

    test "loaded relationships and aggregates are described, nested loads included", %{
      opts: opts
    } do
      schema = output_schema("get_widget_with_parts", opts)

      widget_record = %{
        "id" => %{"type" => "string"},
        "name" => %{"type" => "string"},
        "cost" => %{"type" => "string"}
      }

      assert schema["properties"]["part_count"] == %{"type" => "integer"}

      assert schema["properties"]["parts"] == %{
               "type" => "array",
               "items" => %{
                 "type" => "object",
                 "properties" => %{
                   "id" => %{"type" => "string"},
                   "sku" => %{"type" => "string"},
                   "widget" => %{"type" => "object", "properties" => widget_record}
                 }
               }
             }
    end

    test "tools that don't opt in publish no output schema", %{opts: opts} do
      assert {:ok, tool} = listed_tool("summary_plain", opts)
      refute Map.has_key?(tool, "outputSchema")
    end
  end

  describe "tools/call" do
    test "structured content conforms to the published schema", %{opts: opts} do
      widget = Ash.create!(Widget, %{name: "gear", notes: "private"})
      Ash.create!(Part, %{sku: "p-1", widget_id: widget.id})
      Ash.create!(Part, %{sku: "p-2", widget_id: widget.id})

      for {name, arguments} <- [
            {"summary", %{}},
            {"stats", %{}},
            {"get_widget", %{"id" => widget.id}},
            {"get_widget_with_parts", %{"id" => widget.id}},
            {"create_widget", %{"input" => %{"name" => "sprocket"}}},
            {"destroy_widget", %{"id" => widget.id}}
          ] do
        root = name |> output_schema(opts) |> JSV.build!()
        structured = call(name, arguments, opts)

        assert is_map(structured), "#{name} returned no structured content"

        assert {:ok, _} = JSV.validate(structured, root),
               "#{name} returned #{inspect(structured)}, which doesn't match its output schema"

        if name == "get_widget_with_parts" do
          assert %{"part_count" => 2, "parts" => [_, _] = parts} = structured
          assert Enum.all?(parts, &match?(%{"widget" => %{"name" => "gear"}}, &1))
        end
      end
    end
  end

  describe "compile-time validation" do
    test "requires a non-nil generic action result" do
      assert_raise Spark.Error.DslError, ~r/allow_nil\? false/, fn ->
        define_resource(
          quote do
            action :maybe, :map do
              allow_nil? true
              run fn _input, _context -> {:ok, nil} end
            end
          end,
          quote(do: tool(:maybe, :maybe, output_schema?: true))
        )
      end
    end

    test "requires an object result" do
      assert_raise Spark.Error.DslError, ~r/requires the action to return an object/, fn ->
        define_resource(
          quote do
            action :count, :integer do
              run fn _input, _context -> {:ok, 1} end
            end
          end,
          quote(do: tool(:count, :count, output_schema?: true))
        )
      end
    end

    test "requires get_by on read tools" do
      assert_raise Spark.Error.DslError, ~r/requires `get_by`/, fn ->
        define_resource(nil, quote(do: tool(:list, :read, output_schema?: true)))
      end
    end

    test "requires a static load" do
      assert_raise Spark.Error.DslError, ~r/static `load` list/, fn ->
        define_resource(
          nil,
          quote do
            tool(:get, :read, get_by: :id, output_schema?: true, load: fn _input -> [] end)
          end
        )
      end
    end
  end

  defp output_schema(name, opts) do
    {:ok, tool} = listed_tool(name, opts)
    tool["outputSchema"]
  end

  defp listed_tool(name, opts) do
    %{"result" => %{"tools" => tools}} = rpc("tools/list", %{}, opts)

    case Enum.find(tools, &(&1["name"] == name)) do
      nil -> :error
      tool -> {:ok, tool}
    end
  end

  defp call(name, arguments, opts) do
    %{"result" => result} = rpc("tools/call", %{"name" => name, "arguments" => arguments}, opts)
    refute result["isError"], "#{name} failed: #{inspect(result["content"])}"
    result["structuredContent"]
  end

  defp rpc(method, params, opts) do
    response =
      :post
      |> conn("/", %{"jsonrpc" => "2.0", "id" => "1", "method" => method, "params" => params})
      |> Router.call(opts)

    Jason.decode!(response.resp_body)
  end

  defp define_resource(action, tool) do
    module = Module.concat(__MODULE__, :"Resource#{System.unique_integer([:positive])}")

    Module.create(
      module,
      quote do
        use Ash.Resource,
          domain: unquote(Domain),
          extensions: [AshAi],
          data_layer: Ash.DataLayer.Ets,
          validate_domain_inclusion?: false

        attributes do
          uuid_primary_key :id
        end

        actions do
          defaults [:read]
          unquote(action)
        end

        tools do
          unquote(tool)
        end
      end,
      Macro.Env.location(__ENV__)
    )
  end
end
