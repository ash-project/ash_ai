# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.ListPaginationTest do
  use ExUnit.Case, async: true
  import Plug.{Conn, Test}

  alias AshAi.Mcp.Router
  alias __MODULE__.{Domain, Widget}

  @protocol_version "2026-07-28"
  @protocols [:initialize_based, :per_request]

  defmodule Widget do
    use Ash.Resource,
      domain: Domain,
      data_layer: Ash.DataLayer.Ets,
      validate_domain_inclusion?: false

    attributes do
      uuid_primary_key :id
      attribute :name, :string, public?: true
    end

    actions do
      defaults [:read]

      action :render, :string do
        run fn _input, _context -> {:ok, "hello"} end
      end
    end
  end

  defmodule Domain do
    use Ash.Domain, extensions: [AshAi], validate_config_inclusion?: false

    resources do
      resource Widget
    end

    tools do
      tool :widgets_e, Widget, :read
      tool :widgets_a, Widget, :read
      tool :widgets_d, Widget, :read
      tool :widgets_b, Widget, :read
      tool :widgets_c, Widget, :read
    end

    mcp_resources do
      mcp_resource :doc_3, "file://docs/3.txt", Widget, :render, title: "Doc 3"
      mcp_resource :doc_1, "file://docs/1.txt", Widget, :render, title: "Doc 1"
      mcp_resource :doc_2, "file://docs/2.txt", Widget, :render, title: "Doc 2"
    end
  end

  setup do
    otp_app = :"ash_ai_list_pagination_#{System.unique_integer([:positive])}"
    Application.put_env(otp_app, :ash_domains, [Domain])
    on_exit(fn -> Application.delete_env(otp_app, :ash_domains) end)

    %{opts: [otp_app: otp_app]}
  end

  describe "without list_page_size" do
    test "every entry is returned without a nextCursor", %{opts: opts} do
      for protocol <- @protocols do
        assert {200, %{"result" => tools}} = request(protocol, "tools/list", %{}, opts)
        assert names(tools) == ~w(widgets_a widgets_b widgets_c widgets_d widgets_e)
        refute Map.has_key?(tools, "nextCursor")

        assert {200, %{"result" => resources}} = request(protocol, "resources/list", %{}, opts)
        assert uris(resources) == ~w(file://docs/1.txt file://docs/2.txt file://docs/3.txt)
        refute Map.has_key?(resources, "nextCursor")
      end
    end

    test "a cursor resumes after the entry it was issued for", %{opts: opts} do
      {200, %{"result" => %{"nextCursor" => cursor}}} =
        request(:initialize_based, "tools/list", %{}, Keyword.put(opts, :list_page_size, 2))

      for protocol <- @protocols do
        assert {200, %{"result" => tools}} =
                 request(protocol, "tools/list", %{"cursor" => cursor}, opts)

        assert names(tools) == ~w(widgets_c widgets_d widgets_e)
        refute Map.has_key?(tools, "nextCursor")
      end
    end
  end

  describe "with list_page_size" do
    test "tools are served in pages that cover the whole list", %{opts: opts} do
      opts = Keyword.put(opts, :list_page_size, 2)

      for protocol <- @protocols do
        assert protocol |> pages("tools/list", opts) |> Enum.map(&names/1) == [
                 ~w(widgets_a widgets_b),
                 ~w(widgets_c widgets_d),
                 ~w(widgets_e)
               ]
      end
    end

    test "resources are served in pages that cover the whole list", %{opts: opts} do
      opts = Keyword.put(opts, :list_page_size, 2)

      for protocol <- @protocols do
        assert protocol |> pages("resources/list", opts) |> Enum.map(&uris/1) == [
                 ~w(file://docs/1.txt file://docs/2.txt),
                 ~w(file://docs/3.txt)
               ]
      end
    end

    test "a page that ends the list carries no nextCursor", %{opts: opts} do
      opts = Keyword.put(opts, :list_page_size, 3)

      for protocol <- @protocols do
        assert {200, %{"result" => resources}} = request(protocol, "resources/list", %{}, opts)
        assert length(resources["resources"]) == 3
        refute Map.has_key?(resources, "nextCursor")
      end
    end

    test "a null cursor starts from the beginning", %{opts: opts} do
      opts = Keyword.put(opts, :list_page_size, 2)

      for protocol <- @protocols do
        assert {200, %{"result" => tools}} =
                 request(protocol, "tools/list", %{"cursor" => nil}, opts)

        assert names(tools) == ~w(widgets_a widgets_b)
      end
    end
  end

  describe "invalid cursors" do
    test "are rejected with -32602 whether or not paging is enabled", %{opts: opts} do
      for protocol <- @protocols,
          opts <- [opts, Keyword.put(opts, :list_page_size, 2)],
          method <- ["tools/list", "resources/list", "resources/templates/list"],
          cursor <- ["not-a-cursor", Base.url_encode64(~s({"after": 1})), 42] do
        assert {_status, %{"error" => %{"code" => -32_602, "message" => message}}} =
                 request(protocol, method, %{"cursor" => cursor}, opts)

        assert message =~ "cursor"
      end
    end
  end

  describe "resources/templates/list" do
    test "returns an empty list", %{opts: opts} do
      for protocol <- @protocols do
        assert {200, %{"result" => %{"resourceTemplates" => []}}} =
                 request(protocol, "resources/templates/list", %{}, opts)
      end
    end
  end

  defp pages(protocol, method, opts, cursor \\ nil) do
    params = if cursor, do: %{"cursor" => cursor}, else: %{}
    {200, %{"result" => result}} = request(protocol, method, params, opts)

    case result["nextCursor"] do
      nil -> [result]
      next -> [result | pages(protocol, method, opts, next)]
    end
  end

  defp names(%{"tools" => tools}), do: Enum.map(tools, & &1["name"])
  defp uris(%{"resources" => resources}), do: Enum.map(resources, & &1["uri"])

  defp request(:initialize_based, method, params, opts) do
    :post
    |> conn("/", %{"jsonrpc" => "2.0", "id" => "1", "method" => method, "params" => params})
    |> send_request(opts)
  end

  defp request(:per_request, method, params, opts) do
    meta = %{
      "io.modelcontextprotocol/protocolVersion" => @protocol_version,
      "io.modelcontextprotocol/clientCapabilities" => %{}
    }

    body = %{
      "jsonrpc" => "2.0",
      "id" => "1",
      "method" => method,
      "params" => Map.put(params, "_meta", meta)
    }

    :post
    |> conn("/", body)
    |> put_req_header("mcp-protocol-version", @protocol_version)
    |> put_req_header("mcp-method", method)
    |> send_request(opts)
  end

  defp send_request(conn, opts) do
    response = Router.call(conn, opts)
    {response.status, Jason.decode!(response.resp_body)}
  end
end
