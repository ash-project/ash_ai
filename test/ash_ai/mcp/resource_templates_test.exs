# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.ResourceTemplatesTest do
  @moduledoc """
  URI-templated MCP resources and binary or callback-built `resources/read` contents.
  """
  use ExUnit.Case, async: true
  import ExUnit.CaptureLog
  import Plug.{Conn, Test}

  alias AshAi.Mcp.Router
  alias AshAi.McpResource.Contents
  alias __MODULE__.{Domain, Photo}

  @protocol_version "2026-07-28"
  @protocols [:initialize_based, :per_request]
  @png <<0x89, "PNG", 0x0D, 0x0A, 0x1A, 0x0A>>
  @jpeg <<0xFF, 0xD8, 0xFF, 0xE0>>

  defmodule Photo do
    use Ash.Resource, domain: Domain, validate_domain_inclusion?: false

    @png <<0x89, "PNG", 0x0D, 0x0A, 0x1A, 0x0A>>
    @jpeg <<0xFF, 0xD8, 0xFF, 0xE0>>

    actions do
      action :caption, :string do
        description "A photo's caption"
        allow_nil? true
        argument :id, :string, allow_nil?: false
        argument :lang, :string, default: "en"

        run fn %{arguments: arguments}, _context ->
          case arguments.id do
            "missing" -> {:ok, nil}
            id -> {:ok, "caption #{id} (#{arguments.lang})"}
          end
        end
      end

      action :raw, :binary do
        argument :id, :string, allow_nil?: false
        run fn %{arguments: %{id: id}}, _context -> {:ok, @png <> id} end
      end

      action :featured, :string do
        run fn _input, _context -> {:ok, "the featured photo"} end
      end

      action :file, :string do
        argument :path, :string, allow_nil?: false
        run fn %{arguments: %{path: path}}, _context -> {:ok, "file #{path}"} end
      end

      action :photo, :map do
        argument :id, :string, allow_nil?: false

        run fn %{arguments: %{id: id}}, _context ->
          case id do
            "gone" ->
              {:error, Ash.Error.Query.NotFound.exception(resource: Photo, primary_key: id)}

            "broken" ->
              {:error, "storage unavailable"}

            id ->
              {:ok, %{id: id, mime_type: "image/jpeg", data: @jpeg}}
          end
        end
      end
    end
  end

  defmodule Views do
    def photo(%{data: data, mime_type: mime_type}, %Contents.Context{} = context) do
      send(self(), {:contents_context, context})
      Contents.blob(data, mime_type: mime_type)
    end

    def album(%{id: id, data: data}, _context) do
      [
        Contents.text("album #{id}"),
        Contents.blob(data,
          uri: "photos://#{id}/cover",
          mime_type: "image/jpeg",
          meta: %{"com.example/role" => "cover"}
        )
      ]
    end

    def invalid(_result, _context), do: %{"text" => "not built with text/2"}
    def raising(_result, _context), do: raise("boom")
  end

  defmodule Domain do
    use Ash.Domain, extensions: [AshAi], validate_config_inclusion?: false

    resources do
      resource Photo
    end

    mcp_resources do
      mcp_resource :featured, "photos://featured", Photo, :featured, title: "Featured"

      mcp_resource :photo, "photos://{id}", Photo, :photo,
        title: "Photo",
        description: "A photo, as an image",
        contents: &Views.photo/2

      mcp_resource :caption, "photos://{id}/caption{?lang}", Photo, :caption, title: "Caption"

      mcp_resource :raw, "photos://{id}/raw", Photo, :raw,
        title: "Raw photo",
        mime_type: "image/png"

      mcp_resource :album, "albums://{id}", Photo, :photo,
        title: "Album",
        contents: &Views.album/2

      mcp_resource :file, "files:///{+path}", Photo, :file, title: "File"

      mcp_resource :invalid, "invalid://{id}", Photo, :photo,
        title: "Invalid",
        contents: &Views.invalid/2

      mcp_resource :raising, "raising://{id}", Photo, :photo,
        title: "Raising",
        contents: &Views.raising/2
    end
  end

  setup do
    otp_app = :"ash_ai_resource_templates_#{System.unique_integer([:positive])}"
    Application.put_env(otp_app, :ash_domains, [Domain])
    on_exit(fn -> Application.delete_env(otp_app, :ash_domains) end)

    %{opts: [otp_app: otp_app]}
  end

  describe "resources/templates/list" do
    test "lists templated resources, sorted by template", %{opts: opts} do
      for protocol <- @protocols do
        assert {200, %{"result" => %{"resourceTemplates" => templates} = result}} =
                 request(protocol, "resources/templates/list", %{}, opts)

        refute Map.has_key?(result, "nextCursor")

        assert Enum.map(templates, & &1["uriTemplate"]) == [
                 "albums://{id}",
                 "files:///{+path}",
                 "invalid://{id}",
                 "photos://{id}",
                 "photos://{id}/caption{?lang}",
                 "photos://{id}/raw",
                 "raising://{id}"
               ]

        assert %{
                 "name" => "photo",
                 "title" => "Photo",
                 "description" => "A photo, as an image"
               } = photo = Enum.find(templates, &(&1["name"] == "photo"))

        refute Map.has_key?(photo, "mimeType"), "contents sets each read's MIME type"
        refute Map.has_key?(photo, "uri")

        assert %{"mimeType" => "image/png"} = Enum.find(templates, &(&1["name"] == "raw"))

        assert %{"mimeType" => "text/plain", "description" => "A photo's caption"} =
                 Enum.find(templates, &(&1["name"] == "caption"))
      end
    end

    test "is paged like the other lists", %{opts: opts} do
      opts = Keyword.put(opts, :list_page_size, 3)

      for protocol <- @protocols do
        assert protocol |> pages("resources/templates/list", opts) |> length() == 3
      end
    end

    test "resources/list leaves templated resources out", %{opts: opts} do
      for protocol <- @protocols do
        assert {200, %{"result" => %{"resources" => resources}}} =
                 request(protocol, "resources/list", %{}, opts)

        assert Enum.map(resources, & &1["uri"]) == ["photos://featured"]
      end
    end
  end

  describe "reading a templated resource" do
    test "passes path and query variables to the action", %{opts: opts} do
      for protocol <- @protocols do
        assert read(protocol, "photos://42/caption", opts) == [
                 %{
                   "uri" => "photos://42/caption",
                   "mimeType" => "text/plain",
                   "text" => "caption 42 (en)"
                 }
               ]

        assert [%{"text" => "caption 42 (fr)"}] =
                 read(protocol, "photos://42/caption?lang=fr", opts)
      end
    end

    test "percent-decodes variables", %{opts: opts} do
      assert [%{"text" => "caption a b (en)"}] =
               read(:initialize_based, "photos://a%20b/caption", opts)
    end

    test "matches a reserved variable across path segments", %{opts: opts} do
      assert [%{"uri" => "files:///docs/a/b.txt", "text" => "file docs/a/b.txt"}] =
               read(:initialize_based, "files:///docs/a/b.txt", opts)
    end

    test "prefers a resource whose URI matches exactly", %{opts: opts} do
      assert [%{"text" => "the featured photo"}] =
               read(:initialize_based, "photos://featured", opts)
    end

    test "variables win over request params of the same name", %{opts: opts} do
      assert [%{"text" => "caption 42 (en)"}] =
               read(:initialize_based, "photos://42/caption", opts, %{"id" => "7"})
    end

    test "a URI no template matches is not found", %{opts: opts} do
      for uri <- [
            "photos://42/caption?size=2",
            "photos://42/thumbnail",
            "photos://",
            "videos://42"
          ] do
        assert not_found?(:initialize_based, uri, opts), uri
        assert not_found?(:per_request, uri, opts), uri
      end
    end

    test "an action returning nil is not found", %{opts: opts} do
      for protocol <- @protocols do
        assert not_found?(protocol, "photos://missing/caption", opts)
      end
    end

    test "an action failing with NotFound is not found", %{opts: opts} do
      for protocol <- @protocols do
        assert not_found?(protocol, "photos://gone", opts)
      end
    end

    test "other action errors are read errors", %{opts: opts} do
      assert {200, %{"error" => %{"code" => -32_603, "data" => %{"error" => error}}}} =
               request(:initialize_based, "resources/read", %{"uri" => "photos://broken"}, opts)

      assert error =~ "storage unavailable"
    end
  end

  describe "binary contents" do
    test "an action returning :binary is sent as a base64 blob", %{opts: opts} do
      for protocol <- @protocols do
        assert [%{"uri" => "photos://7/raw", "mimeType" => "image/png", "blob" => blob} = item] =
                 read(protocol, "photos://7/raw", opts)

        refute Map.has_key?(item, "text")
        assert Base.decode64!(blob) == @png <> "7"
      end
    end

    test "defaults a binary action's MIME type to application/octet-stream" do
      assert %AshAi.McpResource{mime_type: "application/octet-stream"} =
               [actions: [{__MODULE__.BinaryOnly, :*}]]
               |> AshAi.exposed_mcp_action_resources()
               |> Enum.find(&(&1.name == :untyped_raw))
    end
  end

  describe "contents" do
    test "builds the contents from the action's result", %{opts: opts} do
      for protocol <- @protocols do
        assert [%{"uri" => "photos://9", "mimeType" => "image/jpeg", "blob" => blob}] =
                 read(protocol, "photos://9", opts)

        assert Base.decode64!(blob) == @jpeg
      end
    end

    test "receives the read's context", %{opts: opts} do
      read(:initialize_based, "photos://9", opts)

      assert_received {:contents_context,
                       %Contents.Context{
                         uri: "photos://9",
                         arguments: %{"id" => "9"},
                         mcp_resource: %AshAi.McpResource{name: :photo}
                       }}
    end

    test "can return several items, each with its own URI and _meta", %{opts: opts} do
      assert [
               %{"uri" => "albums://3", "text" => "album 3"} = text,
               %{
                 "uri" => "photos://3/cover",
                 "mimeType" => "image/jpeg",
                 "blob" => _,
                 "_meta" => %{"com.example/role" => "cover"}
               }
             ] = read(:initialize_based, "albums://3", opts)

      refute Map.has_key?(text, "mimeType")
    end

    test "isn't called when the action finds nothing", %{opts: opts} do
      assert not_found?(:initialize_based, "photos://gone", opts)
      refute_received {:contents_context, _}
    end

    test "an invalid return is logged and sent as a read error", %{opts: opts} do
      log =
        capture_log(fn ->
          assert {200, %{"error" => %{"code" => -32_603, "data" => %{"error" => error}}}} =
                   request(
                     :initialize_based,
                     "resources/read",
                     %{"uri" => "invalid://1"},
                     opts
                   )

          assert error == "Failed to build the resource's contents: invalid contents"
        end)

      assert log =~ "Reading mcp_resource :invalid failed"
      assert log =~ ~s(%{"text" => "not built with text/2"})
    end

    test "a raise is logged and sent as a read error", %{opts: opts} do
      log =
        capture_log(fn ->
          assert {200, %{"error" => %{"code" => -32_603, "data" => %{"error" => error}}}} =
                   request(
                     :initialize_based,
                     "resources/read",
                     %{"uri" => "raising://1"},
                     opts
                   )

          assert error == "Failed to build the resource's contents: contents callback failed"
        end)

      assert log =~ "Reading mcp_resource :raising failed"
      assert log =~ "boom"
    end
  end

  describe "content helpers" do
    test "reject unknown options" do
      assert_raise ArgumentError, fn -> Contents.text("hi", mimetype: "text/plain") end
      assert_raise ArgumentError, fn -> Contents.blob(<<0>>, size: 1) end
    end
  end

  defmodule BinaryOnly do
    use Ash.Resource, domain: __MODULE__.BinaryDomain, validate_domain_inclusion?: false

    actions do
      action :bytes, :binary do
        run fn _input, _context -> {:ok, <<0>>} end
      end
    end

    defmodule BinaryDomain do
      use Ash.Domain, extensions: [AshAi], validate_config_inclusion?: false

      resources do
        resource AshAi.Mcp.ResourceTemplatesTest.BinaryOnly
      end

      mcp_resources do
        mcp_resource :untyped_raw,
                     "file://raw",
                     AshAi.Mcp.ResourceTemplatesTest.BinaryOnly,
                     :bytes,
                     title: "Untyped raw"
      end
    end
  end

  defp read(protocol, uri, opts, params \\ %{}) do
    assert {200, %{"result" => %{"contents" => contents}}} =
             request(protocol, "resources/read", Map.put(params, "uri", uri), opts)

    contents
  end

  # 2026-07-28 reports a missing resource as -32602; earlier revisions as -32002
  defp not_found?(protocol, uri, opts) do
    expected_code = if protocol == :per_request, do: -32_602, else: -32_002

    match?(
      {200, %{"error" => %{"code" => ^expected_code, "message" => "Resource not found"}}},
      request(protocol, "resources/read", %{"uri" => uri}, opts)
    )
  end

  defp pages(protocol, method, opts, cursor \\ nil) do
    params = if cursor, do: %{"cursor" => cursor}, else: %{}
    {200, %{"result" => result}} = request(protocol, method, params, opts)

    case result["nextCursor"] do
      nil -> [result]
      next -> [result | pages(protocol, method, opts, next)]
    end
  end

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

    conn =
      :post
      |> conn("/", body)
      |> put_req_header("mcp-protocol-version", @protocol_version)
      |> put_req_header("mcp-method", method)

    conn =
      if method == "resources/read",
        do: put_req_header(conn, "mcp-name", params["uri"]),
        else: conn

    send_request(conn, opts)
  end

  defp send_request(conn, opts) do
    response = Router.call(conn, opts)
    {response.status, Jason.decode!(response.resp_body)}
  end
end
