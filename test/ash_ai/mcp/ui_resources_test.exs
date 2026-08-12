# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.UiResourcesTest do
  @moduledoc """
  Tests for MCP Apps UI resource-specific behavior (_meta.ui, mimeType, HTML serving).
  """
  use AshAi.RepoCase, async: false
  import Plug.{Conn, Test}

  alias AshAi.Mcp.Router

  @opts [otp_app: :ash_ai]
  @ui_extension "io.modelcontextprotocol/ui"
  @ui_mime_type "text/html;profile=mcp-app"

  describe "mcp_ui_resource in resources/list" do
    test "includes UI resources in the resource list" do
      session_id = initialize_and_get_session_id(@opts)

      response = list_resources(session_id, @opts)
      body = decode_response(response)

      resources = body["result"]["resources"]
      ui_resource = Enum.find(resources, &(&1["uri"] == "ui://test/app.html"))

      assert ui_resource
      assert ui_resource["name"] == "test_app"
      assert ui_resource["title"] == "Test App"
      assert ui_resource["description"] == "A test MCP App UI resource"
      assert ui_resource["mimeType"] == "text/html;profile=mcp-app"
    end

    test "UI resource with CSP and permissions includes _meta" do
      session_id = initialize_and_get_session_id(@opts)

      response = list_resources(session_id, @opts)
      body = decode_response(response)

      resources = body["result"]["resources"]
      csp_resource = Enum.find(resources, &(&1["uri"] == "ui://test/csp_app.html"))

      assert csp_resource
      assert csp_resource["_meta"]["ui"]["csp"]["connectDomains"] == ["api.example.com"]
      assert csp_resource["_meta"]["ui"]["csp"]["frameDomains"] == ["cdn.example.com"]
      assert csp_resource["_meta"]["ui"]["permissions"]["camera"] == %{}
      assert csp_resource["_meta"]["ui"]["permissions"]["clipboardWrite"] == %{}
      assert csp_resource["_meta"]["ui"]["domain"] == "test.example.com"
      assert csp_resource["_meta"]["ui"]["prefersBorder"] == true
    end

    test "UI resource with default :auto domain includes computed domain in _meta" do
      session_id = initialize_and_get_session_id(@opts)

      response = list_resources(session_id, @opts)
      body = decode_response(response)

      resources = body["result"]["resources"]
      plain_resource = Enum.find(resources, &(&1["uri"] == "ui://test/app.html"))

      assert plain_resource["_meta"]["ui"]["domain"] =~ ~r/^[0-9a-f]{32}\.claudemcpcontent\.com$/
    end
  end

  describe "mcp_ui_resource in resources/read" do
    test "serves HTML file content for UI resource" do
      session_id = initialize_and_get_session_id(@opts)

      response = read_resource(session_id, "ui://test/app.html", @opts)
      body = decode_response(response)

      assert response.status == 200
      [content] = body["result"]["contents"]
      assert content["uri"] == "ui://test/app.html"
      assert content["mimeType"] == "text/html;profile=mcp-app"
      assert content["text"] =~ "Hello from MCP App"
    end

    test "resources/read includes _meta for UI resource with CSP" do
      session_id = initialize_and_get_session_id(@opts)

      response = read_resource(session_id, "ui://test/csp_app.html", @opts)
      body = decode_response(response)

      [content] = body["result"]["contents"]
      assert content["_meta"]["ui"]["csp"]["connectDomains"] == ["api.example.com"]
      assert content["_meta"]["ui"]["csp"]["frameDomains"] == ["cdn.example.com"]
      assert content["_meta"]["ui"]["permissions"]["camera"] == %{}
      assert content["_meta"]["ui"]["permissions"]["clipboardWrite"] == %{}
      assert content["_meta"]["ui"]["domain"] == "test.example.com"
      assert content["_meta"]["ui"]["prefersBorder"] == true
    end

    test "resources/read includes auto-computed domain for UI resource without CSP" do
      session_id = initialize_and_get_session_id(@opts)

      response = read_resource(session_id, "ui://test/app.html", @opts)
      body = decode_response(response)

      [content] = body["result"]["contents"]
      assert content["_meta"]["ui"]["domain"] =~ ~r/^[0-9a-f]{32}\.claudemcpcontent\.com$/
    end
  end

  describe "Info introspection" do
    test "mcp_ui_resources/1 returns only UI resources" do
      ui_resources = AshAi.Info.mcp_ui_resources(AshAi.Test.Music)
      assert length(ui_resources) == 2
      assert Enum.all?(ui_resources, &match?(%AshAi.McpUiResource{}, &1))
    end

    test "mcp_action_resources/1 returns only action-based resources" do
      action_resources = AshAi.Info.mcp_action_resources(AshAi.Test.Music)
      assert length(action_resources) == 6
      assert Enum.all?(action_resources, &match?(%AshAi.McpResource{}, &1))
    end
  end

  describe "MCP Apps extension negotiation" do
    test "initialize advertises the stable extension for a capable client" do
      response = initialize_with_capabilities(@opts, ui_capabilities())
      capabilities = decode_response(response)["result"]["capabilities"]

      assert capabilities["extensions"][@ui_extension] == %{
               "mimeTypes" => [@ui_mime_type]
             }
    end

    test "initialize omits the extension for a client without the supported MIME type" do
      response = initialize_with_capabilities(@opts, %{})
      capabilities = decode_response(response)["result"]["capabilities"]

      refute Map.has_key?(capabilities, "extensions")
    end

    test "a non-App client retains the native UI-linked tool and text result" do
      response = initialize_with_capabilities(@opts, %{})
      session_id = extract_session_id(response)

      tool_response =
        conn(:post, "/", %{"method" => "tools/list", "id" => "list_tools"})
        |> put_req_header("mcp-session-id", session_id)
        |> Router.call(tools: [:list_artists_with_ui], otp_app: :ash_ai)

      [tool] = decode_response(tool_response)["result"]["tools"]
      assert tool["_meta"]["ui"]["resourceUri"] == "ui://test/app.html"

      call_response =
        conn(:post, "/", %{
          "method" => "tools/call",
          "id" => "call_tool",
          "params" => %{"name" => "list_artists_with_ui", "arguments" => %{}}
        })
        |> put_req_header("mcp-session-id", session_id)
        |> Router.call(tools: [:list_artists_with_ui], otp_app: :ash_ai)

      result = decode_response(call_response)["result"]
      assert result["isError"] == false
      assert [%{"type" => "text", "text" => text}] = result["content"]
      assert is_list(Jason.decode!(text))
    end

    test "2026-07-28 server discovery negotiates the extension per request" do
      capable = discover_2026_07_28(@opts, ui_capabilities())
      incapable = discover_2026_07_28(@opts, %{})

      assert capable["capabilities"]["extensions"][@ui_extension] == %{
               "mimeTypes" => [@ui_mime_type]
             }

      refute Map.has_key?(incapable["capabilities"], "extensions")
    end

    test "servers without UI resources do not advertise the extension" do
      response = initialize_with_capabilities([actions: [], mcp_resources: []], ui_capabilities())
      capabilities = decode_response(response)["result"]["capabilities"]

      refute Map.has_key?(capabilities, "extensions")
    end
  end

  # Helper functions

  defp initialize_and_get_session_id(opts) do
    response =
      conn(:post, "/", %{
        "method" => "initialize",
        "id" => "init_1",
        "params" => %{"client" => %{"name" => "test_client", "version" => "1.0.0"}}
      })
      |> Router.call(opts)

    extract_session_id(response)
  end

  defp initialize_with_capabilities(opts, capabilities) do
    conn(:post, "/", %{
      "method" => "initialize",
      "id" => "init_capabilities",
      "params" => %{
        "protocolVersion" => "2025-06-18",
        "capabilities" => capabilities,
        "clientInfo" => %{"name" => "test_client", "version" => "1.0.0"}
      }
    })
    |> Router.call(opts)
  end

  defp discover_2026_07_28(opts, client_capabilities) do
    method = "server/discover"

    meta = %{
      "io.modelcontextprotocol/protocolVersion" => "2026-07-28",
      "io.modelcontextprotocol/clientCapabilities" => client_capabilities,
      "io.modelcontextprotocol/clientInfo" => %{"name" => "test_client", "version" => "1.0.0"}
    }

    conn(:post, "/", %{
      "jsonrpc" => "2.0",
      "id" => "discover",
      "method" => method,
      "params" => %{"_meta" => meta}
    })
    |> put_req_header("mcp-protocol-version", "2026-07-28")
    |> put_req_header("mcp-method", method)
    |> Router.call(opts)
    |> decode_response()
    |> Map.fetch!("result")
  end

  defp ui_capabilities do
    %{
      "extensions" => %{
        @ui_extension => %{"mimeTypes" => [@ui_mime_type]}
      }
    }
  end

  defp list_resources(session_id, opts) do
    conn(:post, "/", %{"method" => "resources/list", "id" => "list_1"})
    |> put_req_header("mcp-session-id", session_id)
    |> Router.call(opts)
  end

  defp read_resource(session_id, uri, opts) do
    conn(:post, "/", %{
      "method" => "resources/read",
      "id" => "read_1",
      "params" => %{"uri" => uri}
    })
    |> put_req_header("mcp-session-id", session_id)
    |> Router.call(opts)
  end

  defp extract_session_id(response) do
    List.first(Plug.Conn.get_resp_header(response, "mcp-session-id"))
  end

  defp decode_response(response) do
    Jason.decode!(response.resp_body)
  end
end
