# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.Protocol20260728Test do
  @moduledoc """
  Tests for the stateless 2026-07-28 protocol revision, served in tandem with
  the initialize-based revisions.
  """
  use AshAi.RepoCase, async: false
  import Plug.{Conn, Test}

  alias AshAi.Mcp.Router
  alias AshAi.Test.Music

  @protocol_version "2026-07-28"
  @meta_protocol_version "io.modelcontextprotocol/protocolVersion"
  @meta_server_info "io.modelcontextprotocol/serverInfo"
  @meta_subscription_id "io.modelcontextprotocol/subscriptionId"

  @tool_opts [tools: [:list_artists], otp_app: :ash_ai]
  @resource_opts [otp_app: :ash_ai]

  defp request_meta(version \\ @protocol_version) do
    %{
      @meta_protocol_version => version,
      "io.modelcontextprotocol/clientInfo" => %{"name" => "test_client", "version" => "1.0.0"},
      "io.modelcontextprotocol/clientCapabilities" => %{}
    }
  end

  defp versioned_conn(method, id, params, headers) do
    params = Map.put_new(params, "_meta", request_meta())

    default_headers = %{
      "mcp-protocol-version" => @protocol_version,
      "mcp-method" => method
    }

    conn =
      conn(:post, "/", %{"jsonrpc" => "2.0", "id" => id, "method" => method, "params" => params})

    default_headers
    |> Map.merge(headers)
    |> Enum.reduce(conn, fn
      {_name, nil}, conn -> conn
      {name, value}, conn -> put_req_header(conn, name, value)
    end)
  end

  defp versioned_request(method, params \\ %{}, headers \\ %{}, opts \\ @tool_opts) do
    method
    |> versioned_conn("req_1", params, headers)
    |> Router.call(opts)
  end

  describe "server/discover" do
    test "advertises supported versions, capabilities, and identity" do
      response = versioned_request("server/discover")
      assert response.status == 200

      result = Jason.decode!(response.resp_body)["result"]

      assert result["resultType"] == "complete"
      assert List.first(result["supportedVersions"]) == @protocol_version
      assert "2025-03-26" in result["supportedVersions"]
      assert result["capabilities"]["tools"] == %{"listChanged" => false}
      assert result["_meta"][@meta_server_info]["name"] == "MCP Server"
      assert is_integer(result["ttlMs"])
      assert result["cacheScope"] == "private"
    end

    test "rejects unsupported requested versions like any other method" do
      response =
        versioned_request("server/discover", %{"_meta" => request_meta("2030-01-01")}, %{
          "mcp-protocol-version" => "2030-01-01"
        })

      assert response.status == 400

      error = Jason.decode!(response.resp_body)["error"]
      assert error["code"] == -32_022
      assert @protocol_version in error["data"]["supported"]
    end
  end

  describe "_meta validation" do
    test "a request missing _meta entirely is rejected with -32602" do
      conn =
        conn(:post, "/", %{"jsonrpc" => "2.0", "id" => "1", "method" => "tools/list"})
        |> put_req_header("mcp-protocol-version", @protocol_version)
        |> put_req_header("mcp-method", "tools/list")

      response = Router.call(conn, @tool_opts)
      assert response.status == 400
      assert Jason.decode!(response.resp_body)["error"]["code"] == -32_602
    end

    test "a request whose _meta is missing the protocol version is rejected with -32602" do
      meta = Map.delete(request_meta(), @meta_protocol_version)
      response = versioned_request("tools/list", %{"_meta" => meta})

      assert response.status == 400

      error = Jason.decode!(response.resp_body)["error"]
      assert error["code"] == -32_602
      assert error["message"] =~ "protocolVersion"
    end

    test "a request whose _meta is missing clientCapabilities is rejected with -32602" do
      meta = Map.delete(request_meta(), "io.modelcontextprotocol/clientCapabilities")
      response = versioned_request("tools/list", %{"_meta" => meta})

      assert response.status == 400

      error = Jason.decode!(response.resp_body)["error"]
      assert error["code"] == -32_602
      assert error["message"] =~ "clientCapabilities"
    end

    test "clientInfo is not required" do
      meta = Map.delete(request_meta(), "io.modelcontextprotocol/clientInfo")
      response = versioned_request("tools/list", %{"_meta" => meta})

      assert response.status == 200
      assert Jason.decode!(response.resp_body)["result"]["resultType"] == "complete"
    end
  end

  describe "stateless requests" do
    test "tools/list returns cacheable, deterministically ordered tools without a session" do
      response = versioned_request("tools/list")
      assert response.status == 200
      assert get_resp_header(response, "mcp-session-id") == []

      result = Jason.decode!(response.resp_body)["result"]

      assert result["resultType"] == "complete"
      assert is_integer(result["ttlMs"])
      assert result["cacheScope"] == "private"
      assert result["_meta"][@meta_server_info]["version"]

      names = Enum.map(result["tools"], & &1["name"])
      assert names == Enum.sort(names)
      assert "list_artists" in names
    end

    test "tools/call executes with the Mcp-Name header" do
      Music.create_artist_after_action!(%{name: "Stateless Artist", bio: "2026-07-28 era"})

      response =
        versioned_request("tools/call", %{"name" => "list_artists", "arguments" => %{}}, %{
          "mcp-name" => "list_artists"
        })

      assert response.status == 200

      result = Jason.decode!(response.resp_body)["result"]
      assert result["resultType"] == "complete"
      assert result["isError"] == false

      [%{"type" => "text", "text" => text}] = result["content"]
      assert Enum.any?(Jason.decode!(text), &(&1["name"] == "Stateless Artist"))
    end

    test "tools/call accepts a Base64 sentinel encoded Mcp-Name header" do
      encoded = "=?base64?" <> Base.encode64("list_artists") <> "?="

      response =
        versioned_request("tools/call", %{"name" => "list_artists", "arguments" => %{}}, %{
          "mcp-name" => encoded
        })

      assert response.status == 200
      assert Jason.decode!(response.resp_body)["result"]["resultType"] == "complete"
    end

    test "unknown tools return -32602" do
      response =
        versioned_request("tools/call", %{"name" => "nonsense", "arguments" => %{}}, %{
          "mcp-name" => "nonsense"
        })

      assert response.status == 200
      assert Jason.decode!(response.resp_body)["error"]["code"] == -32_602
    end

    test "resources/read returns contents with cache metadata" do
      response =
        versioned_request(
          "resources/read",
          %{"uri" => "file://ui/artist_card.html"},
          %{"mcp-name" => "file://ui/artist_card.html"},
          @resource_opts
        )

      assert response.status == 200

      result = Jason.decode!(response.resp_body)["result"]
      assert result["resultType"] == "complete"
      assert result["cacheScope"] == "private"
      assert [%{"text" => "<div>Artist Card</div>"}] = result["contents"]
    end

    test "resources/read for a missing resource returns -32602 (not the older -32002)" do
      response =
        versioned_request(
          "resources/read",
          %{"uri" => "file://does/not/exist.txt"},
          %{"mcp-name" => "file://does/not/exist.txt"},
          @resource_opts
        )

      assert response.status == 200

      error = Jason.decode!(response.resp_body)["error"]
      assert error["code"] == -32_602
      assert error["data"]["uri"] == "file://does/not/exist.txt"
    end

    test "unknown methods return HTTP 404 with -32601" do
      response = versioned_request("some/unknown")

      assert response.status == 404
      assert Jason.decode!(response.resp_body)["error"]["code"] == -32_601
    end

    test "initialize with per-request _meta is a removed method naming supported versions" do
      response = versioned_request("initialize", %{"protocolVersion" => @protocol_version})

      assert response.status == 404

      error = Jason.decode!(response.resp_body)["error"]
      assert error["code"] == -32_601
      assert error["message"] =~ "2025-03-26"
    end

    test "whitespace-padded header values are accepted" do
      response =
        versioned_request("tools/call", %{"name" => "list_artists", "arguments" => %{}}, %{
          "mcp-name" => "  list_artists\t ",
          "mcp-method" => " tools/call "
        })

      assert response.status == 200
      assert Jason.decode!(response.resp_body)["result"]["resultType"] == "complete"
    end

    test "notifications are accepted with 202" do
      conn =
        conn(:post, "/", %{
          "jsonrpc" => "2.0",
          "method" => "notifications/whatever",
          "params" => %{"_meta" => request_meta()}
        })

      response = Router.call(conn, @tool_opts)
      assert response.status == 202
    end
  end

  describe "version negotiation" do
    test "unsupported versions are rejected with -32022 and the supported list" do
      response =
        versioned_request("tools/list", %{"_meta" => request_meta("2030-01-01")}, %{
          "mcp-protocol-version" => "2030-01-01"
        })

      assert response.status == 400

      error = Jason.decode!(response.resp_body)["error"]
      assert error["code"] == -32_022
      assert error["data"]["requested"] == "2030-01-01"
      assert @protocol_version in error["data"]["supported"]
    end

    test "initialize-based revisions this server doesn't advertise still route to initialize-based semantics" do
      # e.g. claude.ai sends `MCP-Protocol-Version: 2025-11-25` on requests
      # without per-request _meta; every dated revision before 2026-07-28
      # negotiates via initialize and must not be asked for _meta.
      for version <- ["2025-11-25", "2024-11-05"] do
        conn =
          conn(:post, "/", %{"jsonrpc" => "2.0", "id" => "1", "method" => "tools/list"})
          |> put_req_header("mcp-protocol-version", version)

        response = Router.call(conn, @tool_opts)
        assert response.status == 200

        result = Jason.decode!(response.resp_body)["result"]
        assert is_list(result["tools"])
        refute Map.has_key?(result, "resultType")
      end
    end

    test "initialize-based header versions still get initialize-based semantics" do
      conn =
        conn(:post, "/", %{"jsonrpc" => "2.0", "id" => "1", "method" => "tools/list"})
        |> put_req_header("mcp-protocol-version", "2025-03-26")

      response = Router.call(conn, @tool_opts)
      assert response.status == 200

      result = Jason.decode!(response.resp_body)["result"]
      refute Map.has_key?(result, "resultType")
      refute Map.has_key?(result, "ttlMs")
    end

    test "initialize echoes a supported requested version" do
      conn =
        conn(:post, "/", %{
          "jsonrpc" => "2.0",
          "id" => "1",
          "method" => "initialize",
          "params" => %{"protocolVersion" => "2025-06-18"}
        })

      response = Router.call(conn, @tool_opts)
      assert response.status == 200
      assert [_session_id] = get_resp_header(response, "mcp-session-id")

      result = Jason.decode!(response.resp_body)["result"]
      assert result["protocolVersion"] == "2025-06-18"
    end

    test "initialize downgrades unsupported requested versions" do
      conn =
        conn(:post, "/", %{
          "jsonrpc" => "2.0",
          "id" => "1",
          "method" => "initialize",
          "params" => %{"protocolVersion" => "2025-11-25"}
        })

      response = Router.call(conn, @tool_opts)
      assert Jason.decode!(response.resp_body)["result"]["protocolVersion"] == "2025-03-26"
    end
  end

  describe "header validation" do
    test "a missing Mcp-Method header is rejected with -32020" do
      response = versioned_request("tools/list", %{}, %{"mcp-method" => nil})

      assert response.status == 400

      error = Jason.decode!(response.resp_body)["error"]
      assert error["code"] == -32_020
      assert error["message"] =~ "Mcp-Method"
    end

    test "an Mcp-Method header that does not match the body is rejected" do
      response = versioned_request("tools/list", %{}, %{"mcp-method" => "tools/call"})

      assert response.status == 400
      assert Jason.decode!(response.resp_body)["error"]["code"] == -32_020
    end

    test "a protocol version header that does not match _meta is rejected" do
      response =
        versioned_request("tools/list", %{"_meta" => request_meta("2026-07-28")}, %{
          "mcp-protocol-version" => "2027-01-01"
        })

      assert response.status == 400

      error = Jason.decode!(response.resp_body)["error"]
      assert error["code"] == -32_020
      assert error["message"] =~ "MCP-Protocol-Version"
    end

    test "a missing Mcp-Name header on tools/call is rejected" do
      response = versioned_request("tools/call", %{"name" => "list_artists"})

      assert response.status == 400

      error = Jason.decode!(response.resp_body)["error"]
      assert error["code"] == -32_020
      assert error["message"] =~ "Mcp-Name"
    end

    test "an Mcp-Name header that does not match the body is rejected" do
      response =
        versioned_request("tools/call", %{"name" => "list_artists"}, %{"mcp-name" => "other_tool"})

      assert response.status == 400
      assert Jason.decode!(response.resp_body)["error"]["code"] == -32_020
    end

    test "an Mcp-Session-Id header is ignored on 2026-07-28 requests" do
      response =
        versioned_request("tools/list", %{}, %{
          "mcp-session-id" => "11111111-1111-1111-1111-111111111111"
        })

      assert response.status == 200
      assert get_resp_header(response, "mcp-session-id") == []
      assert Jason.decode!(response.resp_body)["result"]["resultType"] == "complete"
    end
  end

  describe "origin validation" do
    test "cross-origin requests over plain HTTP are rejected with 403" do
      response =
        "tools/list"
        |> versioned_conn("req_1", %{}, %{"origin" => "http://evil.example.com"})
        |> Router.call(@tool_opts)

      assert response.status == 403
    end

    test "localhost origins are accepted" do
      response =
        "tools/list"
        |> versioned_conn("req_1", %{}, %{"origin" => "http://localhost:4000"})
        |> Router.call(@tool_opts)

      assert response.status == 200
    end

    test "explicitly allowed origins are accepted" do
      response =
        "tools/list"
        |> versioned_conn("req_1", %{}, %{"origin" => "https://app.example.com"})
        |> Router.call(Keyword.put(@tool_opts, :allowed_origins, ["https://app.example.com"]))

      assert response.status == 200
    end
  end

  describe "subscriptions/listen" do
    test "acknowledges with an empty filter and closes gracefully" do
      response =
        versioned_request("subscriptions/listen", %{
          "notifications" => %{"toolsListChanged" => true}
        })

      assert response.status == 200
      assert get_resp_header(response, "content-type") == ["text/event-stream"]

      events =
        response.resp_body
        |> String.split("\n")
        |> Enum.filter(&String.starts_with?(&1, "data: "))
        |> Enum.map(&(&1 |> String.trim_leading("data: ") |> Jason.decode!()))

      assert [ack, close] = events

      assert ack["method"] == "notifications/subscriptions/acknowledged"
      assert ack["params"]["notifications"] == %{}
      assert ack["params"]["_meta"][@meta_subscription_id] == "req_1"

      assert close["id"] == "req_1"
      assert close["result"]["resultType"] == "complete"
      assert close["result"]["_meta"][@meta_subscription_id] == "req_1"
    end
  end
end
