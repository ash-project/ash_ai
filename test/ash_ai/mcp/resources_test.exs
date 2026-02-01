# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.ResourcesTest do
  @moduledoc """
  Tests for MCP resources functionality including resources/list and resources/read endpoints.
  """
  use AshAi.RepoCase, async: false
  import Plug.{Conn, Test}

  alias AshAi.Mcp.Router

  @opts [otp_app: :ash_ai]

  describe "resources/list" do
    test "returns available MCP resources" do
      session_id = initialize_and_get_session_id(@opts)

      response = list_resources(session_id, @opts)
      body = decode_response(response)

      assert response.status == 200
      assert body["jsonrpc"] == "2.0"
      assert body["id"] == "list_1"
      assert is_list(body["result"]["resources"])
      assert length(body["result"]["resources"]) > 0

      # Verify at least the artist_card resource is present
      artist_card = Enum.find(body["result"]["resources"], &(&1["name"] == "artist_card"))
      assert artist_card
      assert artist_card["uri"] == "file://ui/artist_card.html"
      assert artist_card["mimeType"] == "text/html"
    end

    test "returns all configured resources with correct metadata" do
      session_id = initialize_and_get_session_id(@opts)

      response = list_resources(session_id, @opts)
      body = decode_response(response)

      resources = body["result"]["resources"]
      assert length(resources) == 6

      resource_names = Enum.map(resources, & &1["name"])
      assert "artist_card" in resource_names
      assert "artist_json" in resource_names
      assert "artist_with_params" in resource_names
      assert "failing_resource" in resource_names
      assert "artist_card_custom" in resource_names
      assert "actor_test_resource" in resource_names

      # Verify each resource has required fields
      for resource <- resources do
        assert is_binary(resource["name"])
        assert is_binary(resource["uri"])
        assert is_binary(resource["mimeType"])
      end
    end

    test "includes action descriptions in resources" do
      session_id = initialize_and_get_session_id(@opts)

      response = list_resources(session_id, @opts)
      body = decode_response(response)

      resources = body["result"]["resources"]

      # Find the artist_card resource which has a description from its action
      artist_card = Enum.find(resources, &(&1["name"] == "artist_card"))
      assert artist_card["description"] == "Get an artist card UI representation."

      # Artist JSON should also have its description from the action
      artist_json = Enum.find(resources, &(&1["name"] == "artist_json"))
      assert artist_json["description"] == "Get artist data as JSON string."
    end

    test "DSL description overrides action description" do
      session_id = initialize_and_get_session_id(@opts)

      response = list_resources(session_id, @opts)
      body = decode_response(response)

      resources = body["result"]["resources"]

      # Find the resource with custom description set via DSL
      custom_card = Enum.find(resources, &(&1["name"] == "artist_card_custom"))
      # This should use the DSL description, not the action description
      assert custom_card["description"] == "Custom description from DSL"
    end
  end

  describe "resources/read" do
    test "successfully reads a resource with valid URI" do
      session_id = initialize_and_get_session_id(@opts)

      response = read_resource(session_id, "file://ui/artist_card.html", @opts)
      body = decode_response(response)

      assert response.status == 200
      assert body["jsonrpc"] == "2.0"
      assert body["id"] == "read_1"

      contents = body["result"]["contents"]
      assert is_list(contents)
      assert length(contents) == 1

      [item] = contents
      assert item["uri"] == "file://ui/artist_card.html"
      assert item["mimeType"] == "text/html"
      assert item["text"] == "<div>Artist Card</div>"
    end

    test "returns -32002 error for non-existent URI" do
      session_id = initialize_and_get_session_id(@opts)

      response = read_resource(session_id, "file://does/not/exist.txt", @opts)
      body = decode_response(response)

      assert response.status == 200
      assert body["jsonrpc"] == "2.0"
      assert body["error"]["code"] == -32_002
      assert body["error"]["message"] == "Resource not found"
      assert body["error"]["data"]["uri"] == "file://does/not/exist.txt"
    end

    test "returns -32603 error when action execution fails" do
      session_id = initialize_and_get_session_id(@opts)

      response = read_resource(session_id, "file://fail/test", @opts)
      body = decode_response(response)

      assert response.status == 200
      assert body["jsonrpc"] == "2.0"
      assert body["error"]["code"] == -32_603
      assert body["error"]["message"] == "Resource read failed"
      assert body["error"]["data"]["uri"] == "file://fail/test"
      assert body["error"]["data"]["error"]
    end

    test "requires exact URI match" do
      session_id = initialize_and_get_session_id(@opts)

      # Test similar but not exact URIs
      similar_uris = [
        "file://ui/artist_card.HTML",
        "file://ui/artist_card.html/",
        "file://UI/artist_card.html",
        "file://ui/artist_card"
      ]

      for uri <- similar_uris do
        response = read_resource(session_id, uri, @opts)
        body = decode_response(response)

        assert body["error"]["code"] == -32_002,
               "Expected resource not found for URI: #{uri}"
      end
    end

    test "preserves different mime types" do
      session_id = initialize_and_get_session_id(@opts)

      # Test HTML mime type
      html_response = read_resource(session_id, "file://ui/artist_card.html", @opts)
      html_body = decode_response(html_response)
      [html_content] = html_body["result"]["contents"]
      assert html_content["mimeType"] == "text/html"

      # Test JSON mime type
      json_response = read_resource(session_id, "file://data/artist.json", @opts)
      json_body = decode_response(json_response)
      [json_content] = json_body["result"]["contents"]
      assert json_content["mimeType"] == "application/json"

      # Verify JSON content can be parsed
      assert {:ok, _} = Jason.decode(json_content["text"])
    end

    test "action with parameters filters safely" do
      session_id = initialize_and_get_session_id(@opts)

      # Pass both valid and invalid parameters
      params = %{
        "uri" => "file://ui/custom_card.html",
        "template" => "Custom Template",
        "extra_param" => "should be ignored",
        "another_param" => 123
      }

      response = read_resource(session_id, "file://ui/custom_card.html", params, @opts)
      body = decode_response(response)

      assert response.status == 200
      [content] = body["result"]["contents"]
      assert content["text"] == "<div>Custom Template</div>"
    end
  end

  describe "context and session" do
    test "session context is passed to action" do
      init_response =
        conn(:post, "/", %{
          "method" => "initialize",
          "id" => "init_1",
          "params" => %{"client" => %{"name" => "test_client", "version" => "1.0.0"}}
        })
        |> Router.call(@opts)

      session_id = extract_session_id(init_response)
      assert session_id

      response = read_resource(session_id, "file://ui/artist_card.html", @opts)
      body = decode_response(response)

      assert body["result"], "Expected successful response when session context is valid"
    end

    test "actor is passed through to MCP resource actions" do
      test_actor = %{id: "test_user_123", name: "Test User"}
      session_id = initialize_and_get_session_id(@opts)

      response =
        conn(:post, "/", %{
          "method" => "resources/read",
          "id" => "actor_read_1",
          "params" => %{"uri" => "file://test/actor"}
        })
        |> put_req_header("mcp-session-id", session_id)
        |> Ash.PlugHelpers.set_actor(test_actor)
        |> Router.call(@opts)

      body = decode_response(response)

      assert response.status == 200
      assert body["result"]["contents"]
      [content] = body["result"]["contents"]
      assert content["text"] =~ "actor:"
      assert content["text"] =~ "test_user_123"
    end

    test "nil actor is handled correctly in MCP resource actions" do
      session_id = initialize_and_get_session_id(@opts)

      response = read_resource(session_id, "file://test/actor", @opts)
      body = decode_response(response)

      assert response.status == 200
      assert body["result"]["contents"]
      [content] = body["result"]["contents"]
      assert content["text"] == "no_actor"
    end

    test "tenant is passed through to MCP resource actions" do
      test_tenant = "test_tenant_org"
      session_id = initialize_and_get_session_id(@opts)

      response =
        conn(:post, "/", %{
          "method" => "resources/read",
          "id" => "tenant_read_1",
          "params" => %{"uri" => "file://test/actor"}
        })
        |> put_req_header("mcp-session-id", session_id)
        |> Ash.PlugHelpers.set_tenant(test_tenant)
        |> Router.call(@opts)

      body = decode_response(response)

      assert response.status == 200
      assert body["result"]["contents"]
    end
  end

  describe "error handling" do
    test "JSON-RPC error format is valid" do
      session_id = initialize_and_get_session_id(@opts)

      # Test resource not found error
      not_found_response = read_resource(session_id, "file://not/found", @opts)
      not_found_body = decode_response(not_found_response)

      assert not_found_body["jsonrpc"] == "2.0"
      assert not_found_body["id"]
      assert is_map(not_found_body["error"])
      assert is_integer(not_found_body["error"]["code"])
      assert not_found_body["error"]["message"] == "Resource not found"
      assert is_map(not_found_body["error"]["data"])

      # Test action failure error
      failure_response = read_resource(session_id, "file://fail/test", @opts)
      failure_body = decode_response(failure_response)

      assert failure_body["jsonrpc"] == "2.0"
      assert failure_body["id"]
      assert is_map(failure_body["error"])
      assert is_integer(failure_body["error"]["code"])
      assert failure_body["error"]["message"] == "Resource read failed"
      assert is_map(failure_body["error"]["data"])
    end
  end

  describe "initialization" do
    test "capabilities include resources when MCP resources are present" do
      init_response =
        conn(:post, "/", %{
          "method" => "initialize",
          "id" => "init_1",
          "params" => %{"client" => %{"name" => "test_client", "version" => "1.0.0"}}
        })
        |> Router.call(@opts)

      init_body = decode_response(init_response)

      assert init_response.status == 200
      assert init_body["result"]["capabilities"]["resources"]
      assert init_body["result"]["capabilities"]["tools"]
    end

    test "capabilities does not include resources when MCP resources not present" do
      init_response =
        conn(:post, "/", %{
          "method" => "initialize",
          "id" => "init_1",
          "params" => %{"client" => %{"name" => "test_client", "version" => "1.0.0"}}
        })
        |> Router.call(Keyword.put(@opts, :mcp_resources, []))

      init_body = decode_response(init_response)

      assert init_response.status == 200
      assert init_body["result"]["capabilities"]["tools"]
      refute init_body["result"]["capabilities"]["resources"]
    end
  end

  describe "integration" do
    test "full flow: initialize -> list -> read" do
      init_response =
        conn(:post, "/", %{
          "method" => "initialize",
          "id" => "init_1",
          "params" => %{"client" => %{"name" => "test_client", "version" => "1.0.0"}}
        })
        |> Router.call(@opts)

      session_id = extract_session_id(init_response)
      init_body = decode_response(init_response)

      assert init_response.status == 200
      assert init_body["result"]["capabilities"]["resources"]

      list_response = list_resources(session_id, @opts)
      list_body = decode_response(list_response)

      assert list_response.status == 200
      resources = list_body["result"]["resources"]
      assert length(resources) == 6

      first_resource = hd(resources)
      uri = first_resource["uri"]

      read_response = read_resource(session_id, uri, @opts)
      read_body = decode_response(read_response)

      assert read_response.status == 200
      [content] = read_body["result"]["contents"]
      assert content["uri"] == uri
      assert is_binary(content["text"])
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

  defp list_resources(session_id, opts) do
    conn(:post, "/", %{"method" => "resources/list", "id" => "list_1"})
    |> put_req_header("mcp-session-id", session_id)
    |> Router.call(opts)
  end

  defp read_resource(session_id, uri, opts) when is_binary(uri) do
    read_resource(session_id, uri, %{}, opts)
  end

  defp read_resource(session_id, uri, params, opts) when is_map(params) do
    request_params = Map.put(params, "uri", uri)

    conn(:post, "/", %{"method" => "resources/read", "id" => "read_1", "params" => request_params})
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
