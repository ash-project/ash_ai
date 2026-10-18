# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.ToolLoopIntegrationTest do
  @moduledoc false
  # A tool loop with a deferred MCP tool that pauses because the server needs
  # OAuth, and resumes the same call once the user authorizes.
  use ExUnit.Case, async: true

  import Plug.Conn

  alias AshAi.Mcp.{Client, OAuth}
  alias AshAi.Test.{FakeOAuthServer, OAuthMemoryStore}
  alias AshAi.ToolLoop
  alias AshAi.Transcript
  alias ReqLLM.{Context, StreamChunk}

  defmodule Widget do
    use Ash.Resource,
      domain: AshAi.Mcp.ToolLoopIntegrationTest.Domain,
      data_layer: Ash.DataLayer.Ets

    ets do
      private?(true)
    end

    actions do
      action :echo, :string do
        description "Echo a message back."
        argument :message, :string, allow_nil?: false

        run fn input, _ctx -> {:ok, "echo: #{input.arguments.message}"} end
      end
    end
  end

  defmodule Domain do
    use Ash.Domain, extensions: [AshAi]

    resources do
      resource Widget
    end

    tools do
      tool :echo, Widget, :echo
    end
  end

  defmodule FakeReqLLM do
    def stream_text(model, messages, opts) do
      [chunks | remaining] = Process.get(:responses)
      Process.put(:responses, remaining)
      send(self(), {:request, opts})

      {:ok,
       %ReqLLM.StreamResponse{
         stream: chunks,
         metadata_handle: AshAi.Test.StreamHelpers.metadata_handle(),
         cancel: fn -> :ok end,
         model: model,
         context: ReqLLM.Context.new(messages)
       }}
    end
  end

  @server_url "https://mcp.example.com/mcp"
  @resource_metadata "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"

  setup do
    {:ok, as} = FakeOAuthServer.start_link()
    {:ok, store} = OAuthMemoryStore.start_link()
    plug = &mcp_and_auth_server(&1, as)

    oauth = [
      store: {OAuthMemoryStore, pid: store},
      owner: "user-1",
      redirect_uri: "https://app.example.com/oauth/callback",
      client_name: "Test App",
      req_options: [plug: plug]
    ]

    server =
      Client.server(
        name: "widgets",
        url: @server_url,
        protocol_version: "2026-07-28",
        auth: {OAuth, oauth},
        req_options: [plug: plug]
      )

    %{as: as, oauth: oauth, server: server}
  end

  test "pauses for authorization and resumes the call", %{as: as, oauth: oauth, server: server} do
    # The definitions an app would have snapshotted for this conversation
    definitions = [
      %{
        "name" => "echo",
        "description" => "Echo a message back.",
        "inputSchema" => %{
          "type" => "object",
          "properties" => %{
            "input" => %{
              "type" => "object",
              "properties" => %{"message" => %{"type" => "string"}}
            }
          }
        }
      }
    ]

    opts = [
      model: %LLMDB.Model{provider: :openai, id: "integration-test"},
      tools: false,
      req_llm: FakeReqLLM,
      extra_tools: Client.req_llm_tools(server, definitions),
      tool_search: [defer: &String.starts_with?(&1.name, "mcp__")]
    ]

    # The provider's hosted search loads the tool, so the model can call it.
    Process.put(:responses, [call("c2", "mcp__widgets__echo", %{"input" => %{"message" => "hi"}})])

    events = ToolLoop.stream([Context.user("Say hi.")], opts) |> Enum.to_list()
    assert_receive {:request, request_opts}
    assert [echo, %{"type" => "tool_search"}] = request_opts[:tools]
    assert ReqLLM.Tool.provider_options(echo, :openai)[:defer_loading]

    assert {:done, paused} = List.last(events)
    assert paused.status == :paused
    assert [%{call: %{id: "c2"}, reason: {:authorization_required, _info}}] = paused.paused_calls

    # The app stores what the loop emitted, then sends the user to authorize.
    parts = Transcript.to_parts(for {:message, message} <- events, do: message)
    assert [%{"id" => "c2"}] = Transcript.pending_tool_calls(parts)

    assert {:ok, url, pending} = OAuth.authorize_url(@server_url, "user-1", oauth)
    code = FakeOAuthServer.approve(as, url)

    assert {:ok, _token, _pending} =
             OAuth.handle_callback(
               %{"code" => code, "state" => pending.state, "iss" => "https://auth.example.com"},
               "user-1",
               oauth
             )

    # Later, perhaps in another process, the loop resumes from storage.
    Process.put(:responses, [text("It said hi.")])
    messages = [Context.user("Say hi.") | Transcript.from_parts(parts)]
    assert {:ok, result} = ToolLoop.run(messages, opts)

    assert result.status == :complete
    assert result.final_text == "It said hi."
    assert %{content: [%{text: text}]} = Enum.find(result.messages, &(&1.tool_call_id == "c2"))
    assert text =~ "echo: hi"
  end

  defp mcp_and_auth_server(%{host: "mcp.example.com", request_path: "/mcp"} = conn, _as) do
    case get_req_header(conn, "authorization") do
      ["Bearer at-" <> _] ->
        {:ok, body, conn} = read_body(conn)
        conn = %{conn | path_info: [], body_params: Jason.decode!(body)}
        opts = AshAi.Mcp.Router.init(actions: [{Widget, :*}], mcp_resources: [])
        AshAi.Mcp.Router.call(conn, opts)

      _ ->
        conn
        |> put_resp_header(
          "www-authenticate",
          ~s(Bearer resource_metadata="#{@resource_metadata}")
        )
        |> send_resp(401, "")
    end
  end

  defp mcp_and_auth_server(conn, as), do: FakeOAuthServer.call(conn, as)

  defp call(id, name, args) do
    [
      StreamChunk.tool_call(name, args, %{id: id}),
      StreamChunk.meta(%{finish_reason: :tool_calls})
    ]
  end

  defp text(text), do: [StreamChunk.text(text), StreamChunk.meta(%{finish_reason: :stop})]
end
