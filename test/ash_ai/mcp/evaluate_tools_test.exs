# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.EvaluateToolsTest do
  use ExUnit.Case, async: true
  import Plug.{Conn, Test}

  alias AshAi.Mcp.Router

  defmodule Department do
    use Ash.Type.Enum,
      values: [billing: "Payments and refunds", technical: "Bugs and outages"]
  end

  defmodule FakeReqLLM do
    def evaluate(_model, _state, _questions, _opts) do
      {:ok,
       %{
         object: %{
           "department" => %{
             "type" => "choice",
             "choice" => "technical",
             "probabilities" => %{"billing" => 0.1, "technical" => 0.9},
             "confidence" => 0.85
           },
           "urgent" => %{"type" => "boolean", "probability" => 0.92},
           "frustration" => %{
             "type" => "score",
             "score" => 1.6,
             "legend" => %{"0" => "Calm", "1" => "Frustrated", "2" => "Angry"},
             "probabilities" => %{"0" => 0.05, "1" => 0.3, "2" => 0.65},
             "confidence" => 0.78
           }
         }
       }}
    end
  end

  defmodule Resource do
    use Ash.Resource,
      domain: AshAi.Mcp.EvaluateToolsTest.Domain,
      data_layer: Ash.DataLayer.Ets,
      extensions: [AshAi]

    ets do
      private? true
    end

    attributes do
      uuid_primary_key :id
    end

    actions do
      action :triage, AshAi.Evaluate.Judgments do
        description "Triage a support ticket."
        argument :ticket, :string, allow_nil?: false, description: "The customer's message."

        constraints fields: [
                      department: [
                        type: Department,
                        description: "Which team should handle `ticket`?"
                      ],
                      urgent: [type: :boolean, description: "Does `ticket` convey urgency?"],
                      frustration: [
                        type: AshAi.Evaluate.Score,
                        constraints: [levels: ["Calm", "Frustrated", "Angry"]],
                        description: "How frustrated is the customer?"
                      ]
                    ]

        run evaluate("typesafe:jev-latest", req_llm: FakeReqLLM)
      end
    end
  end

  defmodule Domain do
    use Ash.Domain, extensions: [AshAi]

    resources do
      resource Resource
    end

    tools do
      tool :triage, Resource, :triage
    end
  end

  @opts [actions: [{Resource, :*}], mcp_resources: []]

  test "an evaluate action works as an MCP tool with input schema and structured content" do
    session_id = initialize()

    tools = session_id |> request("tools/list", %{}) |> result() |> Map.fetch!("tools")
    tool = Enum.find(tools, &(&1["name"] == "triage"))

    assert tool["description"] == "Triage a support ticket."
    assert tool["inputSchema"]["properties"]["input"]["properties"]["ticket"]["type"] == "string"

    call_result =
      session_id
      |> request("tools/call", %{
        "name" => "triage",
        "arguments" => %{"input" => %{"ticket" => "API down!"}}
      })
      |> result()

    assert call_result["isError"] == false
    [%{"type" => "text", "text" => text}] = call_result["content"]
    assert call_result["structuredContent"] == Jason.decode!(text)

    structured = call_result["structuredContent"]
    assert structured["department"]["value"] == "technical"
    assert structured["department"]["probabilities"] == %{"billing" => 0.1, "technical" => 0.9}
    assert structured["department"]["confidence"] == 0.85
    assert structured["urgent"] == %{"probability" => 0.92}
    assert structured["frustration"]["level"] == "Angry"
    assert structured["frustration"]["value"] == 1.6
    assert structured["frustration"]["probabilities"] == %{"0" => 0.05, "1" => 0.3, "2" => 0.65}
  end

  defp initialize do
    conn(:post, "/", %{
      "jsonrpc" => "2.0",
      "id" => "init",
      "method" => "initialize",
      "params" => %{"protocolVersion" => "2025-06-18", "capabilities" => %{}}
    })
    |> Router.call(@opts)
    |> get_resp_header("mcp-session-id")
    |> List.first()
  end

  defp request(session_id, method, params) do
    conn(:post, "/", %{"jsonrpc" => "2.0", "id" => method, "method" => method, "params" => params})
    |> put_req_header("mcp-session-id", session_id)
    |> Router.call(@opts)
  end

  defp result(conn) do
    conn.resp_body |> Jason.decode!() |> Map.fetch!("result")
  end
end
