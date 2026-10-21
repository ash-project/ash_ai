# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.DevTest do
  use ExUnit.Case, async: true
  import Plug.{Conn, Test}

  alias AshAi.Mcp.Dev

  defmodule Echo do
    @moduledoc false
    use Ash.Resource, domain: AshAi.Mcp.DevTest.ExtraDevTools

    actions do
      action :echo, :string do
        argument :text, :string, allow_nil?: false

        run fn input, _context ->
          {:ok, "echo: " <> input.arguments.text}
        end
      end
    end
  end

  defmodule ExtraDevTools do
    @moduledoc false
    use Ash.Domain, extensions: [AshAi], validate_config_inclusion?: false

    tools do
      tool :echo, AshAi.Mcp.DevTest.Echo, :echo do
        description "Echo the given text"
      end
    end

    resources do
      resource AshAi.Mcp.DevTest.Echo
    end
  end

  defmodule CollidingEcho do
    @moduledoc false
    use Ash.Resource, domain: AshAi.Mcp.DevTest.CollidingDevTools

    actions do
      action :echo, :string do
        run fn _input, _context -> {:ok, "echo"} end
      end
    end
  end

  defmodule CollidingDevTools do
    @moduledoc false
    use Ash.Domain, extensions: [AshAi], validate_config_inclusion?: false

    tools do
      tool :list_generators, AshAi.Mcp.DevTest.CollidingEcho, :echo
    end

    resources do
      resource AshAi.Mcp.DevTest.CollidingEcho
    end
  end

  defmodule PlainDomain do
    @moduledoc false
    use Ash.Domain, validate_config_inclusion?: false

    resources do
    end
  end

  @dev_tools ["get_usage_rules", "list_ash_resources", "list_generators"]

  describe "tools/list" do
    test "serves AshAi's dev tools when no dev_tool_domains are given" do
      opts = Dev.init(otp_app: :ash_ai)

      assert tool_names(opts) == @dev_tools
    end

    test "adds the tools of each dev_tool_domains entry" do
      opts = Dev.init(otp_app: :ash_ai, dev_tool_domains: [ExtraDevTools])

      assert tool_names(opts) == Enum.sort(["echo" | @dev_tools])
    end
  end

  describe "tools/call" do
    test "runs a tool from a dev_tool_domains entry" do
      opts = Dev.init(otp_app: :ash_ai, dev_tool_domains: [ExtraDevTools])

      body =
        opts
        |> rpc("tools/call", %{"name" => "echo", "arguments" => %{"input" => %{"text" => "hi"}}})
        |> Jason.decode!()

      assert %{"result" => %{"isError" => false, "content" => [%{"text" => text}]}} = body
      assert Jason.decode!(text) == "echo: hi"
    end

    test "a dev_tool_domains tool is not callable without the option" do
      opts = Dev.init(otp_app: :ash_ai)

      body =
        opts
        |> rpc("tools/call", %{"name" => "echo", "arguments" => %{"input" => %{"text" => "hi"}}})
        |> Jason.decode!()

      assert body["error"]["message"] == "Tool not found: echo"
    end
  end

  describe "init/1" do
    test "rejects a module that is not an Ash domain" do
      assert_raise ArgumentError, ~r/is not an Ash domain/, fn ->
        Dev.init(otp_app: :ash_ai, dev_tool_domains: [Enum])
      end
    end

    test "rejects a module that cannot be loaded" do
      assert_raise ArgumentError, ~r/is not a loaded module/, fn ->
        Dev.init(otp_app: :ash_ai, dev_tool_domains: [This.Module.Does.Not.Exist])
      end
    end

    test "rejects an Ash domain without the AshAi extension" do
      assert_raise ArgumentError, ~r/does not use the AshAi extension/, fn ->
        Dev.init(otp_app: :ash_ai, dev_tool_domains: [PlainDomain])
      end
    end

    test "rejects tool names that collide with another dev tool" do
      assert_raise ArgumentError, ~r/:list_generators/, fn ->
        Dev.init(otp_app: :ash_ai, dev_tool_domains: [CollidingDevTools])
      end
    end

    test "rejects a value that is not a list" do
      assert_raise ArgumentError, ~r/must be a list/, fn ->
        Dev.init(otp_app: :ash_ai, dev_tool_domains: ExtraDevTools)
      end
    end
  end

  defp tool_names(opts) do
    opts
    |> rpc("tools/list", %{})
    |> Jason.decode!()
    |> get_in(["result", "tools"])
    |> Enum.map(& &1["name"])
    |> Enum.sort()
  end

  defp rpc(opts, method, params) do
    session_id =
      conn(:post, "/ash_ai/mcp", %{
        "jsonrpc" => "2.0",
        "method" => "initialize",
        "id" => "init",
        "params" => %{"client" => %{"name" => "test_client", "version" => "1.0.0"}}
      })
      |> Dev.call(opts)
      |> get_resp_header("mcp-session-id")
      |> List.first()

    response =
      conn(:post, "/ash_ai/mcp", %{
        "jsonrpc" => "2.0",
        "method" => method,
        "id" => "1",
        "params" => params
      })
      |> put_req_header("mcp-session-id", session_id)
      |> Dev.call(opts)

    assert response.status == 200
    response.resp_body
  end
end
