# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.NetworkPolicyTest do
  use ExUnit.Case, async: true

  alias AshAi.Mcp.{Client, NetworkPolicy}
  alias AshAi.Mcp.OAuth.Discovery
  alias AshAi.Test.TinyHTTP

  describe "public_address?/1" do
    test "refuses loopback, private, link-local, shared, and reserved IPv4" do
      for address <- [
            {127, 0, 0, 1},
            {10, 1, 2, 3},
            {172, 16, 0, 1},
            {172, 31, 255, 255},
            {192, 168, 1, 1},
            {169, 254, 169, 254},
            {100, 64, 0, 1},
            {0, 0, 0, 0},
            {192, 0, 0, 8},
            {192, 0, 2, 1},
            {198, 18, 0, 1},
            {198, 51, 100, 1},
            {203, 0, 113, 1},
            {224, 0, 0, 1},
            {255, 255, 255, 255}
          ] do
        refute NetworkPolicy.public_address?(address), inspect(address)
      end
    end

    test "allows public IPv4" do
      for address <- [{8, 8, 8, 8}, {1, 1, 1, 1}, {172, 32, 0, 1}, {192, 0, 1, 1}] do
        assert NetworkPolicy.public_address?(address), inspect(address)
      end
    end

    test "allows only global unicast IPv6, judging mapped IPv4 by its IPv4 address" do
      assert NetworkPolicy.public_address?({0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111})
      assert NetworkPolicy.public_address?({0, 0, 0, 0, 0, 0xFFFF, 0x0808, 0x0808})

      for address <- [
            {0, 0, 0, 0, 0, 0, 0, 1},
            {0, 0, 0, 0, 0, 0, 0, 0},
            {0xFE80, 0, 0, 0, 0, 0, 0, 1},
            {0xFC00, 0, 0, 0, 0, 0, 0, 1},
            {0, 0, 0, 0, 0, 0xFFFF, 0xA9FE, 0xA9FE},
            {0x2001, 0x0DB8, 0, 0, 0, 0, 0, 1},
            {0x2002, 0x0A00, 0x0001, 0, 0, 0, 0, 1},
            {0x2001, 0, 0, 0, 0, 0, 0, 1},
            {0x0064, 0xFF9B, 0, 0, 0, 0, 0x0A00, 0x0001}
          ] do
        refute NetworkPolicy.public_address?(address), inspect(address)
      end
    end
  end

  describe "req_options/3" do
    test "adds the policy unless the host is allowed or the request opens no connection" do
      enforced = NetworkPolicy.req_options([], "https://mcp.example.com/mcp", [])
      assert enforced[:connect_options][:transport_opts][:tcp_module] == NetworkPolicy.TCP

      # Existing connect options are kept
      enforced =
        NetworkPolicy.req_options(
          [connect_options: [timeout: 1, transport_opts: [verify: :verify_peer]]],
          "https://mcp.example.com",
          []
        )

      assert enforced[:connect_options][:timeout] == 1
      assert enforced[:connect_options][:transport_opts][:verify] == :verify_peer

      for {options, allowed} <- [
            {[], ["MCP.example.com."]},
            {[plug: fn conn -> conn end], []},
            {[finch: MyFinch], :all}
          ] do
        assert NetworkPolicy.req_options(options, "https://mcp.example.com/mcp", allowed) ==
                 options
      end
    end

    test "applies the policy through Finch pool options" do
      enforced =
        NetworkPolicy.req_options(
          [finch: [conn_max_idle_time: 1_000]],
          "https://mcp.example.com/mcp",
          []
        )

      assert enforced[:finch][:conn_max_idle_time] == 1_000
      assert enforced[:finch][:conn_opts][:transport_opts][:tcp_module] == NetworkPolicy.TCP
      refute Keyword.has_key?(enforced, :connect_options)
    end

    test "refuses to leave requests unchecked without allowed_private_hosts: :all" do
      for options <- [
            [finch: MyFinch],
            [adapter: fn request -> {request, %Req.Response{}} end],
            [connect_options: [proxy: {:http, "proxy", 3128, []}]]
          ] do
        assert_raise ArgumentError, ~r/allowed_private_hosts: :all/, fn ->
          NetworkPolicy.req_options(options, "https://mcp.example.com/mcp", [])
        end
      end
    end
  end

  describe "connections" do
    test "the client refuses loopback hosts, before connecting" do
      for url <- ["http://127.0.0.1:1/mcp", "http://localhost:1/mcp", "http://[::1]:1/mcp"] do
        assert {:error, {:non_public_address, ^url}} = Client.connect(name: "local", url: url)
      end
    end

    test "the client connects to allowed private hosts" do
      port =
        TinyHTTP.start(fn socket, body ->
          %{"id" => id} = Jason.decode!(body)
          result = %{"jsonrpc" => "2.0", "id" => id, "result" => %{"capabilities" => %{}}}

          TinyHTTP.respond(
            socket,
            200,
            [{"content-type", "application/json"}],
            Jason.encode!(result)
          )
        end)

      assert {:ok, %{era: :modern}} =
               Client.connect(
                 name: "local",
                 url: "http://127.0.0.1:#{port}/mcp",
                 allowed_private_hosts: ["127.0.0.1"]
               )
    end

    test "the client gives up on a response that outlasts request_timeout" do
      port =
        TinyHTTP.start(fn socket, _body ->
          :gen_tcp.send(
            socket,
            "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\n"
          )

          # Keepalive comments forever, so no single read times out
          Stream.repeatedly(fn -> :gen_tcp.send(socket, ": keepalive\n\n") end)
          |> Stream.each(fn _ -> Process.sleep(20) end)
          |> Enum.find(&match?({:error, _}, &1))
        end)

      started = System.monotonic_time(:millisecond)

      assert {:error, _} =
               Client.connect(
                 name: "local",
                 url: "http://127.0.0.1:#{port}/mcp",
                 allowed_private_hosts: ["127.0.0.1"],
                 request_timeout: 200
               )

      assert System.monotonic_time(:millisecond) - started < 2_000
    end

    test "OAuth discovery refuses loopback hosts" do
      assert {:error, {:protected_resource_metadata_not_found, _, errors}} =
               Discovery.discover("http://127.0.0.1:1/mcp", [])

      assert Enum.all?(errors, &match?({:non_public_address, _}, &1))
    end
  end
end
