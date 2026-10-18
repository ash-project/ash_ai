# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Test.TinyHTTP do
  @moduledoc false
  # A bare HTTP/1.1 server on 127.0.0.1, for tests that need a real socket
  # rather than Req's `plug:`. `handler` gets each connection's socket and its
  # request body, writes the response, and the connection is closed after.

  def start(handler) do
    {:ok, listen} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, port} = :inet.port(listen)
    pid = spawn_link(fn -> accept(listen, handler) end)
    :ok = :gen_tcp.controlling_process(listen, pid)
    port
  end

  def respond(socket, status, headers, body) do
    head =
      Enum.map_join(
        [{"content-length", Integer.to_string(byte_size(body))}, {"connection", "close"}] ++
          headers,
        fn {name, value} -> "#{name}: #{value}\r\n" end
      )

    :gen_tcp.send(socket, "HTTP/1.1 #{status} OK\r\n#{head}\r\n#{body}")
  end

  defp accept(listen, handler) do
    case :gen_tcp.accept(listen) do
      {:ok, socket} ->
        with {:ok, body} <- read_request(socket, ""), do: handler.(socket, body)
        :gen_tcp.close(socket)
        accept(listen, handler)

      {:error, _closed} ->
        :ok
    end
  end

  defp read_request(socket, acc) do
    case :binary.split(acc, "\r\n\r\n") do
      [head, body] ->
        read_body(socket, body, content_length(head))

      [_partial] ->
        with {:ok, data} <- :gen_tcp.recv(socket, 0, 5_000), do: read_request(socket, acc <> data)
    end
  end

  defp read_body(_socket, body, length) when byte_size(body) >= length, do: {:ok, body}

  defp read_body(socket, body, length) do
    with {:ok, data} <- :gen_tcp.recv(socket, 0, 5_000),
         do: read_body(socket, body <> data, length)
  end

  defp content_length(head) do
    case Regex.run(~r/^content-length:\s*(\d+)/im, head) do
      [_, length] -> String.to_integer(length)
      nil -> 0
    end
  end
end
