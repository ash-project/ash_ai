# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

if Code.ensure_loaded?(Req) do
  defmodule AshAi.Mcp.OAuth.HTTP do
    @moduledoc false

    alias AshAi.Mcp.NetworkPolicy

    # Metadata documents and token responses are small. Anything larger is cut
    # off instead of buffered, as are requests that run past the timeouts.
    @max_response_bytes 262_144
    @connect_timeout 5_000
    @request_timeout 10_000

    # Fetches a JSON object. Anything but a 200 with a JSON object body is an error.
    def get_json(url, opts) do
      case request(url, opts, method: :get, headers: [{"accept", "application/json"}]) do
        {:ok, %Req.Response{status: 200} = response} ->
          case decode(response.body) do
            %{} = body -> {:ok, body}
            _ -> {:error, {:invalid_json, url}}
          end

        {:ok, %Req.Response{status: status}} ->
          {:error, {:http_status, status, url}}

        {:error, reason} ->
          {:error, reason}
      end
    end

    # POSTs and returns `{:ok, status, decoded_body, response}` for any status.
    def post(url, body_opts, headers, opts) do
      case request(
             url,
             opts,
             [method: :post, headers: [{"accept", "application/json"} | headers]] ++ body_opts
           ) do
        {:ok, %Req.Response{} = response} ->
          {:ok, response.status, decode(response.body), response}

        {:error, reason} ->
          {:error, reason}
      end
    end

    # URLs the application chose (the redirect URI, the MCP server) must be
    # HTTPS. Plain HTTP is allowed only for loopback hosts, for local development.
    def secure_url?(url) when is_binary(url) do
      case URI.parse(url) do
        %URI{scheme: "https", host: host} when is_binary(host) and host != "" -> true
        %URI{scheme: "http", host: host} -> NetworkPolicy.loopback_host?(host)
        _ -> false
      end
    end

    def secure_url?(_url), do: false

    # URLs a server supplied (resource metadata, authorization servers, their
    # endpoints) must be HTTPS, without userinfo or a fragment. Plain HTTP is
    # allowed only for loopback hosts listed in `:allowed_private_hosts`, for
    # local development. `AshAi.Mcp.NetworkPolicy` decides where they connect.
    def fetchable_url?(url, opts) when is_binary(url) do
      case URI.parse(url) do
        %URI{scheme: scheme, host: host, userinfo: nil, fragment: nil}
        when scheme in ["http", "https"] and is_binary(host) and host != "" ->
          scheme == "https" or
            (NetworkPolicy.loopback_host?(host) and
               NetworkPolicy.allowed_host?(host, opts[:allowed_private_hosts]))

        _ ->
          false
      end
    end

    def fetchable_url?(_url, _opts), do: false

    # The OAuth error fields of an error response. The rest of the body is
    # dropped so it can't reach an error the application might show, since the
    # endpoint may not be what the server claimed it was. The fields themselves
    # are cut short and stripped of control characters, since errors get logged
    # and a server can put anything in them, including secrets it was sent.
    def error_fields(status, %{} = body) do
      %{
        status: status,
        error: remote_text(body["error"], 64),
        error_description: remote_text(body["error_description"], 256)
      }
    end

    def error_fields(status, _body), do: %{status: status, error: nil, error_description: nil}

    defp remote_text(value, limit) when is_binary(value) do
      if String.valid?(value),
        do: value |> String.replace(~r/[[:cntrl:]]/u, " ") |> String.slice(0, limit),
        else: nil
    end

    defp remote_text(_value, _limit), do: nil

    defp request(url, opts, request_opts) do
      req_options = Keyword.get(opts, :req_options, [])

      # Req refuses `connect_options` alongside an application's own `finch:` pool
      connect_options =
        if Keyword.has_key?(req_options, :finch),
          do: [],
          else: [connect_options: [timeout: @connect_timeout]]

      result =
        [
          url: url,
          retry: false,
          redirect: false,
          decode_body: false,
          receive_timeout: @request_timeout,
          request_timeout: @request_timeout,
          into: &collect/2
        ]
        |> Keyword.merge(connect_options)
        |> Keyword.merge(req_options)
        |> NetworkPolicy.req_options(url, opts[:allowed_private_hosts])
        |> Req.new()
        |> Req.request(request_opts)

      case result do
        {:ok, %Req.Response{} = response} ->
          if Req.Response.get_private(response, :too_large),
            do: {:error, {:response_too_large, url}},
            else: {:ok, response}

        {:error, %{reason: :non_public_address}} ->
          {:error, {:non_public_address, url}}

        {:error, reason} ->
          {:error, {:http_error, reason, url}}
      end
    end

    defp collect({:data, data}, {request, response}) do
      body = response.body <> data

      if byte_size(body) > @max_response_bytes do
        {:halt, {request, Req.Response.put_private(%{response | body: ""}, :too_large, true)}}
      else
        {:cont, {request, %{response | body: body}}}
      end
    end

    defp decode(body) when is_binary(body) do
      case Jason.decode(body) do
        {:ok, decoded} -> decoded
        {:error, _} -> body
      end
    end

    defp decode(body), do: body
  end
end
