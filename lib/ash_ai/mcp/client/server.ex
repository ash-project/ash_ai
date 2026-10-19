# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.Client.Server do
  @moduledoc """
  Configuration for an MCP server reached over Streamable HTTP.

  Build one with `new/1` (or `AshAi.Mcp.Client.server/1`) and pass it to
  `AshAi.Mcp.Client.connect/1`. The struct holds no connection state, so it is
  safe to build from stored configuration in each job or request.
  """

  @schema [
    name: [
      type: {:custom, __MODULE__, :validate_name, []},
      required: true,
      doc: """
      A name for the server, unique among the servers a conversation uses: up
      to 32 letters and digits in runs joined by single `-` or `_`. It
      prefixes the server's tool names (`mcp__<name>__<tool>`), so changing it
      changes every tool name. The format keeps one server's tool names from
      colliding with another's.
      """
    ],
    url: [
      type: :string,
      required: true,
      doc: "The server's MCP endpoint, e.g. `https://example.com/mcp`."
    ],
    allowed_private_hosts: [
      type: {:or, [{:list, :string}, {:literal, :all}]},
      default: [],
      doc: """
      Hosts that may resolve to loopback, private, or other non-public
      addresses, such as `["localhost"]` in development or an internal MCP
      server's hostname. The client connects to any other host only at public
      addresses, so a URL a user supplies can't reach services on your network.
      `:all` turns the check off. A proxy, a named `finch:` pool, or a custom
      `adapter:` in `req_options` takes the connection out of the check's
      reach, so they require `:all`, for example with an egress proxy that
      enforces it.
      """
    ],
    request_timeout: [
      type: :pos_integer,
      default: 60_000,
      doc: "Milliseconds a request may take in all, including a streamed response."
    ],
    max_response_size: [
      type: :pos_integer,
      default: 8_388_608,
      doc: "The most bytes a response may carry, including a streamed one."
    ],
    auth: [
      type: {:or, [{:tuple, [:atom, :keyword_list]}, {:literal, nil}]},
      default: nil,
      doc: """
      `{module, opts}`, where `module` implements `AshAi.Mcp.Client.Auth`, such as
      `{AshAi.Mcp.OAuth, store: MyApp.McpTokens, owner: user.id}`.
      """
    ],
    headers: [
      type: {:or, [{:list, {:tuple, [:string, :string]}}, {:fun, 0}]},
      default: [],
      doc: """
      Static headers sent with every request, such as an API key. A zero-arity
      function is called before each request.
      """
    ],
    req_options: [
      type: :keyword_list,
      default: [],
      doc: "Options merged into `Req.new/1`, e.g. `plug:` in tests or `receive_timeout:`."
    ],
    client_info: [
      type: {:map, :string, :any},
      doc: """
      The `Implementation` sent as `clientInfo`. Defaults to
      `%{"name" => "ash_ai", "version" => <AshAi's version>}`.
      """
    ],
    capabilities: [
      type: {:map, :string, :any},
      default: %{},
      doc: "The client capabilities to declare. The client implements none beyond the core."
    ],
    protocol_version: [
      type: {:or, [:string, {:literal, nil}]},
      default: nil,
      doc: """
      Skip version detection and use this protocol version. Set it from a
      previously negotiated `AshAi.Mcp.Client.Connection.protocol_version` to save
      the probe request.
      """
    ]
  ]

  # Headers, auth options, and Req options can all carry credentials
  @derive {Inspect, only: [:name, :url, :protocol_version]}
  defstruct Keyword.keys(@schema)

  @type t :: %__MODULE__{
          name: String.t(),
          url: String.t(),
          allowed_private_hosts: [String.t()] | :all,
          request_timeout: pos_integer(),
          max_response_size: pos_integer(),
          auth: {module(), keyword()} | nil,
          headers: [{String.t(), String.t()}] | (-> [{String.t(), String.t()}]),
          req_options: keyword(),
          client_info: map() | nil,
          capabilities: map(),
          protocol_version: String.t() | nil
        }

  @doc """
  Builds a server configuration.

  ## Options

  #{Spark.Options.docs(@schema)}
  """
  @spec new(keyword()) :: t()
  def new(opts) do
    opts = Spark.Options.validate!(opts, @schema)
    server = struct!(__MODULE__, opts)
    validate_url!(server)

    # Raises now, instead of on the first request, when `req_options` take
    # requests out of the address check without `allowed_private_hosts: :all`
    AshAi.Mcp.NetworkPolicy.req_options(
      server.req_options,
      server.url,
      server.allowed_private_hosts
    )

    server
  end

  # An absolute HTTP(S) URL without credentials, which `inspect/1` and logs
  # would show, or a fragment. Plain HTTP carries headers and tool arguments in
  # the clear, so it's for local hosts and allowed private ones only.
  defp validate_url!(%__MODULE__{url: url, allowed_private_hosts: allowed}) do
    case URI.new(url) do
      {:ok, %URI{scheme: scheme, host: host, userinfo: nil, fragment: nil}}
      when scheme in ["http", "https"] and is_binary(host) and host != "" ->
        if scheme == "http" and not AshAi.Mcp.NetworkPolicy.loopback_host?(host) and
             not AshAi.Mcp.NetworkPolicy.allowed_host?(host, allowed) do
          raise ArgumentError,
                "MCP server URLs must use HTTPS, except for localhost and hosts in " <>
                  "`allowed_private_hosts`, got: #{inspect(url)}"
        end

      _ ->
        raise ArgumentError,
              "expected an absolute http or https URL without credentials or a fragment, got: #{inspect(url)}"
    end
  end

  # With no `__` and no leading or trailing `_`, the name ends at the first
  # `__` after `mcp__`, so different servers' tool names can't coincide. At
  # 32 characters the prefix also survives `AshAi.Mcp.Client.tool_name/2`
  # shortening a long name.
  @doc false
  def validate_name(name) when is_binary(name) do
    if byte_size(name) <= 32 and String.match?(name, ~r/\A[A-Za-z0-9]+(?:[-_][A-Za-z0-9]+)*\z/) do
      {:ok, name}
    else
      {:error,
       "expected up to 32 letters and digits in runs joined by single `-` or `_`, got: #{inspect(name)}"}
    end
  end

  def validate_name(name), do: {:error, "expected a string, got: #{inspect(name)}"}
end
