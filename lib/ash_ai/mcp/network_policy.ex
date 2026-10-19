# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.NetworkPolicy do
  @moduledoc false
  # Keeps requests to MCP servers and the authorization servers they name on
  # public addresses, so a URL that a user or a server supplies can't reach
  # the services around the application, such as cloud metadata endpoints,
  # databases, or admin APIs.
  #
  # The check runs inside `gen_tcp` through a `tcp_module`: the addresses it
  # approves are the ones the connection is made to, so DNS can't answer one
  # way for the check and another for the connection.
  #
  # Hosts in `allowed_private_hosts` skip the check, and `:all` turns it off.
  # So do requests that open no network connection (a `plug:` or a
  # `unix_socket:`). A proxy, a named `finch:` pool, or a custom `adapter:`
  # would take the connection out of the check's reach, so they need `:all`
  # rather than leaving the check off without saying so.

  import Bitwise

  @type allowed_private_hosts :: [String.t()] | :all | nil

  @doc """
  Adds the policy to `req_options` for a request to `url`.

  Raises when `req_options` connect where the policy can't be applied and
  `allowed_private_hosts` isn't `:all`.
  """
  @spec req_options(keyword(), String.t(), allowed_private_hosts()) :: keyword()
  def req_options(req_options, _url, :all), do: req_options

  def req_options(req_options, url, allowed_private_hosts) do
    finch = Keyword.get(req_options, :finch)

    cond do
      Keyword.has_key?(req_options, :plug) or Keyword.has_key?(req_options, :unix_socket) ->
        req_options

      allowed_host?(URI.parse(url).host, allowed_private_hosts) ->
        req_options

      Keyword.has_key?(req_options, :adapter) or (finch != nil and not is_list(finch)) or
          Keyword.has_key?(Keyword.get(req_options, :connect_options, []), :proxy) ->
        raise ArgumentError, """
        AshAi can't check the addresses that requests through a proxy, a named Finch \
        pool, or a custom adapter connect to, so it won't make them silently \
        unchecked. Pass `allowed_private_hosts: :all` to make them without the \
        check, for example when the proxy enforces it.
        """

      # Finch pool options, which take the connection options themselves
      is_list(finch) ->
        Keyword.put(req_options, :finch, put_tcp_module(finch, :conn_opts))

      true ->
        put_tcp_module(req_options, :connect_options)
    end
  end

  defp put_tcp_module(options, key) do
    nested = Keyword.get(options, key, [])

    transport_opts =
      nested
      |> Keyword.get(:transport_opts, [])
      |> Keyword.put(:tcp_module, __MODULE__.TCP)

    Keyword.put(options, key, Keyword.put(nested, :transport_opts, transport_opts))
  end

  @doc "Whether `host`, a URL's host, may resolve to a private address."
  @spec allowed_host?(String.t() | nil, allowed_private_hosts()) :: boolean()
  def allowed_host?(_host, :all), do: true
  def allowed_host?(nil, _allowed_private_hosts), do: false

  def allowed_host?(host, allowed_private_hosts) do
    normalize_host(host) in Enum.map(allowed_private_hosts || [], &normalize_host/1)
  end

  @doc "Whether `host` names the local machine."
  @spec loopback_host?(String.t() | nil) :: boolean()
  def loopback_host?(nil), do: false

  def loopback_host?(host),
    do: normalize_host(host) in ["localhost", "127.0.0.1", "::1"]

  @doc """
  Whether `address` is publicly routable: not loopback, private, link-local,
  shared (CGNAT), multicast, documentation, benchmarking, or otherwise
  reserved in the IANA special-purpose registries.
  """
  @spec public_address?(:inet.ip_address()) :: boolean()
  def public_address?({a, b, c, d} = address)
      when a in 0..255 and b in 0..255 and c in 0..255 and d in 0..255,
      do: not reserved_ipv4?(address)

  # IPv4-mapped addresses are judged by the IPv4 address they carry
  def public_address?({0, 0, 0, 0, 0, 0xFFFF, high, low})
      when high in 0..0xFFFF and low in 0..0xFFFF,
      do: public_address?({high >>> 8, high &&& 0xFF, low >>> 8, low &&& 0xFF})

  # Only global unicast (2000::/3) is public. 6to4 and Teredo can tunnel to
  # private IPv4 addresses, so they're refused with the documentation ranges.
  def public_address?({a, b, _c, _d, _e, _f, _g, _h} = address)
      when a in 0..0xFFFF and b in 0..0xFFFF do
    (a &&& 0xE000) == 0x2000 and not reserved_ipv6?(address)
  end

  def public_address?(_address), do: false

  defp reserved_ipv4?({a, _, _, _}) when a in [0, 10, 127] or a >= 224, do: true
  defp reserved_ipv4?({100, b, _, _}) when b in 64..127, do: true
  defp reserved_ipv4?({169, 254, _, _}), do: true
  defp reserved_ipv4?({172, b, _, _}) when b in 16..31, do: true
  defp reserved_ipv4?({192, 0, c, _}) when c in [0, 2], do: true
  defp reserved_ipv4?({192, 88, 99, _}), do: true
  defp reserved_ipv4?({192, 168, _, _}), do: true
  defp reserved_ipv4?({198, b, _, _}) when b in 18..19, do: true
  defp reserved_ipv4?({198, 51, 100, _}), do: true
  defp reserved_ipv4?({203, 0, 113, _}), do: true
  defp reserved_ipv4?(_address), do: false

  defp reserved_ipv6?({0x2001, b, _, _, _, _, _, _}) when b in [0, 2, 0x0DB8], do: true
  defp reserved_ipv6?({0x2001, b, _, _, _, _, _, _}) when b in 0x0010..0x002F, do: true
  defp reserved_ipv6?({0x2002, _, _, _, _, _, _, _}), do: true
  defp reserved_ipv6?({0x3FFF, b, _, _, _, _, _, _}) when b <= 0x0FFF, do: true
  defp reserved_ipv6?(_address), do: false

  defp normalize_host(host) do
    host
    |> String.downcase()
    |> String.trim_trailing(".")
    |> String.trim_leading("[")
    |> String.trim_trailing("]")
  end

  defmodule TCP do
    @moduledoc false
    # The `tcp_module` that enforces the policy. `gen_tcp` resolves the host
    # with `getaddrs/2` and connects to each address it returns with
    # `connect/4`. The `socket` inet backend calls `getaddrs/2` too, then
    # refuses this module (it only knows OTP's own), so it fails closed.

    alias AshAi.Mcp.NetworkPolicy

    def getaddrs(address, timer) do
      with {:ok, addresses} <- resolve(address, timer) do
        # Every address must be public, so an answer can't slip a private
        # address in among public ones
        if Enum.all?(addresses, &NetworkPolicy.public_address?/1),
          do: {:ok, addresses},
          else: {:error, :non_public_address}
      end
    end

    def getserv(port), do: :inet_tcp.getserv(port)

    # `{:error, :einval}` would make `gen_tcp` exit, so a refusal has its own reason
    def connect(address, port, opts, timeout) do
      if NetworkPolicy.public_address?(address),
        do: family_module(address).connect(address, port, opts, timeout),
        else: {:error, :non_public_address}
    end

    # IPv4 first, as `gen_tcp` does by default, then IPv6
    defp resolve(address, timer) do
      case :inet_tcp.getaddrs(address, timer) do
        {:ok, [_ | _]} = ok -> ok
        _ -> :inet6_tcp.getaddrs(address, timer)
      end
    end

    defp family_module(address) when tuple_size(address) == 8, do: :inet6_tcp
    defp family_module(_address), do: :inet_tcp
  end
end
