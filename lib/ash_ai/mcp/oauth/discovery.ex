# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

if Code.ensure_loaded?(Req) do
  defmodule AshAi.Mcp.OAuth.Discovery do
    @moduledoc """
    Finds an MCP server's authorization server.

    Implements the discovery steps of the MCP authorization spec (2026-07-28):
    the `WWW-Authenticate` challenge, OAuth 2.0 Protected Resource Metadata
    (RFC 9728), and authorization server metadata through RFC 8414 or OpenID
    Connect Discovery.
    """

    alias AshAi.Mcp.OAuth.HTTP

    @token "[!#$%&'*+\\-.^_`|~0-9A-Za-z]+"
    @scheme_re Regex.compile!("\\A(#{@token})")
    @param_re Regex.compile!(
                "\\A(#{@token})[ \\t]*=[ \\t]*(\"(?:[^\"\\\\]|\\\\.)*\"|#{@token})",
                "s"
              )
    @token68_re ~r/\A([A-Za-z0-9\-._~+\/]+=*)[ \t]*(?=,|\z)/

    @typedoc "The parameters of a `Bearer` challenge."
    @type challenge :: %{
            resource_metadata: String.t() | nil,
            scope: String.t() | nil,
            error: String.t() | nil,
            error_description: String.t() | nil,
            params: %{String.t() => String.t()},
            www_authenticate: String.t()
          }

    @typedoc "What `discover/2` found."
    @type t :: %{
            server: String.t(),
            resource: String.t(),
            issuer: String.t(),
            protected_resource: map(),
            authorization_server: map(),
            challenge: challenge() | nil
          }

    @doc """
    Parses the `Bearer` challenge out of a `WWW-Authenticate` header.

    Accepts one header value or a list of them, and returns `nil` when there is
    no `Bearer` challenge.
    """
    @spec parse_www_authenticate(String.t() | [String.t()] | nil) :: challenge() | nil
    def parse_www_authenticate(nil), do: nil
    def parse_www_authenticate([]), do: nil

    def parse_www_authenticate(values) when is_list(values),
      do: parse_www_authenticate(Enum.join(values, ", "))

    def parse_www_authenticate(header) when is_binary(header) do
      header
      |> challenges([])
      |> Enum.find(&(&1.scheme == "bearer"))
      |> case do
        nil ->
          nil

        %{params: params} ->
          %{
            resource_metadata: params["resource_metadata"],
            scope: params["scope"],
            error: params["error"],
            error_description: params["error_description"],
            params: params,
            www_authenticate: header
          }
      end
    end

    @doc """
    The canonical resource URI of an MCP server (RFC 8707), used as the
    `resource` parameter and as the key tokens are stored under.

    Lowercases the scheme and host, drops the fragment and a default port, and
    drops a bare trailing slash.
    """
    @spec canonical_resource(String.t()) :: {:ok, String.t()} | {:error, term()}
    def canonical_resource(url) when is_binary(url) do
      case URI.parse(url) do
        %URI{scheme: scheme, host: host} = uri
        when is_binary(scheme) and is_binary(host) and host != "" ->
          scheme = String.downcase(scheme)

          if scheme in ["http", "https"] do
            port = if uri.port == URI.default_port(scheme), do: nil, else: uri.port
            path = if uri.path in [nil, "", "/"], do: nil, else: uri.path

            {:ok,
             URI.to_string(%URI{
               scheme: scheme,
               host: String.downcase(host),
               port: port,
               path: path,
               query: uri.query
             })}
          else
            {:error, {:invalid_resource, url}}
          end

        _ ->
          {:error, {:invalid_resource, url}}
      end
    end

    def canonical_resource(url), do: {:error, {:invalid_resource, url}}

    @doc """
    Discovers the authorization server for the MCP server at `server_url`.

    Uses the `resource_metadata` URL from `:challenge` (a `WWW-Authenticate`
    header value or a parsed challenge) when present, and otherwise the
    well-known URIs: with path insertion first, then at the root. If neither
    exists and no challenge was given, it sends one unauthenticated request to
    the server to obtain a challenge.

    Uses the first authorization server the metadata lists.
    """
    @spec discover(String.t(), keyword()) :: {:ok, t()} | {:error, term()}
    def discover(server_url, opts \\ []) do
      with {:ok, server} <- canonical_resource(server_url),
           {:ok, prm, metadata_url, challenge} <-
             protected_resource_metadata(server_url, challenge(opts[:challenge]), opts),
           {:ok, resource} <- protected_resource(prm, server, metadata_url),
           {:ok, issuer} <- select_authorization_server(prm),
           {:ok, metadata} <- authorization_server_metadata(issuer, opts) do
        {:ok,
         %{
           server: server,
           resource: resource,
           issuer: issuer,
           protected_resource: prm,
           authorization_server: metadata,
           challenge: challenge
         }}
      end
    end

    @doc """
    Fetches and validates the authorization server metadata for `issuer`.

    Tries the endpoints the spec lists, in order, and requires the document's
    `issuer` to be identical to `issuer`, HTTPS endpoints, and PKCE `S256`
    support.
    """
    @spec authorization_server_metadata(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
    def authorization_server_metadata(issuer, opts \\ []) do
      if HTTP.fetchable_url?(issuer, opts) do
        issuer
        |> authorization_server_metadata_urls()
        |> first_json(opts)
        |> case do
          {:ok, metadata, _url} -> validate_authorization_server(metadata, issuer, opts)
          {:error, errors} -> {:error, {:authorization_server_metadata_not_found, issuer, errors}}
        end
      else
        {:error, {:insecure_url, issuer}}
      end
    end

    @doc """
    The URLs to try for an issuer's metadata, in the spec's priority order.
    """
    @spec authorization_server_metadata_urls(String.t()) :: [String.t()]
    def authorization_server_metadata_urls(issuer) do
      uri = URI.parse(issuer)
      base = origin(uri)

      case String.trim_trailing(uri.path || "", "/") do
        "" ->
          [
            base <> "/.well-known/oauth-authorization-server",
            base <> "/.well-known/openid-configuration"
          ]

        path ->
          [
            base <> "/.well-known/oauth-authorization-server" <> path,
            base <> "/.well-known/openid-configuration" <> path,
            base <> path <> "/.well-known/openid-configuration"
          ]
      end
    end

    @doc """
    The well-known protected resource metadata URLs for an MCP server, in the
    spec's priority order.
    """
    @spec protected_resource_metadata_urls(String.t()) :: [String.t()]
    def protected_resource_metadata_urls(server_url) do
      uri = URI.parse(server_url)
      root = root_metadata_url(uri)

      # RFC 9728 section 3.1: the well-known path goes before the server's own
      # path and query
      suffix =
        String.trim_trailing(uri.path || "", "/") <> if(uri.query, do: "?" <> uri.query, else: "")

      case suffix do
        "" -> [root]
        suffix -> [root <> suffix, root]
      end
    end

    defp protected_resource_metadata(_server_url, %{resource_metadata: url} = challenge, opts)
         when is_binary(url) do
      with :ok <- fetchable(url, opts),
           {:ok, prm} <- HTTP.get_json(url, opts) do
        {:ok, prm, url, challenge}
      end
    end

    defp protected_resource_metadata(server_url, challenge, opts) do
      case first_json(protected_resource_metadata_urls(server_url), opts) do
        {:ok, prm, url} ->
          {:ok, prm, url, challenge}

        {:error, errors} when is_nil(challenge) ->
          case probe(server_url, opts) do
            %{resource_metadata: url} = challenge when is_binary(url) ->
              protected_resource_metadata(server_url, challenge, opts)

            _ ->
              {:error, {:protected_resource_metadata_not_found, server_url, errors}}
          end

        {:error, errors} ->
          {:error, {:protected_resource_metadata_not_found, server_url, errors}}
      end
    end

    # The MCP flow starts with an unauthenticated request that the server
    # answers with a 401 challenge. Only used when the well-known URIs fail.
    defp probe(server_url, opts) do
      body = %{"jsonrpc" => "2.0", "id" => 1, "method" => "ping"}

      case HTTP.post(
             server_url,
             [json: body],
             [{"accept", "application/json, text/event-stream"}],
             opts
           ) do
        {:ok, 401, _body, response} ->
          response
          |> Req.Response.get_header("www-authenticate")
          |> parse_www_authenticate()

        _ ->
          nil
      end
    end

    # RFC 9728 section 3.3: the metadata's `resource` must be the resource it
    # was fetched for, the server itself, query included. The one exception is
    # the metadata at the origin's root well-known URI, which describes the
    # origin. Anything looser would let a server on a shared host claim a
    # resource it doesn't serve and receive tokens meant for it. The metadata's
    # value is used as the `resource` parameter.
    defp protected_resource(%{"authorization_servers" => [_ | _]} = prm, server, metadata_url) do
      case prm["resource"] do
        nil ->
          {:ok, server}

        resource when is_binary(resource) ->
          with {:ok, resource} <- canonical_resource(resource) do
            server_uri = URI.parse(server)

            if resource == server or
                 (resource == origin(server_uri) and
                    canonical_resource(metadata_url) ==
                      canonical_resource(root_metadata_url(server_uri))),
               do: {:ok, resource},
               else: {:error, {:resource_mismatch, resource, server}}
          end

        _other ->
          {:error, {:invalid_protected_resource_metadata, "resource"}}
      end
    end

    # Errors name the offending field instead of carrying the document, which
    # may have come from somewhere other than a real metadata endpoint
    defp protected_resource(_prm, _server, _metadata_url),
      do: {:error, {:invalid_protected_resource_metadata, "authorization_servers"}}

    defp root_metadata_url(%URI{} = uri),
      do: origin(uri) <> "/.well-known/oauth-protected-resource"

    defp select_authorization_server(%{"authorization_servers" => [issuer | _]})
         when is_binary(issuer),
         do: {:ok, issuer}

    defp select_authorization_server(_prm),
      do: {:error, {:invalid_protected_resource_metadata, "authorization_servers"}}

    defp validate_authorization_server(metadata, issuer, opts) do
      methods = List.wrap(metadata["code_challenge_methods_supported"])

      cond do
        metadata["issuer"] != issuer ->
          {:error, {:issuer_mismatch, issuer, metadata["issuer"]}}

        "S256" not in methods ->
          {:error, {:pkce_not_supported, issuer}}

        not is_binary(metadata["authorization_endpoint"]) or
            not is_binary(metadata["token_endpoint"]) ->
          {:error, {:invalid_authorization_server_metadata, issuer}}

        endpoint = insecure_endpoint(metadata, opts) ->
          {:error, {:insecure_url, endpoint}}

        true ->
          {:ok, metadata}
      end
    end

    defp insecure_endpoint(metadata, opts) do
      ["authorization_endpoint", "token_endpoint", "registration_endpoint", "revocation_endpoint"]
      |> Enum.map(&metadata[&1])
      |> Enum.find(&(is_binary(&1) and not HTTP.fetchable_url?(&1, opts)))
    end

    defp fetchable(url, opts) do
      if HTTP.fetchable_url?(url, opts), do: :ok, else: {:error, {:insecure_url, url}}
    end

    # The first document found, and the URL it came from
    defp first_json(urls, opts) do
      Enum.reduce_while(urls, {:error, []}, fn url, {:error, errors} ->
        case HTTP.get_json(url, opts) do
          {:ok, json} -> {:halt, {:ok, json, url}}
          {:error, error} -> {:cont, {:error, errors ++ [error]}}
        end
      end)
    end

    defp challenge(nil), do: nil

    defp challenge(header) when is_binary(header) or is_list(header),
      do: parse_www_authenticate(header)

    defp challenge(%{} = challenge), do: challenge

    defp origin(%URI{} = uri),
      do: URI.to_string(%URI{scheme: uri.scheme, host: uri.host, port: uri.port})

    defp challenges(header, acc) do
      rest = skip_separators(header)

      case Regex.run(@scheme_re, rest) do
        [match, scheme] ->
          {params, rest} = params(drop(rest, match), %{})
          challenges(rest, [%{scheme: String.downcase(scheme), params: params} | acc])

        nil ->
          Enum.reverse(acc)
      end
    end

    defp params(header, params) do
      rest = skip_separators(header)

      case Regex.run(@param_re, rest) do
        [match, name, value] ->
          params(drop(rest, match), Map.put(params, String.downcase(name), unquote_value(value)))

        nil ->
          # A token68 credential (`Basic abc==`) can only follow the scheme
          case params == %{} && Regex.run(@token68_re, rest) do
            [match, token68] -> {%{"token68" => token68}, drop(rest, match)}
            _ -> {params, rest}
          end
      end
    end

    defp unquote_value("\"" <> quoted) do
      quoted
      |> String.slice(0..-2//1)
      |> String.replace(~r/\\(.)/s, "\\1")
    end

    defp unquote_value(token), do: token

    defp skip_separators(header), do: String.replace(header, ~r/\A[ \t,]+/, "")

    defp drop(string, match),
      do: binary_part(string, byte_size(match), byte_size(string) - byte_size(match))
  end
end
