# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

if Code.ensure_loaded?(Req) do
  defmodule AshAi.Mcp.OAuth.Registration do
    @moduledoc """
    Obtains a client ID from an authorization server.

    Follows the spec's priority order: a pre-registered client, then a Client
    ID Metadata Document when the server supports them, then a client
    registered earlier through Dynamic Client Registration, then a new
    registration. With none of these available it returns
    `{:error, :client_registration_required}`, and the application has to ask
    for client credentials and supply them through `:pre_registered`.

    Pre-registered credentials and dynamic registrations both belong to one
    MCP server. A server that names another server's authorization server
    can't use the credentials configured for that server, and gets a
    registration of its own, so the authorization server asks the user for
    consent instead of reusing a grant made for the other server.
    """

    alias AshAi.Mcp.OAuth.{Client, Discovery, HTTP, Store}

    @grant_types ["authorization_code", "refresh_token"]

    @doc """
    Selects or registers a client for the MCP server `server` (its canonical
    resource URI) and the authorization server described by `metadata`
    (validated authorization server metadata).
    """
    @spec select_client(String.t(), map(), String.t(), keyword()) ::
            {:ok, Client.t()} | {:error, term()}
    def select_client(server, metadata, redirect_uri, opts) do
      issuer = metadata["issuer"]

      case pre_registered(server, issuer, opts) do
        {:ok, %Client{} = client} ->
          {:ok, client}

        {:ok, nil} ->
          if opts[:client_metadata_url] &&
               metadata["client_id_metadata_document_supported"] == true do
            cimd_client(issuer, opts)
          else
            case Store.call(opts[:store], :get_client, [server, issuer]) do
              {:ok, %Client{} = client} ->
                if reusable?(client, redirect_uri),
                  do: {:ok, client},
                  else: register(server, metadata, redirect_uri, opts)

              :error ->
                register(server, metadata, redirect_uri, opts)
            end
          end

        {:error, reason} ->
          {:error, reason}
      end
    end

    @doc """
    Finds the client `client_id` that `server` used with `issuer` again, for
    example when exchanging an authorization code or refreshing a token.
    """
    @spec resolve_client(String.t(), String.t(), String.t(), keyword()) ::
            {:ok, Client.t()} | {:error, :unknown_client}
    def resolve_client(server, issuer, client_id, opts) do
      case pre_registered(server, issuer, opts) do
        {:ok, %Client{client_id: ^client_id} = client} ->
          {:ok, client}

        _ ->
          if client_id == opts[:client_metadata_url] do
            cimd_client(issuer, opts)
          else
            # A client whose secret expired can't authenticate any more
            case Store.call(opts[:store], :get_client, [server, issuer]) do
              {:ok, %Client{client_id: ^client_id} = client} ->
                if expired?(client), do: {:error, :unknown_client}, else: {:ok, client}

              _ ->
                {:error, :unknown_client}
            end
          end
      end
    end

    @doc """
    The Client ID Metadata Document to serve at `:client_metadata_url`.

    Uses `:client_metadata_url` (required), `:client_name`, `:redirect_uris` (or
    `:redirect_uri`), `:client_uri`, and `:logo_uri`. The client is public and
    authenticates with PKCE alone.
    """
    @spec client_metadata_document(keyword()) :: map()
    def client_metadata_document(opts) do
      url = Keyword.fetch!(opts, :client_metadata_url)

      unless cimd_url?(url) do
        raise ArgumentError,
              "client_metadata_url must be an https URL with a path, got: #{inspect(url)}"
      end

      %{
        "client_id" => url,
        "client_name" => opts[:client_name] || "AshAi MCP Client",
        "redirect_uris" => opts[:redirect_uris] || List.wrap(opts[:redirect_uri]),
        "grant_types" => @grant_types,
        "response_types" => ["code"],
        "token_endpoint_auth_method" => "none"
      }
      |> maybe_put("client_uri", opts[:client_uri])
      |> maybe_put("logo_uri", opts[:logo_uri])
    end

    @doc """
    Registers a new client for `server` through Dynamic Client Registration
    (RFC 7591) and stores it.
    """
    @spec register(String.t(), map(), String.t(), keyword()) ::
            {:ok, Client.t()} | {:error, term()}
    def register(server, %{"registration_endpoint" => endpoint} = metadata, redirect_uri, opts)
        when is_binary(endpoint) do
      auth_method = opts[:token_endpoint_auth_method] || "none"
      redirect_uris = opts[:redirect_uris] || [redirect_uri]

      body =
        %{
          "client_name" => opts[:client_name] || "AshAi MCP Client",
          "redirect_uris" => redirect_uris,
          "grant_types" => @grant_types,
          "response_types" => ["code"],
          "token_endpoint_auth_method" => auth_method,
          "application_type" => opts[:application_type] || application_type(redirect_uri)
        }
        |> maybe_put("client_uri", opts[:client_uri])
        |> maybe_put("logo_uri", opts[:logo_uri])

      case HTTP.post(endpoint, [json: body], [], opts) do
        {:ok, status, %{"client_id" => client_id} = response, _}
        when status in 200..299 and is_binary(client_id) ->
          secret = string(response["client_secret"])

          client = %Client{
            issuer: metadata["issuer"],
            client_id: client_id,
            client_secret: secret,
            client_secret_expires_at: secret_expiry(response["client_secret_expires_at"]),
            registration_access_token: string(response["registration_access_token"]),
            registration_client_uri: string(response["registration_client_uri"]),
            source: :dcr,
            token_endpoint_auth_method:
              string(response["token_endpoint_auth_method"]) ||
                if(secret, do: "client_secret_basic", else: auth_method),
            redirect_uris: strings(response["redirect_uris"]) || redirect_uris
          }

          with :ok <- Store.call(opts[:store], :put_client, [server, client]) do
            {:ok, client}
          end

        {:ok, status, body, _} ->
          {:error, {:registration_failed, HTTP.error_fields(status, body)}}

        {:error, reason} ->
          {:error, reason}
      end
    end

    def register(_server, _metadata, _redirect_uri, _opts),
      do: {:error, :client_registration_required}

    # The credentials configured for `server`, checked against the issuer it
    # names now. A mismatch is an error rather than a reason to register
    # another way, since the server's authorization server changed.
    defp pre_registered(server, issuer, opts) do
      case pre_registered_config(server, opts) do
        nil ->
          {:ok, nil}

        config ->
          client = pre_registered_client(config)

          if client.issuer == issuer,
            do: {:ok, client},
            else: {:error, {:pre_registered_issuer_mismatch, client.issuer, issuer}}
      end
    end

    defp pre_registered_config(server, opts) do
      case opts[:pre_registered] do
        nil ->
          nil

        fun when is_function(fun, 1) ->
          fun.(server)

        %{} = by_server ->
          Enum.find_value(by_server, fn {url, config} ->
            if Discovery.canonical_resource(url) == {:ok, server}, do: config
          end)
      end
    end

    defp pre_registered_client(%Client{issuer: issuer} = client) when is_binary(issuer),
      do: %{client | source: :pre_registered}

    defp pre_registered_client(config) when is_list(config) or is_map(config) do
      config = Map.new(config, fn {key, value} -> {to_string(key), value} end)
      secret = config["client_secret"]

      %Client{
        issuer: Map.fetch!(config, "issuer"),
        client_id: Map.fetch!(config, "client_id"),
        client_secret: secret,
        source: :pre_registered,
        token_endpoint_auth_method:
          config["token_endpoint_auth_method"] ||
            if(secret, do: "client_secret_basic", else: "none"),
        redirect_uris: config["redirect_uris"] || []
      }
    end

    defp cimd_client(issuer, opts) do
      url = opts[:client_metadata_url]

      if cimd_url?(url) do
        {:ok,
         %Client{
           issuer: issuer,
           client_id: url,
           source: :cimd,
           token_endpoint_auth_method: "none",
           redirect_uris: opts[:redirect_uris] || List.wrap(opts[:redirect_uri])
         }}
      else
        {:error, {:invalid_client_metadata_url, url}}
      end
    end

    # A stored registration is reused while it still covers the redirect URI
    # and its secret hasn't expired.
    defp reusable?(%Client{} = client, redirect_uri),
      do: redirect_uri in client.redirect_uris and not expired?(client)

    defp expired?(%Client{client_secret_expires_at: nil}), do: false

    defp expired?(%Client{client_secret_expires_at: expires_at}),
      do: DateTime.compare(expires_at, DateTime.utc_now()) != :gt

    defp cimd_url?(url) when is_binary(url) do
      case URI.parse(url) do
        %URI{scheme: "https", host: host, path: path}
        when is_binary(host) and host != "" and is_binary(path) and path not in ["", "/"] ->
          true

        _ ->
          false
      end
    end

    defp cimd_url?(_url), do: false

    defp application_type(redirect_uri) do
      if AshAi.Mcp.NetworkPolicy.loopback_host?(URI.parse(redirect_uri).host),
        do: "native",
        else: "web"
    end

    # RFC 7591: 0 means the secret never expires
    defp secret_expiry(expires_at) when is_integer(expires_at) and expires_at > 0 do
      case DateTime.from_unix(expires_at) do
        {:ok, expiry} -> expiry
        {:error, _out_of_range} -> nil
      end
    end

    defp secret_expiry(_expires_at), do: nil

    # The registration response comes from the authorization server, so fields
    # of the wrong type are treated as absent
    defp string(value) when is_binary(value), do: value
    defp string(_value), do: nil

    defp strings(values) when is_list(values),
      do: if(Enum.all?(values, &is_binary/1), do: values)

    defp strings(_values), do: nil

    defp maybe_put(map, _key, nil), do: map
    defp maybe_put(map, key, value), do: Map.put(map, key, value)
  end
end
