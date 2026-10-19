# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Test.OAuthMemoryStore do
  @moduledoc false
  @behaviour AshAi.Mcp.OAuth.Store

  alias AshAi.Mcp.OAuth.{Client, Pending, Token}

  def start_link do
    Agent.start_link(fn -> %{clients: %{}, tokens: %{}, pending: %{}, puts: 0} end)
  end

  def state(pid), do: Agent.get(pid, & &1)

  @impl true
  def get_client(server, issuer, pid: pid) do
    case Agent.get(pid, &get_in(&1, [:clients, {server, issuer}])) do
      nil -> :error
      map -> {:ok, Client.from_map(map)}
    end
  end

  @impl true
  def put_client(server, %Client{} = client, pid: pid) do
    Agent.update(pid, &put_in(&1, [:clients, {server, client.issuer}], Client.to_map(client)))
  end

  @impl true
  def get_token(server, owner, pid: pid) do
    case Agent.get(pid, &get_in(&1, [:tokens, {server, owner}])) do
      nil -> :error
      map -> {:ok, Token.from_map(map)}
    end
  end

  @impl true
  def put_token(server, owner, %Token{} = token, pid: pid) do
    Agent.update(pid, fn state ->
      state
      |> put_in([:tokens, {server, owner}], Token.to_map(token))
      |> Map.update!(:puts, &(&1 + 1))
    end)
  end

  @impl true
  def delete_token(server, owner, pid: pid) do
    Agent.update(
      pid,
      &update_in(&1, [:tokens], fn tokens -> Map.delete(tokens, {server, owner}) end)
    )
  end

  @impl true
  def with_lock(server, owner, fun, pid: pid) do
    :global.trans({{__MODULE__, pid, server, owner}, self()}, fun, [node()], :infinity)
  end

  @impl true
  def put_pending(%Pending{} = pending, pid: pid) do
    Agent.update(pid, &put_in(&1, [:pending, pending.state], Pending.to_map(pending)))
  end

  @impl true
  def take_pending(state, pid: pid) do
    Agent.get_and_update(pid, fn store ->
      {map, pending} = Map.pop(store.pending, state)
      {map, %{store | pending: pending}}
    end)
    |> case do
      nil -> :error
      map -> {:ok, Pending.from_map(map)}
    end
  end
end

defmodule AshAi.Test.FakeOAuthServer do
  @moduledoc false
  # An MCP server at https://mcp.example.com/mcp and its authorization server at
  # https://auth.example.com, run as a plug through Req's `plug:` option.

  import Plug.Conn

  @mcp "mcp.example.com"
  @auth "auth.example.com"

  def start_link(overrides \\ %{}) do
    Agent.start_link(fn -> Map.merge(default_state(), overrides) end)
  end

  def default_state do
    %{
      docs: %{
        {@mcp, "/.well-known/oauth-protected-resource/mcp"} => %{
          "resource" => "https://mcp.example.com/mcp",
          "authorization_servers" => ["https://auth.example.com"],
          "scopes_supported" => ["mcp:read"]
        },
        {@auth, "/.well-known/oauth-authorization-server"} => as_metadata()
      },
      www_authenticate: nil,
      codes: %{},
      refresh_tokens: %{},
      clients: %{},
      rotate_refresh_tokens: true,
      omit_refresh_token: false,
      refresh_delay: 0,
      expires_in: 3600,
      issued: 0,
      # Fields merged into the responses of "/register" and "/token"
      overrides: %{},
      revoked: [],
      revoke_status: 200,
      requests: []
    }
  end

  def as_metadata(overrides \\ %{}) do
    Map.merge(
      %{
        "issuer" => "https://auth.example.com",
        "authorization_endpoint" => "https://auth.example.com/authorize",
        "token_endpoint" => "https://auth.example.com/token",
        "registration_endpoint" => "https://auth.example.com/register",
        "revocation_endpoint" => "https://auth.example.com/revoke",
        "code_challenge_methods_supported" => ["S256"],
        "scopes_supported" => ["mcp:read", "mcp:write", "offline_access"],
        "authorization_response_iss_parameter_supported" => true
      },
      overrides
    )
  end

  def update(pid, fun), do: Agent.update(pid, fun)
  def get(pid, key), do: Agent.get(pid, &Map.fetch!(&1, key))

  def requests(pid), do: pid |> get(:requests) |> Enum.reverse()

  def request_paths(pid), do: Enum.map(requests(pid), &{&1.method, &1.host, &1.path})

  # Plays the user approving the authorization request at `url`
  def approve(pid, url) do
    query = url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
    code = "code-" <> Integer.to_string(System.unique_integer([:positive]))

    Agent.update(pid, fn state ->
      put_in(state, [:codes, code], %{
        challenge: query["code_challenge"],
        client_id: query["client_id"],
        redirect_uri: query["redirect_uri"],
        resource: query["resource"],
        scope: query["scope"]
      })
    end)

    code
  end

  # Gives `refresh_token` to the authorization server, as if it had issued it
  def put_refresh_token(pid, refresh_token, client_id, resource \\ "https://mcp.example.com/mcp") do
    Agent.update(pid, fn state ->
      put_in(state, [:refresh_tokens, refresh_token], %{client_id: client_id, resource: resource})
    end)
  end

  def init(pid), do: pid

  def call(conn, pid) do
    {:ok, body, conn} = read_body(conn)

    params =
      case get_req_header(conn, "content-type") do
        ["application/json" <> _] -> Jason.decode!(body)
        _ -> URI.decode_query(body)
      end

    Agent.update(pid, fn state ->
      request = %{
        method: conn.method,
        host: conn.host,
        path: conn.request_path,
        params: params,
        headers: conn.req_headers
      }

      %{state | requests: [request | state.requests]}
    end)

    route(conn, conn.method, conn.host, conn.request_path, params, pid)
  end

  defp route(conn, "GET", host, path, _params, pid) do
    case Agent.get(pid, &Map.get(&1.docs, {host, path})) do
      nil -> send_resp(conn, 404, "not found")
      doc -> json(conn, 200, doc)
    end
  end

  defp route(conn, "POST", @mcp, "/mcp", _params, pid) do
    case get(pid, :www_authenticate) do
      nil -> send_resp(conn, 401, "")
      header -> conn |> put_resp_header("www-authenticate", header) |> send_resp(401, "")
    end
  end

  defp route(conn, "POST", @auth, "/register", params, pid) do
    client_id = "dcr-" <> Integer.to_string(System.unique_integer([:positive]))
    method = params["token_endpoint_auth_method"]
    secret = if method == "none", do: nil, else: "secret-#{client_id}"

    Agent.update(pid, &put_in(&1, [:clients, client_id], %{secret: secret, method: method}))

    json(
      conn,
      201,
      %{
        "client_id" => client_id,
        "redirect_uris" => params["redirect_uris"],
        "token_endpoint_auth_method" => method,
        "client_secret_expires_at" => 0
      }
      |> then(&if(secret, do: Map.put(&1, "client_secret", secret), else: &1))
      |> Map.merge(get(pid, :overrides)["/register"] || %{})
    )
  end

  defp route(conn, "POST", @auth, "/token", params, pid) do
    case authenticate_client(conn, params, pid) do
      {:ok, client_id} -> grant(conn, params["grant_type"], client_id, params, pid)
      :error -> json(conn, 401, %{"error" => "invalid_client"})
    end
  end

  defp route(conn, "POST", @auth, "/revoke", params, pid) do
    case authenticate_client(conn, params, pid) do
      {:ok, _client_id} ->
        Agent.update(pid, fn state ->
          %{
            state
            | refresh_tokens: Map.delete(state.refresh_tokens, params["token"]),
              revoked: state.revoked ++ [{params["token_type_hint"], params["token"]}]
          }
        end)

        send_resp(conn, get(pid, :revoke_status), "")

      :error ->
        json(conn, 401, %{"error" => "invalid_client"})
    end
  end

  defp route(conn, _method, _host, _path, _params, _pid), do: send_resp(conn, 404, "not found")

  defp authenticate_client(conn, params, pid) do
    clients = get(pid, :clients)

    case get_req_header(conn, "authorization") do
      ["Basic " <> encoded] ->
        [id, secret] = encoded |> Base.decode64!() |> String.split(":", parts: 2)
        id = URI.decode_www_form(id)

        if clients[id] && clients[id].secret == URI.decode_www_form(secret),
          do: {:ok, id},
          else: :error

      [] ->
        id = params["client_id"]

        case clients[id] do
          %{secret: nil} -> {:ok, id}
          %{secret: secret} -> if params["client_secret"] == secret, do: {:ok, id}, else: :error
          # Public clients we don't know, such as Client ID Metadata Document URLs
          nil -> if is_binary(id), do: {:ok, id}, else: :error
        end
    end
  end

  defp grant(conn, "authorization_code", client_id, params, pid) do
    code = Agent.get_and_update(pid, fn state -> pop_in(state, [:codes, params["code"]]) end)

    challenge =
      Base.url_encode64(:crypto.hash(:sha256, params["code_verifier"] || ""), padding: false)

    cond do
      is_nil(code) or code.client_id != client_id or code.redirect_uri != params["redirect_uri"] ->
        json(conn, 400, %{"error" => "invalid_grant"})

      code.challenge != challenge ->
        json(conn, 400, %{"error" => "invalid_grant", "error_description" => "PKCE"})

      code.resource != params["resource"] ->
        json(conn, 400, %{"error" => "invalid_target"})

      true ->
        issue(conn, client_id, code.resource, code.scope, true, pid)
    end
  end

  defp grant(conn, "refresh_token", client_id, params, pid) do
    Process.sleep(get(pid, :refresh_delay))
    state = Agent.get(pid, & &1)

    case state.refresh_tokens[params["refresh_token"]] do
      %{client_id: ^client_id, resource: resource} ->
        if state.rotate_refresh_tokens do
          Agent.update(
            pid,
            &update_in(&1, [:refresh_tokens], fn rts ->
              Map.delete(rts, params["refresh_token"])
            end)
          )
        end

        issue(conn, client_id, resource, nil, not state.omit_refresh_token, pid)

      _ ->
        json(conn, 400, %{"error" => "invalid_grant"})
    end
  end

  defp grant(conn, _grant_type, _client_id, _params, _pid),
    do: json(conn, 400, %{"error" => "unsupported_grant_type"})

  defp issue(conn, client_id, resource, scope, refresh?, pid) do
    n =
      Agent.get_and_update(pid, fn state ->
        {state.issued + 1, %{state | issued: state.issued + 1}}
      end)

    refresh_token = "rt-#{n}"

    if refresh?, do: put_refresh_token(pid, refresh_token, client_id, resource)

    json(
      conn,
      200,
      %{
        "access_token" => "at-#{n}",
        "token_type" => "Bearer",
        "expires_in" => get(pid, :expires_in)
      }
      |> then(&if(refresh?, do: Map.put(&1, "refresh_token", refresh_token), else: &1))
      |> then(&if(scope, do: Map.put(&1, "scope", scope), else: &1))
      |> Map.merge(get(pid, :overrides)["/token"] || %{})
    )
  end

  defp json(conn, status, body) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(body))
  end
end
