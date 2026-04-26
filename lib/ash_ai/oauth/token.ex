# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

if Code.ensure_loaded?(Plug) do
  defmodule AshAi.Oauth.Token do
    @moduledoc """
    Plug implementing OAuth 2.1 token endpoint.

    Mount at `POST /oauth/token`. Supports:
      - `grant_type=authorization_code` with PKCE
      - `grant_type=refresh_token` with rotation + reuse detection
        (RFC 6749 §6, OAuth 2.1 §4.3.1)
    """

    @behaviour Plug
    import Plug.Conn
    require Ash.Query

    alias AshAi.Oauth.{Config, Error, Jwt, Pkce}

    @impl Plug
    def init(opts), do: Keyword.fetch!(opts, :otp_app)

    @impl Plug
    def call(%{method: "POST"} = conn, otp_app) do
      params = conn.params || %{}

      case Map.get(params, "grant_type") do
        "authorization_code" -> handle_code(conn, otp_app, params)
        "refresh_token" -> handle_refresh(conn, otp_app, params)
        _ -> Error.send_oauth_error(conn, 400, "unsupported_grant_type")
      end
    end

    def call(conn, _), do: Error.send_oauth_error(conn, 405, "invalid_request", "POST required")

    # ── authorization_code grant ─────────────────────────────────────────

    defp handle_code(conn, otp_app, params) do
      with {:ok, code, client} <- consume_code(otp_app, params),
           :ok <- check_pkce(code, params),
           :ok <- check_resource_match(otp_app, params, code),
           :ok <- check_redirect_match(params, code),
           {:ok, access, refresh} <- mint_tokens(otp_app, client, code) do
        touch_client(client)
        respond_with_tokens(conn, otp_app, access, refresh, code.scope)
      else
        {:error, :reuse} -> Error.send_oauth_error(conn, 400, "invalid_grant", "code already used")
        {:error, :expired} -> Error.send_oauth_error(conn, 400, "invalid_grant", "code expired")
        {:error, :pkce} -> Error.send_oauth_error(conn, 400, "invalid_grant", "PKCE verification failed")
        {:error, :resource} -> Error.send_oauth_error(conn, 400, "invalid_grant", "resource mismatch")
        {:error, :redirect} -> Error.send_oauth_error(conn, 400, "invalid_grant", "redirect_uri mismatch")
        {:error, :not_found} -> Error.send_oauth_error(conn, 400, "invalid_grant", "code not found")
      end
    end

    defp consume_code(otp_app, %{"code" => code_id, "client_id" => client_id}) do
      with {:ok, code} <- Ash.get(Config.authorization_code_resource(otp_app), code_id, authorize?: false),
           :ok <- check_client_match(code, client_id),
           :ok <- check_not_expired(code),
           {:ok, code} <- code |> Ash.Changeset.for_update(:consume, %{}) |> Ash.update(authorize?: false),
           {:ok, client} <- Ash.get(Config.client_resource(otp_app), code.client_id, authorize?: false) do
        {:ok, code, client}
      else
        {:error, %Ash.Error.Invalid{}} -> {:error, :reuse}
        {:error, _} = err -> err
      end
    end

    defp consume_code(_, _), do: {:error, :not_found}

    # Both sides are binary UUID strings — direct equality is fine and
    # consistent with the other id checks in this module.
    defp check_client_match(%{client_id: code_client_id}, client_id) when is_binary(client_id) do
      if code_client_id == client_id, do: :ok, else: {:error, :not_found}
    end

    defp check_client_match(_, _), do: {:error, :not_found}

    defp check_not_expired(code) do
      if DateTime.compare(DateTime.utc_now(), code.expires_at) == :gt,
        do: {:error, :expired},
        else: :ok
    end

    defp check_pkce(code, %{"code_verifier" => verifier}),
      do: if(Pkce.verify(verifier, code.code_challenge) == :ok, do: :ok, else: {:error, :pkce})

    defp check_pkce(_, _), do: {:error, :pkce}

    defp check_resource_match(otp_app, %{"resource" => res}, code) when is_binary(res) do
      expected = Config.canonical_mcp_url(otp_app)

      if Config.normalize_url(res) == expected and code.resource_uri == expected,
        do: :ok,
        else: {:error, :resource}
    end

    defp check_resource_match(_, _, _), do: {:error, :resource}

    defp check_redirect_match(%{"redirect_uri" => uri}, code),
      do: if(uri == code.redirect_uri, do: :ok, else: {:error, :redirect})

    defp check_redirect_match(_, _), do: {:error, :redirect}

    defp mint_tokens(otp_app, client, code) do
      with {:ok, access, _claims} <- Jwt.mint(otp_app, sub: code.user_id, client_id: client.id, scope: code.scope),
           {:ok, refresh_raw} <- issue_refresh(otp_app, client.id, code.user_id, code.scope, code.resource_uri) do
        {:ok, access, refresh_raw}
      end
    end

    defp issue_refresh(otp_app, client_id, user_id, scope, resource_uri) do
      raw = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
      hash = :crypto.hash(:sha256, raw) |> Base.encode16(case: :lower)

      Config.refresh_token_resource(otp_app)
      |> Ash.Changeset.for_create(:issue, %{
        token_hash: hash,
        client_id: client_id,
        user_id: user_id,
        scope: scope,
        resource_uri: resource_uri,
        expires_at: DateTime.add(DateTime.utc_now(), Config.refresh_token_ttl(otp_app), :second)
      })
      |> Ash.create(authorize?: false)
      |> case do
        {:ok, _row} -> {:ok, raw}
        {:error, _} = err -> err
      end
    end

    defp respond_with_tokens(conn, otp_app, access, refresh, scope) do
      body =
        Jason.encode!(%{
          "access_token" => access,
          "token_type" => "Bearer",
          "expires_in" => Config.access_token_ttl(otp_app),
          "refresh_token" => refresh,
          "scope" => scope
        })

      conn
      |> put_resp_header("content-type", "application/json")
      |> put_resp_header("cache-control", "no-store")
      |> send_resp(200, body)
      |> halt()
    end

    # ── refresh_token grant ──────────────────────────────────────────────

    defp handle_refresh(conn, otp_app, %{"refresh_token" => raw, "client_id" => client_id, "resource" => res}) do
      hash = :crypto.hash(:sha256, raw) |> Base.encode16(case: :lower)

      with {:ok, row} <- find_refresh(otp_app, hash),
           :ok <- check_refresh_validity(row, client_id, otp_app, res),
           {:ok, access, new_refresh} <- rotate_refresh(otp_app, row) do
        touch_client_by_id(otp_app, row.client_id)
        respond_with_tokens(conn, otp_app, access, new_refresh, row.scope)
      else
        {:error, :reuse} ->
          revoke_chain(otp_app, hash)
          Error.send_oauth_error(conn, 400, "invalid_grant", "refresh token reuse")

        {:error, _} ->
          Error.send_oauth_error(conn, 400, "invalid_grant", "refresh failed")
      end
    end

    defp handle_refresh(conn, _, _),
      do: Error.send_oauth_error(conn, 400, "invalid_request", "missing refresh params")

    defp find_refresh(otp_app, hash) do
      Config.refresh_token_resource(otp_app)
      |> Ash.Query.filter(token_hash == ^hash)
      |> Ash.read_one(authorize?: false)
      |> case do
        {:ok, %{} = row} -> {:ok, row}
        _ -> {:error, :not_found}
      end
    end

    defp check_refresh_validity(row, client_id, otp_app, res) do
      cond do
        row.client_id != client_id -> {:error, :client_mismatch}
        row.resource_uri != Config.canonical_mcp_url(otp_app) or row.resource_uri != res -> {:error, :resource}
        row.revoked_at -> {:error, :revoked}
        row.rotated_to_id -> {:error, :reuse}
        DateTime.compare(DateTime.utc_now(), row.expires_at) == :gt -> {:error, :expired}
        true -> :ok
      end
    end

    defp rotate_refresh(otp_app, row) do
      # Create new refresh token first, then rotate old to point at new
      raw = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
      hash = :crypto.hash(:sha256, raw) |> Base.encode16(case: :lower)

      with {:ok, new_row} <-
             Config.refresh_token_resource(otp_app)
             |> Ash.Changeset.for_create(:issue, %{
               token_hash: hash,
               client_id: row.client_id,
               user_id: row.user_id,
               scope: row.scope,
               resource_uri: row.resource_uri,
               expires_at: DateTime.add(DateTime.utc_now(), Config.refresh_token_ttl(otp_app), :second)
             })
             |> Ash.create(authorize?: false),
           {:ok, _} <- row |> Ash.Changeset.for_update(:rotate, %{new_id: new_row.id}) |> Ash.update(authorize?: false),
           {:ok, access, _} <-
             Jwt.mint(otp_app, sub: row.user_id, client_id: row.client_id, scope: row.scope) do
        {:ok, access, raw}
      end
    end

    # Best-effort: bump `last_used_at` on the issuing OAuthClient so operators
    # can prune dormant DCR-registered clients. Failure is silent — touch is
    # bookkeeping, not a security control.
    defp touch_client(client) do
      client
      |> Ash.Changeset.for_update(:touch, %{})
      |> Ash.update(authorize?: false)
    rescue
      _ -> :noop
    end

    defp touch_client_by_id(otp_app, client_id) do
      case Ash.get(Config.client_resource(otp_app), client_id, authorize?: false) do
        {:ok, client} -> touch_client(client)
        _ -> :noop
      end
    end

    # On reuse-detection, walk forward through `rotated_to_id` and revoke every
    # descendant of the offending refresh token. Per OAuth 2.1 §4.3.1.
    defp revoke_chain(otp_app, hash) do
      case find_refresh(otp_app, hash) do
        {:ok, row} -> revoke_descendants(otp_app, row)
        _ -> :noop
      end
    end

    defp revoke_descendants(otp_app, row) do
      row |> Ash.Changeset.for_update(:revoke, %{}) |> Ash.update(authorize?: false)

      if row.rotated_to_id do
        case Ash.get(Config.refresh_token_resource(otp_app), row.rotated_to_id, authorize?: false) do
          {:ok, next} -> revoke_descendants(otp_app, next)
          _ -> :ok
        end
      else
        :ok
      end
    end
  end
end
