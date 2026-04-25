# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

if Code.ensure_loaded?(Plug) do
  defmodule AshAi.Oauth.Authorize do
    @moduledoc """
    Plug implementing OAuth 2.1 authorization endpoint.

    Mount at `GET` and `POST /oauth/authorize`.

    ## Options

    - `:otp_app` (required)
    - `:skip_csrf?` (default `false`) — used in tests to bypass CSRF.
    """

    @behaviour Plug
    import Plug.Conn
    require Ash.Query

    alias AshAi.Oauth.Config

    @impl Plug
    def init(opts) do
      %{
        otp_app: Keyword.fetch!(opts, :otp_app),
        skip_csrf?: Keyword.get(opts, :skip_csrf?, false)
      }
    end

    @impl Plug
    def call(%{method: "GET"} = conn, opts), do: handle_get(conn, opts)
    def call(%{method: "POST"} = conn, opts), do: handle_post(conn, opts)
    def call(conn, _), do: send_resp(conn, 405, "method not allowed") |> halt()

    # ── GET ──────────────────────────────────────────────────────────────

    defp handle_get(conn, %{otp_app: otp_app}) do
      params = conn.query_params

      with {:ok, validated} <- validate_params(otp_app, params),
           {:ok, user} <- require_user(conn) do
        case existing_consent(otp_app, user, validated.client, validated.scope) do
          true -> issue_code_and_redirect(conn, otp_app, user, validated)
          false -> render_consent(conn, otp_app, validated)
        end
      else
        {:error, :no_user} -> sign_in_redirect(conn)
        {:error, :bad_redirect} -> send_resp(conn, 400, "invalid redirect_uri") |> halt()
        {:error, code, desc} -> bad_request(conn, code, desc)
      end
    end

    # ── POST ─────────────────────────────────────────────────────────────

    defp handle_post(conn, %{otp_app: otp_app, skip_csrf?: skip_csrf?}) do
      params = conn.params

      with :ok <- check_csrf(conn, params, skip_csrf?),
           {:ok, validated} <- validate_params(otp_app, params),
           {:ok, user} <- require_user(conn) do
        case Map.get(params, "action") do
          "approve" ->
            grant_consent(otp_app, user, validated)
            issue_code_and_redirect(conn, otp_app, user, validated)

          "deny" ->
            redirect_with_error(conn, validated, "access_denied")

          _ ->
            bad_request(conn, "invalid_request", "missing action")
        end
      else
        {:error, :no_user} -> sign_in_redirect(conn)
        {:error, :csrf} -> send_resp(conn, 403, "csrf failure") |> halt()
        {:error, :bad_redirect} -> send_resp(conn, 400, "invalid redirect_uri") |> halt()
        {:error, code, desc} -> bad_request(conn, code, desc)
      end
    end

    # ── Validation ───────────────────────────────────────────────────────

    defp validate_params(otp_app, params) do
      with :ok <- require_param(params, "response_type", "code", "unsupported_response_type"),
           {:ok, client} <- load_client(otp_app, params),
           :ok <- check_redirect_uri(params, client),
           :ok <- require_param(params, "code_challenge_method", "S256", "invalid_request"),
           :ok <- check_resource(otp_app, params),
           {:ok, code_challenge} <- require_present(params, "code_challenge"),
           {:ok, scope} <- require_present(params, "scope"),
           {:ok, redirect_uri} <- require_present(params, "redirect_uri"),
           {:ok, state} <- require_present(params, "state") do
        {:ok,
         %{
           client: client,
           redirect_uri: redirect_uri,
           code_challenge: code_challenge,
           scope: scope,
           state: state,
           resource: Map.fetch!(params, "resource")
         }}
      end
    end

    defp require_param(params, key, expected, error) do
      case Map.get(params, key) do
        ^expected -> :ok
        _ -> {:error, error, "expected #{key}=#{expected}"}
      end
    end

    defp require_present(params, key) do
      case Map.get(params, key) do
        v when is_binary(v) and v != "" -> {:ok, v}
        _ -> {:error, "invalid_request", "#{key} is required"}
      end
    end

    defp load_client(otp_app, %{"client_id" => id}) do
      case Ash.get(Config.client_resource(otp_app), id, authorize?: false) do
        {:ok, client} -> {:ok, client}
        _ -> {:error, "invalid_client", "unknown client_id"}
      end
    end

    defp load_client(_, _), do: {:error, "invalid_request", "client_id required"}

    defp check_redirect_uri(%{"redirect_uri" => uri}, %{redirect_uris: uris}) do
      if uri in uris, do: :ok, else: {:error, :bad_redirect}
    end

    defp check_redirect_uri(_, _), do: {:error, :bad_redirect}

    defp check_resource(otp_app, %{"resource" => res}) when is_binary(res) do
      if Config.normalize_url(res) == Config.canonical_mcp_url(otp_app),
        do: :ok,
        else: {:error, "invalid_target", "resource does not match this MCP server"}
    end

    defp check_resource(_, _), do: {:error, "invalid_request", "resource is required"}

    # ── Auth/consent helpers ─────────────────────────────────────────────

    defp require_user(conn) do
      case Ash.PlugHelpers.get_actor(conn) do
        nil -> {:error, :no_user}
        user -> {:ok, user}
      end
    end

    # Returns `true` only when prior consent exists AND the consented scope
    # is a superset of the currently-requested scope. Prevents silent
    # privilege expansion when scopes grow over time.
    defp existing_consent(otp_app, user, client, requested_scope) do
      consent_resource = Config.consent_resource(otp_app)

      consent_resource
      |> Ash.Query.filter(user_id == ^user.id and client_id == ^client.id)
      |> Ash.read_one(authorize?: false)
      |> case do
        {:ok, %{scope: stored}} -> scope_covers?(stored, requested_scope)
        _ -> false
      end
    end

    defp scope_covers?(stored, requested) when is_binary(stored) and is_binary(requested) do
      stored_set = stored |> String.split(" ", trim: true) |> MapSet.new()
      requested_set = requested |> String.split(" ", trim: true) |> MapSet.new()
      MapSet.subset?(requested_set, stored_set)
    end

    defp scope_covers?(_, _), do: false

    defp grant_consent(otp_app, user, %{client: client, scope: scope}) do
      Config.consent_resource(otp_app)
      |> Ash.Changeset.for_create(:grant, %{user_id: user.id, client_id: client.id, scope: scope})
      |> Ash.create!(authorize?: false)
    end

    # ── Code issuance ────────────────────────────────────────────────────

    defp issue_code_and_redirect(conn, otp_app, user, validated) do
      ttl_seconds = Config.authorization_code_ttl(otp_app)
      expires_at = DateTime.add(DateTime.utc_now(), ttl_seconds, :second)

      code =
        Config.authorization_code_resource(otp_app)
        |> Ash.Changeset.for_create(:create, %{
          client_id: validated.client.id,
          user_id: user.id,
          redirect_uri: validated.redirect_uri,
          code_challenge: validated.code_challenge,
          scope: validated.scope,
          resource_uri: validated.resource,
          expires_at: expires_at
        })
        |> Ash.create!(authorize?: false)

      query = URI.encode_query(%{"code" => code.id, "state" => validated.state})
      location = validated.redirect_uri <> "?" <> query

      conn
      |> put_resp_header("location", location)
      |> send_resp(302, "")
      |> halt()
    end

    defp redirect_with_error(conn, validated, error) do
      query = URI.encode_query(%{"error" => error, "state" => validated.state})
      location = validated.redirect_uri <> "?" <> query

      conn
      |> put_resp_header("location", location)
      |> send_resp(302, "")
      |> halt()
    end

    # ── Rendering ────────────────────────────────────────────────────────

    defp render_consent(conn, otp_app, validated) do
      template = Config.consent_template(otp_app)

      assigns = %{
        client_name: validated.client.client_name,
        client_id: validated.client.id,
        redirect_uri: validated.redirect_uri,
        code_challenge: validated.code_challenge,
        scope: validated.scope,
        state: validated.state,
        resource: validated.resource,
        resource_uri: validated.resource,
        action_path: "/oauth/authorize",
        csrf_token: get_csrf_token(conn)
      }

      body = template.render(:consent, assigns) |> to_string()

      conn
      |> put_resp_header("content-type", "text/html; charset=utf-8")
      |> put_resp_header("x-frame-options", "DENY")
      |> send_resp(200, body)
      |> halt()
    end

    defp get_csrf_token(_conn) do
      try do
        Plug.CSRFProtection.get_csrf_token()
      rescue
        _ -> ""
      end
    end

    defp check_csrf(_conn, _params, true), do: :ok

    defp check_csrf(conn, params, false) do
      token = Map.get(params, "_csrf_token")

      with t when is_binary(t) <- token,
           true <- Plug.CSRFProtection.valid_state_and_csrf_token?(get_session(conn, "_csrf_token"), t) do
        :ok
      else
        _ -> {:error, :csrf}
      end
    end

    # ── Misc ─────────────────────────────────────────────────────────────

    defp sign_in_redirect(conn), do: send_resp(conn, 401, "authentication required") |> halt()

    defp bad_request(conn, code, desc) do
      AshAi.Oauth.Error.send_oauth_error(conn, 400, code, desc)
    end
  end
end
