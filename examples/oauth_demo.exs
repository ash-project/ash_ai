# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

# Self-contained OAuth 2.1 MCP demo server.
#
# Run from the repo root:
#
#     mix run --no-halt examples/oauth_demo.exs
#
# Then in another terminal:
#
#     bash examples/test-oauth.sh
#
# Or point ChatGPT / Claude at http://localhost:4000/mcp (you'll need a
# tunnel like ngrok / cloudflared for them to reach it; ChatGPT requires
# https in production, but accepts http://localhost in development).
#
# What this script does:
#
#   1. Defines the four OAuth Ash resources (client, code, refresh, consent)
#      and a User resource, all using the ETS data layer (in-memory).
#   2. Configures :ash_ai, AshAi.Oauth at runtime.
#   3. Mounts a tiny MCP endpoint that just echoes the authenticated actor.
#   4. Starts Bandit on http://localhost:4000.

# ── Resources ────────────────────────────────────────────────────────

defmodule OAuthDemo.User do
  @moduledoc false
  use Ash.Resource, domain: OAuthDemo.Domain, data_layer: Ash.DataLayer.Ets

  attributes do
    uuid_v7_primary_key :id
    attribute :email, :ci_string, public?: true, allow_nil?: false
  end

  actions do
    defaults [:read]
    create :create, accept: [:email]
  end
end

defmodule OAuthDemo.OAuthClient do
  @moduledoc false
  use Ash.Resource, domain: OAuthDemo.Domain, data_layer: Ash.DataLayer.Ets

  attributes do
    uuid_v7_primary_key :id
    attribute :client_name, :string, public?: true, allow_nil?: false
    attribute :redirect_uris, {:array, :string}, public?: true, allow_nil?: false, default: []
    attribute :grant_types, {:array, :string}, public?: true, default: ["authorization_code"]
    attribute :response_types, {:array, :string}, public?: true, default: ["code"]
    attribute :token_endpoint_auth_method, :string, public?: true, default: "none"
    attribute :client_secret_hash, :string, public?: false
    attribute :scope, :string, public?: true, default: "mcp"
    attribute :last_used_at, :utc_datetime_usec, public?: true
    create_timestamp :created_at
    update_timestamp :updated_at
  end

  actions do
    defaults [:read, :destroy]

    create :register do
      accept [:client_name, :redirect_uris, :grant_types, :response_types, :token_endpoint_auth_method, :scope]
    end

    update :touch do
      accept []
      change set_attribute(:last_used_at, &DateTime.utc_now/0)
    end
  end
end

defmodule OAuthDemo.OAuthAuthorizationCode do
  @moduledoc false
  use Ash.Resource, domain: OAuthDemo.Domain, data_layer: Ash.DataLayer.Ets

  attributes do
    uuid_v7_primary_key :id
    attribute :client_id, :uuid_v7, allow_nil?: false, public?: true
    attribute :user_id, :uuid_v7, allow_nil?: false, public?: true
    attribute :redirect_uri, :string, allow_nil?: false, public?: true
    attribute :code_challenge, :string, allow_nil?: false, public?: true
    attribute :scope, :string, allow_nil?: false, public?: true
    attribute :resource_uri, :string, allow_nil?: false, public?: true
    attribute :expires_at, :utc_datetime_usec, allow_nil?: false, public?: true
    attribute :consumed_at, :utc_datetime_usec, public?: true
  end

  actions do
    defaults [:read, :destroy]

    create :create do
      accept [:client_id, :user_id, :redirect_uri, :code_challenge, :scope, :resource_uri, :expires_at]
    end

    update :consume do
      accept []
      require_atomic? false

      change fn changeset, _ ->
        if Ash.Changeset.get_data(changeset, :consumed_at) do
          Ash.Changeset.add_error(changeset, field: :consumed_at, message: "code already used")
        else
          Ash.Changeset.change_attribute(changeset, :consumed_at, DateTime.utc_now())
        end
      end
    end
  end
end

defmodule OAuthDemo.OAuthRefreshToken do
  @moduledoc false
  use Ash.Resource, domain: OAuthDemo.Domain, data_layer: Ash.DataLayer.Ets

  attributes do
    uuid_v7_primary_key :id
    attribute :token_hash, :string, allow_nil?: false, public?: true
    attribute :client_id, :uuid_v7, allow_nil?: false, public?: true
    attribute :user_id, :uuid_v7, allow_nil?: false, public?: true
    attribute :scope, :string, allow_nil?: false, public?: true
    attribute :resource_uri, :string, allow_nil?: false, public?: true
    attribute :expires_at, :utc_datetime_usec, allow_nil?: false, public?: true
    attribute :rotated_to_id, :uuid_v7, public?: true
    attribute :revoked_at, :utc_datetime_usec, public?: true
  end

  actions do
    defaults [:read, :destroy]

    create :issue do
      accept [:token_hash, :client_id, :user_id, :scope, :resource_uri, :expires_at]
    end

    update :rotate do
      argument :new_id, :uuid_v7, allow_nil?: false
      accept []
      require_atomic? false

      change fn changeset, _ ->
        cond do
          Ash.Changeset.get_data(changeset, :revoked_at) ->
            Ash.Changeset.add_error(changeset, message: "refresh token revoked")

          Ash.Changeset.get_data(changeset, :rotated_to_id) ->
            Ash.Changeset.add_error(changeset, message: "refresh token already rotated")

          true ->
            new_id = Ash.Changeset.get_argument(changeset, :new_id)
            Ash.Changeset.change_attribute(changeset, :rotated_to_id, new_id)
        end
      end
    end

    update :revoke do
      accept []
      change set_attribute(:revoked_at, &DateTime.utc_now/0)
    end
  end

  identities do
    identity :by_token_hash, [:token_hash]
  end
end

defmodule OAuthDemo.OAuthConsent do
  @moduledoc false
  use Ash.Resource, domain: OAuthDemo.Domain, data_layer: Ash.DataLayer.Ets

  attributes do
    uuid_v7_primary_key :id
    attribute :user_id, :uuid_v7, allow_nil?: false, public?: true
    attribute :client_id, :uuid_v7, allow_nil?: false, public?: true
    attribute :scope, :string, allow_nil?: false, public?: true
    attribute :granted_at, :utc_datetime_usec, allow_nil?: false, public?: true, default: &DateTime.utc_now/0
  end

  actions do
    defaults [:read, :destroy]

    create :grant do
      upsert? true
      upsert_identity :by_user_client
      accept [:user_id, :client_id, :scope]
    end
  end

  identities do
    identity :by_user_client, [:user_id, :client_id], pre_check_with: OAuthDemo.Domain
  end
end

defmodule OAuthDemo.Domain do
  @moduledoc false
  use Ash.Domain

  resources do
    resource OAuthDemo.User
    resource OAuthDemo.OAuthClient
    resource OAuthDemo.OAuthAuthorizationCode
    resource OAuthDemo.OAuthRefreshToken
    resource OAuthDemo.OAuthConsent
  end
end

# ── A trivial MCP endpoint ───────────────────────────────────────────

defmodule OAuthDemo.McpEcho do
  @moduledoc """
  Stand-in for AshAi.Mcp.Router. Returns the authenticated user so you
  can prove the bearer token was accepted.
  """
  @behaviour Plug
  import Plug.Conn

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    actor = Ash.PlugHelpers.get_actor(conn)
    claims = conn.assigns[:oauth_claims] || %{}

    body =
      Jason.encode!(%{
        "ok" => true,
        "user" => actor && %{"id" => actor.id, "email" => to_string(actor.email)},
        "scope" => claims["scope"],
        "client_id" => claims["client_id"],
        "jti" => claims["jti"]
      })

    conn
    |> put_resp_header("content-type", "application/json")
    |> send_resp(200, body)
  end
end

# ── Browser-side auto-sign-in + auto-consent (demo only) ────────────

defmodule OAuthDemo.AutoSignIn do
  @moduledoc """
  Demo-only: pretend the user is signed in by setting the seeded user as
  the current actor. A real app uses AshAuthentication's sign-in flow.
  """
  @behaviour Plug
  import Plug.Conn

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    {:ok, [user | _]} = Ash.read(OAuthDemo.User, authorize?: false)
    Ash.PlugHelpers.set_actor(conn, user)
  end
end

defmodule OAuthDemo.AutoConsent do
  @moduledoc """
  Demo-only: silently grant consent for the requesting client so the
  walkthrough script never has to render and submit the consent form.

  In a real app, the user clicks "Approve" on the consent page. Do not
  ship this in production — it defeats the entire confused-deputy
  protection.
  """
  @behaviour Plug
  import Plug.Conn

  @impl true
  def init(opts), do: opts

  @impl true
  def call(%Plug.Conn{method: "GET"} = conn, _opts) do
    conn = fetch_query_params(conn)
    user = Ash.PlugHelpers.get_actor(conn)
    client_id = conn.query_params["client_id"]
    scope = conn.query_params["scope"] || "mcp"

    if user && is_binary(client_id) do
      OAuthDemo.OAuthConsent
      |> Ash.Changeset.for_create(:grant, %{
        user_id: user.id,
        client_id: client_id,
        scope: scope
      })
      |> Ash.create!(authorize?: false)
    end

    conn
  end

  def call(conn, _opts), do: conn
end

# ── Plug pipelines (must be defined before the Router) ──────────────

defmodule OAuthDemo.AuthorizeWithUser do
  @moduledoc false
  use Plug.Builder

  plug OAuthDemo.AutoSignIn
  plug OAuthDemo.AutoConsent
  plug AshAi.Oauth.Authorize, otp_app: :ash_ai
end

defmodule OAuthDemo.McpPipeline do
  @moduledoc false
  use Plug.Builder

  plug AshAi.Mcp.BearerPlug, otp_app: :ash_ai, required?: true
  plug OAuthDemo.McpEcho
end

# ── Top-level router ─────────────────────────────────────────────────

defmodule OAuthDemo.Router do
  use Plug.Router

  plug Plug.Logger

  # Sessions are required for CSRF on POST /oauth/authorize
  @session_options [
    store: :cookie,
    key: "_oauth_demo_session",
    signing_salt: "demo-salt-32-bytes-or-more",
    same_site: "Lax"
  ]
  plug Plug.Session, @session_options
  plug :fetch_session

  plug Plug.Parsers,
    parsers: [:urlencoded, :json],
    pass: ["*/*"],
    json_decoder: Jason

  plug :match
  plug :dispatch

  # Auto-sign-in the demo user before the OAuth Authorize plug runs
  forward "/oauth/authorize", to: OAuthDemo.AuthorizeWithUser

  # OAuth + well-known metadata
  forward "/oauth/register", to: AshAi.Oauth.Register, init_opts: [otp_app: :ash_ai]
  forward "/oauth/token", to: AshAi.Oauth.Token, init_opts: [otp_app: :ash_ai]
  forward "/oauth/revoke", to: AshAi.Oauth.Revoke, init_opts: [otp_app: :ash_ai]

  forward "/.well-known/oauth-protected-resource",
    to: AshAi.Mcp.Metadata.ProtectedResource,
    init_opts: [otp_app: :ash_ai]

  forward "/.well-known/oauth-authorization-server",
    to: AshAi.Oauth.Metadata.AuthServer,
    init_opts: [otp_app: :ash_ai]

  # Bearer-protected MCP endpoint
  forward "/mcp", to: OAuthDemo.McpPipeline

  match _ do
    send_resp(conn, 404, "not found")
  end
end

# ── Boot ────────────────────────────────────────────────────────────

# Configure AshAi.Oauth at runtime
Application.put_env(:ash_ai, AshAi.Oauth,
  user_resource: OAuthDemo.User,
  client_resource: OAuthDemo.OAuthClient,
  authorization_code_resource: OAuthDemo.OAuthAuthorizationCode,
  refresh_token_resource: OAuthDemo.OAuthRefreshToken,
  consent_resource: OAuthDemo.OAuthConsent,
  issuer_url: "http://localhost:4000",
  canonical_mcp_url: "http://localhost:4000/mcp",
  signing_secret: String.duplicate("d", 64),
  access_token_ttl: {1, :hour},
  refresh_token_ttl: {30, :days},
  authorization_code_ttl: {10, :minutes},
  scopes: ["mcp"]
)

# Seed a demo user
{:ok, user} =
  OAuthDemo.User
  |> Ash.Changeset.for_create(:create, %{email: "demo@example.com"})
  |> Ash.create(authorize?: false)

IO.puts("\n" <> String.duplicate("─", 60))
IO.puts("AshAi OAuth 2.1 MCP demo")
IO.puts(String.duplicate("─", 60))
IO.puts("Server:    http://localhost:4000")
IO.puts("MCP URL:   http://localhost:4000/mcp")
IO.puts("Demo user: demo@example.com (id #{user.id})")
IO.puts("")
IO.puts("Try:")
IO.puts("  curl -i http://localhost:4000/mcp -X POST -d '{}'")
IO.puts("  curl http://localhost:4000/.well-known/oauth-protected-resource | jq")
IO.puts("")
IO.puts("Or run: bash examples/test-oauth.sh")
IO.puts(String.duplicate("─", 60) <> "\n")

{:ok, _} = Bandit.start_link(plug: OAuthDemo.Router, port: 4000)

# Keep the script alive
Process.sleep(:infinity)
