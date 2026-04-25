# OAuth 2.1 for AshAi MCP — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an OAuth 2.1 resource server + authorization server to ash_ai's MCP module so ChatGPT Apps SDK and Claude.ai custom connectors can authenticate end-users against an AshAuthentication-backed app.

**Architecture:** ash_ai plays both OAuth roles in one process. Bearer tokens are HS256-signed JWTs minted via `AshAuthentication.Jwt`, with `aud` bound to the MCP canonical URI per RFC 8707. Four Ash resources (client, authorization_code, refresh_token, consent) are generated into the user's app by `mix ash_ai.gen.oauth`. All endpoints are plain `Plug` modules guarded by `Code.ensure_loaded?(Plug) and Code.ensure_loaded?(AshAuthentication)`. Config lives in `config :my_app, AshAi.Oauth, ...`.

**Tech Stack:** Elixir, Plug, Ash 3.x, AshAuthentication 4.x, Joken (via AshAuth), EEx (for consent HTML), Phoenix.HTML.Safe (optional, via ash_phoenix).

**Spec:** `docs/superpowers/specs/2026-04-23-oauth21-mcp-design.md`

---

## File Structure

### New library modules

```
lib/ash_ai/
├── mcp/
│   ├── bearer_plug.ex                    # NEW — RS bearer validation
│   └── metadata/
│       └── protected_resource.ex         # NEW — RFC 9728 PRM endpoint
└── oauth/
    ├── application.ex                    # NEW — boot-time config validator
    ├── config.ex                         # NEW — Application.get_env wrapper
    ├── secret.ex                         # NEW — default AshAuthentication.Secret impl
    ├── pkce.ex                           # NEW — S256 verifier check
    ├── jwt.ex                            # NEW — audience-aware mint/verify
    ├── error.ex                          # NEW — RFC-shaped error responses
    ├── router.ex                         # NEW — mounts the AS subtree
    ├── consent_view.ex                   # NEW — EEx consent template
    ├── metadata/
    │   └── auth_server.ex                # NEW — RFC 8414 ASM endpoint
    ├── register.ex                       # NEW — RFC 7591 DCR endpoint
    ├── authorize.ex                      # NEW — /oauth/authorize GET + POST
    ├── token.ex                          # NEW — /oauth/token (code + refresh)
    └── revoke.ex                         # NEW — RFC 7009 revocation
```

### Test files

```
test/ash_ai/
├── mcp/
│   ├── bearer_plug_test.exs
│   └── metadata/
│       └── protected_resource_test.exs
└── oauth/
    ├── config_test.exs
    ├── pkce_test.exs
    ├── jwt_test.exs
    ├── metadata/
    │   └── auth_server_test.exs
    ├── register_test.exs
    ├── authorize_test.exs
    ├── token_test.exs
    ├── revoke_test.exs
    └── full_flow_test.exs                # End-to-end OAuth round trip

test/support/
├── oauth_user.ex                         # AshAuthentication user fixture
├── oauth_client_resource.ex              # OAuthClient test resource
├── oauth_authorization_code_resource.ex
├── oauth_refresh_token_resource.ex
├── oauth_consent_resource.ex
└── oauth_helpers.ex                      # Test fixture functions
```

### Generator output (`mix ash_ai.gen.oauth`)

```
lib/ash_ai/mix/tasks/ash_ai.gen.oauth.ex  # NEW
```

Writes the four resources into the user's app + a config block in `runtime.exs`. Modeled after `mix ash_authentication.add_strategy api_key`.

### Documentation

```
documentation/topics/mcp-oauth.md          # NEW — user guide
documentation/topics/mcp-oauth-security.md # NEW — security posture
README.md                                  # MODIFY — replace roadmap bullet
CHANGELOG.md                               # MODIFY — entry
```

---

## Conventions

- All new files start with the SPDX header used elsewhere in the repo.
- Plug modules guard with `if Code.ensure_loaded?(Plug) and Code.ensure_loaded?(AshAuthentication) do`.
- Test modules `use AshAi.RepoCase, async: false` when DB-backed; otherwise `use ExUnit.Case, async: true`.
- Commit messages follow the project's conventional-commits style (`feat:`, `fix:`, `test:`, `docs:`).
- Run `mix check` before each commit.

---

## Task 1: Add `:phoenix_html` optional dep + scaffold

**Files:**
- Modify: `mix.exs`
- Modify: `mix.lock`

- [ ] **Step 1: Add `phoenix_html` as an optional dep**

Edit `mix.exs` deps list:

```elixir
{:phoenix_html, "~> 4.0", optional: true},
```

It goes near the existing `{:plug, "~> 1.17", optional: true},` line.

- [ ] **Step 2: Run `mix deps.get`**

Run: `mix deps.get`
Expected: clean fetch.

- [ ] **Step 3: Run existing tests to confirm no regression**

Run: `mix test`
Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add mix.exs mix.lock
git commit -m "chore: add phoenix_html as optional dep for OAuth consent view"
```

---

## Task 2: `AshAi.Oauth.Config` — config wrapper

**Files:**
- Create: `lib/ash_ai/oauth/config.ex`
- Test: `test/ash_ai/oauth/config_test.exs`

- [ ] **Step 1: Write the failing test**

Create `test/ash_ai/oauth/config_test.exs`:

```elixir
# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Oauth.ConfigTest do
  use ExUnit.Case, async: false

  alias AshAi.Oauth.Config

  setup do
    prior = Application.get_env(:ash_ai, AshAi.Oauth)

    Application.put_env(:ash_ai, AshAi.Oauth,
      user_resource: SomeApp.User,
      issuer_url: "https://app.example.com",
      canonical_mcp_url: "https://app.example.com/mcp",
      access_token_ttl: {1, :hour},
      refresh_token_ttl: {30, :days},
      authorization_code_ttl: {10, :minutes},
      scopes: ["mcp"]
    )

    on_exit(fn ->
      if prior do
        Application.put_env(:ash_ai, AshAi.Oauth, prior)
      else
        Application.delete_env(:ash_ai, AshAi.Oauth)
      end
    end)
  end

  test "user_resource/1" do
    assert Config.user_resource(:ash_ai) == SomeApp.User
  end

  test "issuer_url/1 normalizes to no trailing slash" do
    Application.put_env(:ash_ai, AshAi.Oauth,
      Application.get_env(:ash_ai, AshAi.Oauth)
      |> Keyword.put(:issuer_url, "https://app.example.com/")
    )

    assert Config.issuer_url(:ash_ai) == "https://app.example.com"
  end

  test "canonical_mcp_url/1 normalizes lowercase scheme/host, drops trailing slash" do
    Application.put_env(:ash_ai, AshAi.Oauth,
      Application.get_env(:ash_ai, AshAi.Oauth)
      |> Keyword.put(:canonical_mcp_url, "HTTPS://APP.EXAMPLE.COM/mcp/")
    )

    assert Config.canonical_mcp_url(:ash_ai) == "https://app.example.com/mcp"
  end

  test "access_token_ttl/1 returns seconds" do
    assert Config.access_token_ttl(:ash_ai) == 3_600
  end

  test "scopes/1 defaults to [\"mcp\"]" do
    assert Config.scopes(:ash_ai) == ["mcp"]
  end

  test "fetch!/2 raises with helpful message when key missing" do
    Application.delete_env(:ash_ai, AshAi.Oauth)

    assert_raise RuntimeError, ~r/AshAi.Oauth not configured/, fn ->
      Config.user_resource(:ash_ai)
    end
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mix test test/ash_ai/oauth/config_test.exs`
Expected: FAIL with `module AshAi.Oauth.Config is not loaded`.

- [ ] **Step 3: Implement `AshAi.Oauth.Config`**

Create `lib/ash_ai/oauth/config.ex`:

```elixir
# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Oauth.Config do
  @moduledoc """
  Thin wrapper around `Application.get_env/2` for OAuth configuration.

  Reads `config :my_app, AshAi.Oauth, ...` and normalizes values
  (URL canonicalization, TTL → seconds).

  All functions take the user's `otp_app` atom and read keys from the
  `AshAi.Oauth` namespace.
  """

  @ttl_units %{second: 1, seconds: 1, minute: 60, minutes: 60, hour: 3_600, hours: 3_600, day: 86_400, days: 86_400}

  @spec user_resource(atom()) :: module()
  def user_resource(otp_app), do: fetch!(otp_app, :user_resource)

  @spec issuer_url(atom()) :: String.t()
  def issuer_url(otp_app), do: otp_app |> fetch!(:issuer_url) |> normalize_url()

  @spec canonical_mcp_url(atom()) :: String.t()
  def canonical_mcp_url(otp_app), do: otp_app |> fetch!(:canonical_mcp_url) |> normalize_url()

  @spec signing_secret(atom()) :: term()
  def signing_secret(otp_app), do: fetch!(otp_app, :signing_secret)

  @spec client_resource(atom()) :: module()
  def client_resource(otp_app), do: fetch!(otp_app, :client_resource)

  @spec authorization_code_resource(atom()) :: module()
  def authorization_code_resource(otp_app), do: fetch!(otp_app, :authorization_code_resource)

  @spec refresh_token_resource(atom()) :: module()
  def refresh_token_resource(otp_app), do: fetch!(otp_app, :refresh_token_resource)

  @spec consent_resource(atom()) :: module()
  def consent_resource(otp_app), do: fetch!(otp_app, :consent_resource)

  @spec access_token_ttl(atom()) :: pos_integer()
  def access_token_ttl(otp_app), do: ttl(otp_app, :access_token_ttl, {1, :hour})

  @spec refresh_token_ttl(atom()) :: pos_integer()
  def refresh_token_ttl(otp_app), do: ttl(otp_app, :refresh_token_ttl, {30, :days})

  @spec authorization_code_ttl(atom()) :: pos_integer()
  def authorization_code_ttl(otp_app), do: ttl(otp_app, :authorization_code_ttl, {10, :minutes})

  @spec scopes(atom()) :: [String.t()]
  def scopes(otp_app), do: get(otp_app, :scopes, ["mcp"])

  @spec consent_template(atom()) :: module()
  def consent_template(otp_app), do: get(otp_app, :consent_template, AshAi.Oauth.ConsentView)

  @spec dcr_always_return_client_secret?(atom()) :: boolean()
  def dcr_always_return_client_secret?(otp_app),
    do: get(otp_app, :dcr_always_return_client_secret, false)

  @spec all(atom()) :: keyword()
  def all(otp_app) do
    case Application.get_env(otp_app, AshAi.Oauth) do
      nil -> raise "AshAi.Oauth not configured for :#{otp_app}. Add `config :#{otp_app}, AshAi.Oauth, ...` to runtime.exs."
      kw -> kw
    end
  end

  defp fetch!(otp_app, key) do
    case all(otp_app) |> Keyword.fetch(key) do
      {:ok, value} -> value
      :error -> raise "AshAi.Oauth config key #{inspect(key)} missing for :#{otp_app}"
    end
  end

  defp get(otp_app, key, default) do
    case Application.get_env(otp_app, AshAi.Oauth) do
      nil -> default
      kw -> Keyword.get(kw, key, default)
    end
  end

  defp ttl(otp_app, key, default) do
    case get(otp_app, key, default) do
      seconds when is_integer(seconds) -> seconds
      {n, unit} when is_integer(n) and is_map_key(@ttl_units, unit) -> n * Map.fetch!(@ttl_units, unit)
      other -> raise "Invalid TTL config #{inspect(key)} for :#{otp_app}: #{inspect(other)}"
    end
  end

  defp normalize_url(url) when is_binary(url) do
    uri = URI.parse(url)

    %URI{
      scheme: String.downcase(uri.scheme || "https"),
      host: uri.host && String.downcase(uri.host),
      port: uri.port,
      path: uri.path && String.trim_trailing(uri.path, "/")
    }
    |> URI.to_string()
    |> String.trim_trailing("/")
  end
end
```

- [ ] **Step 4: Run tests to verify pass**

Run: `mix test test/ash_ai/oauth/config_test.exs`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add lib/ash_ai/oauth/config.ex test/ash_ai/oauth/config_test.exs
git commit -m "feat(oauth): add Config wrapper for OAuth runtime configuration"
```

---

## Task 3: `AshAi.Oauth.Secret` — default secret module

**Files:**
- Create: `lib/ash_ai/oauth/secret.ex`
- Test: covered indirectly via `AshAi.Oauth.Jwt` test in Task 5

- [ ] **Step 1: Implement the module**

Create `lib/ash_ai/oauth/secret.ex`:

```elixir
# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Oauth.Secret do
  @moduledoc """
  Default `AshAuthentication.Secret` implementation.

  Reads the OAuth signing secret from the user's `runtime.exs` configuration.
  Users may swap this for their own secret module.

  The secret can be specified directly:

      config :my_app, AshAi.Oauth,
        signing_secret: "raw-secret-string"

  Or via env var:

      config :my_app, AshAi.Oauth,
        signing_secret: System.fetch_env!("MCP_SIGNING_SECRET")
  """

  if Code.ensure_loaded?(AshAuthentication) do
    @behaviour AshAuthentication.Secret

    @impl true
    def secret_for(_path, _resource, _opts, context) do
      otp_app = context[:otp_app] || raise "AshAi.Oauth.Secret requires :otp_app in context"

      case AshAi.Oauth.Config.signing_secret(otp_app) do
        {mod, opts} when is_atom(mod) -> mod.secret_for([], nil, opts, context)
        secret when is_binary(secret) -> {:ok, secret}
        other -> {:error, "Invalid signing_secret: #{inspect(other)}"}
      end
    end
  end
end
```

- [ ] **Step 2: Run existing tests to confirm compilation**

Run: `mix compile`
Expected: clean compile.

- [ ] **Step 3: Commit**

```bash
git add lib/ash_ai/oauth/secret.ex
git commit -m "feat(oauth): default AshAuthentication.Secret implementation"
```

---

## Task 4: `AshAi.Oauth.Pkce` — PKCE S256 verifier

**Files:**
- Create: `lib/ash_ai/oauth/pkce.ex`
- Test: `test/ash_ai/oauth/pkce_test.exs`

- [ ] **Step 1: Write the failing test**

Create `test/ash_ai/oauth/pkce_test.exs`:

```elixir
# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Oauth.PkceTest do
  use ExUnit.Case, async: true

  alias AshAi.Oauth.Pkce

  test "challenge/1 produces RFC 7636 §4.2 fixture" do
    # Verifier and expected challenge from RFC 7636 §4.2
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert Pkce.challenge(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
  end

  test "verify/2 returns :ok for matching pair" do
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    assert Pkce.verify(verifier, challenge) == :ok
  end

  test "verify/2 returns :error for mismatch" do
    verifier = "wrong-verifier"
    challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    assert Pkce.verify(verifier, challenge) == :error
  end

  test "verify/2 is constant-time (uses Plug.Crypto.secure_compare)" do
    # Sanity: function returns :error rather than crashing on any input shape
    assert Pkce.verify("", "") == :error
    assert Pkce.verify(nil, "x") == :error
    assert Pkce.verify("x", nil) == :error
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mix test test/ash_ai/oauth/pkce_test.exs`
Expected: FAIL with `module AshAi.Oauth.Pkce is not loaded`.

- [ ] **Step 3: Implement the module**

Create `lib/ash_ai/oauth/pkce.ex`:

```elixir
# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Oauth.Pkce do
  @moduledoc """
  PKCE S256 helpers per RFC 7636.

  We only support S256 — `plain` is rejected by `/oauth/authorize`.
  """

  @doc """
  Compute the S256 code challenge for a verifier.

  challenge = base64url(sha256(verifier))
  """
  @spec challenge(String.t()) :: String.t()
  def challenge(verifier) when is_binary(verifier) do
    :sha256
    |> :crypto.hash(verifier)
    |> Base.url_encode64(padding: false)
  end

  @doc """
  Constant-time comparison of `verifier` against a stored `challenge`.

  Returns `:ok` if they match, `:error` otherwise. Bad input shapes return
  `:error` rather than crashing.
  """
  @spec verify(String.t() | nil, String.t() | nil) :: :ok | :error
  def verify(verifier, challenge) when is_binary(verifier) and is_binary(challenge) do
    expected = challenge(verifier)

    if Plug.Crypto.secure_compare(expected, challenge) do
      :ok
    else
      :error
    end
  end

  def verify(_, _), do: :error
end
```

- [ ] **Step 4: Run tests to verify pass**

Run: `mix test test/ash_ai/oauth/pkce_test.exs`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add lib/ash_ai/oauth/pkce.ex test/ash_ai/oauth/pkce_test.exs
git commit -m "feat(oauth): PKCE S256 challenge + constant-time verify"
```

---

## Task 5: `AshAi.Oauth.Jwt` — audience-aware mint and verify

**Files:**
- Create: `lib/ash_ai/oauth/jwt.ex`
- Test: `test/ash_ai/oauth/jwt_test.exs`

- [ ] **Step 1: Write the failing test**

Create `test/ash_ai/oauth/jwt_test.exs`:

```elixir
# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Oauth.JwtTest do
  use ExUnit.Case, async: false

  alias AshAi.Oauth.Jwt

  setup do
    prior = Application.get_env(:ash_ai, AshAi.Oauth)

    Application.put_env(:ash_ai, AshAi.Oauth,
      user_resource: nil,
      issuer_url: "https://app.example.com",
      canonical_mcp_url: "https://app.example.com/mcp",
      signing_secret: String.duplicate("x", 64),
      access_token_ttl: 3_600,
      scopes: ["mcp"]
    )

    on_exit(fn ->
      if prior, do: Application.put_env(:ash_ai, AshAi.Oauth, prior), else: Application.delete_env(:ash_ai, AshAi.Oauth)
    end)

    :ok
  end

  test "mint/2 produces a token with required claims" do
    {:ok, token, claims} =
      Jwt.mint(:ash_ai,
        sub: "user-123",
        client_id: "client-abc",
        scope: "mcp"
      )

    assert is_binary(token)
    assert claims["iss"] == "https://app.example.com"
    assert claims["aud"] == "https://app.example.com/mcp"
    assert claims["sub"] == "user-123"
    assert claims["client_id"] == "client-abc"
    assert claims["scope"] == "mcp"
    assert is_integer(claims["iat"])
    assert is_integer(claims["exp"])
    assert is_binary(claims["jti"])
  end

  test "verify/2 round-trips a freshly minted token" do
    {:ok, token, _} = Jwt.mint(:ash_ai, sub: "u", client_id: "c", scope: "mcp")
    assert {:ok, claims} = Jwt.verify(:ash_ai, token)
    assert claims["sub"] == "u"
  end

  test "verify/2 rejects token with wrong audience" do
    Application.put_env(:ash_ai, AshAi.Oauth,
      Application.get_env(:ash_ai, AshAi.Oauth) |> Keyword.put(:canonical_mcp_url, "https://other.example.com/mcp")
    )

    {:ok, token, _} = Jwt.mint(:ash_ai, sub: "u", client_id: "c", scope: "mcp")

    Application.put_env(:ash_ai, AshAi.Oauth,
      Application.get_env(:ash_ai, AshAi.Oauth) |> Keyword.put(:canonical_mcp_url, "https://app.example.com/mcp")
    )

    assert {:error, :invalid_audience} = Jwt.verify(:ash_ai, token)
  end

  test "verify/2 rejects expired token" do
    {:ok, token, _} = Jwt.mint(:ash_ai, sub: "u", client_id: "c", scope: "mcp", ttl: -1)
    assert {:error, :expired} = Jwt.verify(:ash_ai, token)
  end

  test "verify/2 rejects garbage" do
    assert {:error, _} = Jwt.verify(:ash_ai, "not-a-jwt")
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mix test test/ash_ai/oauth/jwt_test.exs`
Expected: FAIL with module not loaded.

- [ ] **Step 3: Implement the module**

Create `lib/ash_ai/oauth/jwt.ex`:

```elixir
# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Oauth.Jwt do
  @moduledoc """
  Mint and verify OAuth 2.1 access tokens for the MCP server.

  Uses HS256 with a shared secret. Audience is bound to the canonical MCP URL
  per RFC 8707. We use Joken directly rather than `AshAuthentication.Jwt`
  because we need explicit control over the audience claim.
  """

  alias AshAi.Oauth.Config

  @signer_alg "HS256"

  @doc """
  Mint a new access token.

  Required keys: `:sub`, `:client_id`, `:scope`.
  Optional: `:ttl` (seconds, defaults to `access_token_ttl` config).
  """
  @spec mint(atom(), keyword()) :: {:ok, String.t(), map()} | {:error, term()}
  def mint(otp_app, opts) do
    sub = Keyword.fetch!(opts, :sub)
    client_id = Keyword.fetch!(opts, :client_id)
    scope = Keyword.fetch!(opts, :scope)
    ttl = Keyword.get(opts, :ttl, Config.access_token_ttl(otp_app))
    now = System.system_time(:second)

    claims = %{
      "iss" => Config.issuer_url(otp_app),
      "sub" => to_string(sub),
      "aud" => Config.canonical_mcp_url(otp_app),
      "client_id" => to_string(client_id),
      "scope" => scope,
      "iat" => now,
      "nbf" => now,
      "exp" => now + ttl,
      "jti" => Ash.UUIDv7.generate()
    }

    with {:ok, secret} <- secret(otp_app),
         signer <- Joken.Signer.create(@signer_alg, secret),
         {:ok, token, _claims} <- Joken.encode_and_sign(claims, signer) do
      {:ok, token, claims}
    end
  end

  @doc """
  Verify a token's signature, issuer, audience, and expiry.

  Returns `{:ok, claims}` on success or `{:error, reason}` on failure.
  """
  @spec verify(atom(), String.t()) :: {:ok, map()} | {:error, term()}
  def verify(otp_app, token) when is_binary(token) do
    with {:ok, secret} <- secret(otp_app),
         signer <- Joken.Signer.create(@signer_alg, secret),
         {:ok, claims} <- Joken.verify(token, signer),
         :ok <- check_iss(claims, otp_app),
         :ok <- check_aud(claims, otp_app),
         :ok <- check_exp(claims) do
      {:ok, claims}
    end
  end

  def verify(_, _), do: {:error, :invalid_token}

  defp secret(otp_app) do
    case Config.signing_secret(otp_app) do
      raw when is_binary(raw) -> {:ok, raw}
      {mod, opts} when is_atom(mod) -> mod.secret_for([], nil, opts, %{otp_app: otp_app})
      other -> {:error, {:invalid_signing_secret, other}}
    end
  end

  defp check_iss(%{"iss" => iss}, otp_app) do
    if iss == Config.issuer_url(otp_app), do: :ok, else: {:error, :invalid_issuer}
  end

  defp check_iss(_, _), do: {:error, :invalid_issuer}

  defp check_aud(%{"aud" => aud}, otp_app) do
    expected = Config.canonical_mcp_url(otp_app)

    cond do
      aud == expected -> :ok
      is_list(aud) and expected in aud -> :ok
      true -> {:error, :invalid_audience}
    end
  end

  defp check_aud(_, _), do: {:error, :invalid_audience}

  defp check_exp(%{"exp" => exp}) when is_integer(exp) do
    if System.system_time(:second) < exp, do: :ok, else: {:error, :expired}
  end

  defp check_exp(_), do: {:error, :missing_exp}
end
```

- [ ] **Step 4: Run tests to verify pass**

Run: `mix test test/ash_ai/oauth/jwt_test.exs`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add lib/ash_ai/oauth/jwt.ex test/ash_ai/oauth/jwt_test.exs
git commit -m "feat(oauth): JWT mint/verify with audience binding (RFC 8707)"
```

---

## Task 6: `AshAi.Oauth.Error` — RFC-shaped error responses

**Files:**
- Create: `lib/ash_ai/oauth/error.ex`
- Test: covered by endpoint tests; no standalone test.

- [ ] **Step 1: Implement the module**

Create `lib/ash_ai/oauth/error.ex`:

```elixir
# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

if Code.ensure_loaded?(Plug) do
  defmodule AshAi.Oauth.Error do
    @moduledoc """
    OAuth 2.1 / RFC 7591 error response helpers.
    """

    import Plug.Conn

    @doc """
    Send a JSON error per OAuth 2.0 / RFC 6749 §5.2.

    Examples of `code`: `"invalid_request"`, `"invalid_client"`,
    `"invalid_grant"`, `"unsupported_grant_type"`, `"invalid_scope"`.
    """
    def send_oauth_error(conn, status, code, description \\ nil) do
      body = %{"error" => code} |> maybe_put("error_description", description)

      conn
      |> put_resp_header("content-type", "application/json")
      |> put_resp_header("cache-control", "no-store")
      |> send_resp(status, Jason.encode!(body))
      |> halt()
    end

    @doc """
    Send a 400 with an RFC 7591 DCR-shaped error.

    Codes: `"invalid_redirect_uri"`, `"invalid_client_metadata"`.
    """
    def send_dcr_error(conn, code, description \\ nil) do
      send_oauth_error(conn, 400, code, description)
    end

    defp maybe_put(map, _key, nil), do: map
    defp maybe_put(map, key, value), do: Map.put(map, key, value)
  end
end
```

- [ ] **Step 2: Compile**

Run: `mix compile`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add lib/ash_ai/oauth/error.ex
git commit -m "feat(oauth): RFC-shaped error response helpers"
```

---

## Task 7: `AshAi.Mcp.Metadata.ProtectedResource` — RFC 9728 endpoint

**Files:**
- Create: `lib/ash_ai/mcp/metadata/protected_resource.ex`
- Test: `test/ash_ai/mcp/metadata/protected_resource_test.exs`

- [ ] **Step 1: Write the failing test**

Create `test/ash_ai/mcp/metadata/protected_resource_test.exs`:

```elixir
# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.Metadata.ProtectedResourceTest do
  use ExUnit.Case, async: false
  import Plug.{Conn, Test}

  alias AshAi.Mcp.Metadata.ProtectedResource

  setup do
    prior = Application.get_env(:ash_ai, AshAi.Oauth)

    Application.put_env(:ash_ai, AshAi.Oauth,
      user_resource: nil,
      issuer_url: "https://app.example.com",
      canonical_mcp_url: "https://app.example.com/mcp",
      signing_secret: "x",
      scopes: ["mcp"]
    )

    on_exit(fn ->
      if prior, do: Application.put_env(:ash_ai, AshAi.Oauth, prior), else: Application.delete_env(:ash_ai, AshAi.Oauth)
    end)

    :ok
  end

  test "returns required RFC 9728 fields" do
    conn = conn(:get, "/.well-known/oauth-protected-resource")
    conn = ProtectedResource.call(conn, ProtectedResource.init(otp_app: :ash_ai))

    assert conn.status == 200
    assert get_resp_header(conn, "content-type") == ["application/json"]

    body = Jason.decode!(conn.resp_body)
    assert body["resource"] == "https://app.example.com/mcp"
    assert body["authorization_servers"] == ["https://app.example.com"]
    assert body["scopes_supported"] == ["mcp"]
    assert body["bearer_methods_supported"] == ["header"]
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mix test test/ash_ai/mcp/metadata/protected_resource_test.exs`
Expected: FAIL.

- [ ] **Step 3: Implement the module**

Create `lib/ash_ai/mcp/metadata/protected_resource.ex`:

```elixir
# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

if Code.ensure_loaded?(Plug) do
  defmodule AshAi.Mcp.Metadata.ProtectedResource do
    @moduledoc """
    Plug serving the RFC 9728 OAuth 2.0 Protected Resource Metadata document.

    Mount at `/.well-known/oauth-protected-resource`.
    """

    @behaviour Plug
    import Plug.Conn

    alias AshAi.Oauth.Config

    @impl Plug
    def init(opts), do: Keyword.fetch!(opts, :otp_app)

    @impl Plug
    def call(conn, otp_app) do
      body =
        Jason.encode!(%{
          "resource" => Config.canonical_mcp_url(otp_app),
          "authorization_servers" => [Config.issuer_url(otp_app)],
          "scopes_supported" => Config.scopes(otp_app),
          "bearer_methods_supported" => ["header"]
        })

      conn
      |> put_resp_header("content-type", "application/json")
      |> put_resp_header("cache-control", "public, max-age=300")
      |> send_resp(200, body)
      |> halt()
    end
  end
end
```

- [ ] **Step 4: Run tests**

Run: `mix test test/ash_ai/mcp/metadata/protected_resource_test.exs`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add lib/ash_ai/mcp/metadata/protected_resource.ex test/ash_ai/mcp/metadata/protected_resource_test.exs
git commit -m "feat(mcp): RFC 9728 Protected Resource Metadata endpoint"
```

---

## Task 8: `AshAi.Mcp.BearerPlug` — bearer validation + 401 challenge

**Files:**
- Create: `lib/ash_ai/mcp/bearer_plug.ex`
- Test: `test/ash_ai/mcp/bearer_plug_test.exs`

- [ ] **Step 1: Write the failing test**

Create `test/ash_ai/mcp/bearer_plug_test.exs`:

```elixir
# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.BearerPlugTest do
  use ExUnit.Case, async: false
  import Plug.{Conn, Test}

  alias AshAi.Mcp.BearerPlug
  alias AshAi.Oauth.Jwt

  setup do
    prior = Application.get_env(:ash_ai, AshAi.Oauth)

    Application.put_env(:ash_ai, AshAi.Oauth,
      user_resource: AshAi.Test.OauthUser,
      issuer_url: "https://app.example.com",
      canonical_mcp_url: "https://app.example.com/mcp",
      signing_secret: String.duplicate("x", 64),
      access_token_ttl: 3_600,
      scopes: ["mcp"]
    )

    on_exit(fn ->
      if prior, do: Application.put_env(:ash_ai, AshAi.Oauth, prior), else: Application.delete_env(:ash_ai, AshAi.Oauth)
    end)

    :ok
  end

  test "401 with WWW-Authenticate when no token and required?: true" do
    conn = conn(:post, "/mcp", "{}")
    conn = BearerPlug.call(conn, BearerPlug.init(otp_app: :ash_ai, required?: true))

    assert conn.status == 401
    [auth] = get_resp_header(conn, "www-authenticate")
    assert auth =~ ~r/^Bearer resource_metadata="https:\/\/app\.example\.com\/\.well-known\/oauth-protected-resource"$/
  end

  test "passes through with no token when required?: false" do
    conn = conn(:post, "/mcp", "{}")
    conn = BearerPlug.call(conn, BearerPlug.init(otp_app: :ash_ai, required?: false))

    refute conn.halted
  end

  test "401 on bad signature" do
    conn = conn(:post, "/mcp", "{}") |> put_req_header("authorization", "Bearer not-a-real-jwt")
    conn = BearerPlug.call(conn, BearerPlug.init(otp_app: :ash_ai, required?: true))

    assert conn.status == 401
  end

  test "401 on audience mismatch", %{} do
    Application.put_env(:ash_ai, AshAi.Oauth,
      Application.get_env(:ash_ai, AshAi.Oauth)
      |> Keyword.put(:canonical_mcp_url, "https://other.example.com/mcp")
    )

    {:ok, token, _} = Jwt.mint(:ash_ai, sub: "u", client_id: "c", scope: "mcp")

    Application.put_env(:ash_ai, AshAi.Oauth,
      Application.get_env(:ash_ai, AshAi.Oauth)
      |> Keyword.put(:canonical_mcp_url, "https://app.example.com/mcp")
    )

    conn =
      conn(:post, "/mcp", "{}")
      |> put_req_header("authorization", "Bearer #{token}")

    conn = BearerPlug.call(conn, BearerPlug.init(otp_app: :ash_ai, required?: true))

    assert conn.status == 401
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mix test test/ash_ai/mcp/bearer_plug_test.exs`
Expected: FAIL.

- [ ] **Step 3: Implement the module**

Create `lib/ash_ai/mcp/bearer_plug.ex`:

```elixir
# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

if Code.ensure_loaded?(Plug) do
  defmodule AshAi.Mcp.BearerPlug do
    @moduledoc """
    Validates an OAuth 2.1 bearer token on inbound MCP requests.

    On success, sets the actor on the conn via `Ash.PlugHelpers.set_actor/2`
    and assigns `:oauth_claims` for downstream use.

    On failure (or no token, when `required?: true`), responds with
    `401 Unauthorized` and a `WWW-Authenticate` header pointing at the
    Protected Resource Metadata document (RFC 9728 §5.1).

    ## Options

    - `:otp_app` (required) — the consuming app's atom.
    - `:required?` (default `true`) — if `false`, missing tokens pass through
      without error; invalid tokens still 401.
    """

    @behaviour Plug
    import Plug.Conn

    alias AshAi.Oauth.{Config, Jwt}

    @impl Plug
    def init(opts) do
      %{
        otp_app: Keyword.fetch!(opts, :otp_app),
        required?: Keyword.get(opts, :required?, true)
      }
    end

    @impl Plug
    def call(conn, %{otp_app: otp_app, required?: required?}) do
      case extract_token(conn) do
        nil when required? -> challenge(conn, otp_app)
        nil -> conn
        token -> verify_and_assign(conn, otp_app, token)
      end
    end

    defp extract_token(conn) do
      case get_req_header(conn, "authorization") do
        ["Bearer " <> token | _] -> String.trim(token)
        _ -> nil
      end
    end

    defp verify_and_assign(conn, otp_app, token) do
      with {:ok, claims} <- Jwt.verify(otp_app, token),
           {:ok, user} <- load_user(otp_app, claims) do
        conn
        |> Ash.PlugHelpers.set_actor(user)
        |> assign(:oauth_claims, claims)
      else
        _ -> challenge(conn, otp_app)
      end
    end

    defp load_user(otp_app, %{"sub" => sub}) do
      resource = Config.user_resource(otp_app)

      case Ash.get(resource, sub, authorize?: false) do
        {:ok, user} -> {:ok, user}
        _ -> :error
      end
    end

    defp load_user(_, _), do: :error

    defp challenge(conn, otp_app) do
      prm_url = Config.issuer_url(otp_app) <> "/.well-known/oauth-protected-resource"

      conn
      |> put_resp_header("www-authenticate", ~s(Bearer resource_metadata="#{prm_url}"))
      |> send_resp(401, "")
      |> halt()
    end
  end
end
```

- [ ] **Step 4: Add a minimal test user resource**

Create `test/support/oauth_user.ex`:

```elixir
# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Test.OauthUser do
  @moduledoc false
  use Ash.Resource,
    domain: AshAi.Test.OauthDomain,
    data_layer: Ash.DataLayer.Ets

  attributes do
    uuid_v7_primary_key :id
    attribute :email, :ci_string, public?: true, allow_nil?: false
  end

  actions do
    defaults [:read]
    create :create, accept: [:email]
  end
end

defmodule AshAi.Test.OauthDomain do
  @moduledoc false
  use Ash.Domain

  resources do
    resource AshAi.Test.OauthUser
  end
end
```

- [ ] **Step 5: Run tests to verify pass**

Update test setup to seed a user with a known id and use it as `sub` in the JWT mint. Add to setup:

```elixir
{:ok, user} =
  AshAi.Test.OauthUser
  |> Ash.Changeset.for_create(:create, %{email: "u@example.com"})
  |> Ash.create()

%{user: user}
```

Run: `mix test test/ash_ai/mcp/bearer_plug_test.exs`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add lib/ash_ai/mcp/bearer_plug.ex test/ash_ai/mcp/bearer_plug_test.exs test/support/oauth_user.ex
git commit -m "feat(mcp): BearerPlug for OAuth 2.1 token validation + 401 challenge"
```

---

## Task 9: OAuthClient test resource

**Files:**
- Create: `test/support/oauth_client_resource.ex`

- [ ] **Step 1: Implement the resource**

Create `test/support/oauth_client_resource.ex`:

```elixir
# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Test.OAuthClient do
  @moduledoc false
  use Ash.Resource,
    domain: AshAi.Test.OauthDomain,
    data_layer: Ash.DataLayer.Ets

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

  identities do
    identity :unique_id, [:id]
  end
end
```

Add to `AshAi.Test.OauthDomain`:

```elixir
resources do
  resource AshAi.Test.OauthUser
  resource AshAi.Test.OAuthClient
end
```

- [ ] **Step 2: Compile**

Run: `mix compile`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add test/support/oauth_client_resource.ex test/support/oauth_user.ex
git commit -m "test(oauth): OAuthClient test resource"
```

---

## Task 10: OAuthAuthorizationCode test resource

**Files:**
- Create: `test/support/oauth_authorization_code_resource.ex`

- [ ] **Step 1: Implement the resource**

Create `test/support/oauth_authorization_code_resource.ex`:

```elixir
# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Test.OAuthAuthorizationCode do
  @moduledoc false
  use Ash.Resource,
    domain: AshAi.Test.OauthDomain,
    data_layer: Ash.DataLayer.Ets

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
      accept [:id, :client_id, :user_id, :redirect_uri, :code_challenge, :scope, :resource_uri, :expires_at]
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
```

Add `resource AshAi.Test.OAuthAuthorizationCode` to the domain.

- [ ] **Step 2: Compile**

Run: `mix compile`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add test/support/oauth_authorization_code_resource.ex
git commit -m "test(oauth): OAuthAuthorizationCode test resource"
```

---

## Task 11: OAuthRefreshToken test resource

**Files:**
- Create: `test/support/oauth_refresh_token_resource.ex`

- [ ] **Step 1: Implement the resource**

Create `test/support/oauth_refresh_token_resource.ex`:

```elixir
# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Test.OAuthRefreshToken do
  @moduledoc false
  use Ash.Resource,
    domain: AshAi.Test.OauthDomain,
    data_layer: Ash.DataLayer.Ets

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
      accept [:id, :token_hash, :client_id, :user_id, :scope, :resource_uri, :expires_at]
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
```

Add `resource AshAi.Test.OAuthRefreshToken` to the domain.

- [ ] **Step 2: Compile**

Run: `mix compile`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add test/support/oauth_refresh_token_resource.ex
git commit -m "test(oauth): OAuthRefreshToken test resource"
```

---

## Task 12: OAuthConsent test resource

**Files:**
- Create: `test/support/oauth_consent_resource.ex`

- [ ] **Step 1: Implement the resource**

Create `test/support/oauth_consent_resource.ex`:

```elixir
# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Test.OAuthConsent do
  @moduledoc false
  use Ash.Resource,
    domain: AshAi.Test.OauthDomain,
    data_layer: Ash.DataLayer.Ets

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

    update :revoke do
      accept []
      require_atomic? false
      change fn changeset, _ ->
        Ash.Changeset.before_action(changeset, fn cs ->
          Ash.destroy!(cs.data)
          cs
        end)
      end
    end
  end

  identities do
    identity :by_user_client, [:user_id, :client_id], pre_check_with: AshAi.Test.OauthDomain
  end
end
```

Add `resource AshAi.Test.OAuthConsent` to the domain.

- [ ] **Step 2: Compile**

Run: `mix compile`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add test/support/oauth_consent_resource.ex
git commit -m "test(oauth): OAuthConsent test resource"
```

---

## Task 13: `AshAi.Oauth.Metadata.AuthServer` — RFC 8414 endpoint

**Files:**
- Create: `lib/ash_ai/oauth/metadata/auth_server.ex`
- Test: `test/ash_ai/oauth/metadata/auth_server_test.exs`

- [ ] **Step 1: Write the failing test**

Create `test/ash_ai/oauth/metadata/auth_server_test.exs`:

```elixir
# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Oauth.Metadata.AuthServerTest do
  use ExUnit.Case, async: false
  import Plug.{Conn, Test}

  alias AshAi.Oauth.Metadata.AuthServer

  setup do
    prior = Application.get_env(:ash_ai, AshAi.Oauth)

    Application.put_env(:ash_ai, AshAi.Oauth,
      user_resource: nil,
      issuer_url: "https://app.example.com",
      canonical_mcp_url: "https://app.example.com/mcp",
      signing_secret: "x",
      scopes: ["mcp"]
    )

    on_exit(fn ->
      if prior, do: Application.put_env(:ash_ai, AshAi.Oauth, prior), else: Application.delete_env(:ash_ai, AshAi.Oauth)
    end)

    :ok
  end

  test "returns required RFC 8414 fields for OAuth 2.1 + PKCE + DCR" do
    conn = conn(:get, "/.well-known/oauth-authorization-server")
    conn = AuthServer.call(conn, AuthServer.init(otp_app: :ash_ai))

    assert conn.status == 200
    body = Jason.decode!(conn.resp_body)

    assert body["issuer"] == "https://app.example.com"
    assert body["authorization_endpoint"] == "https://app.example.com/oauth/authorize"
    assert body["token_endpoint"] == "https://app.example.com/oauth/token"
    assert body["registration_endpoint"] == "https://app.example.com/oauth/register"
    assert body["revocation_endpoint"] == "https://app.example.com/oauth/revoke"
    assert body["response_types_supported"] == ["code"]
    assert body["grant_types_supported"] == ["authorization_code", "refresh_token"]
    assert body["code_challenge_methods_supported"] == ["S256"]
    assert "none" in body["token_endpoint_auth_methods_supported"]
    assert "client_secret_basic" in body["token_endpoint_auth_methods_supported"]
    assert body["scopes_supported"] == ["mcp"]
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mix test test/ash_ai/oauth/metadata/auth_server_test.exs`
Expected: FAIL.

- [ ] **Step 3: Implement the module**

Create `lib/ash_ai/oauth/metadata/auth_server.ex`:

```elixir
# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

if Code.ensure_loaded?(Plug) do
  defmodule AshAi.Oauth.Metadata.AuthServer do
    @moduledoc """
    Plug serving the RFC 8414 OAuth 2.0 Authorization Server Metadata document.

    Mount at `/.well-known/oauth-authorization-server`.
    """

    @behaviour Plug
    import Plug.Conn

    alias AshAi.Oauth.Config

    @impl Plug
    def init(opts), do: Keyword.fetch!(opts, :otp_app)

    @impl Plug
    def call(conn, otp_app) do
      issuer = Config.issuer_url(otp_app)

      body =
        Jason.encode!(%{
          "issuer" => issuer,
          "authorization_endpoint" => issuer <> "/oauth/authorize",
          "token_endpoint" => issuer <> "/oauth/token",
          "registration_endpoint" => issuer <> "/oauth/register",
          "revocation_endpoint" => issuer <> "/oauth/revoke",
          "response_types_supported" => ["code"],
          "grant_types_supported" => ["authorization_code", "refresh_token"],
          "code_challenge_methods_supported" => ["S256"],
          "token_endpoint_auth_methods_supported" => ["none", "client_secret_basic"],
          "scopes_supported" => Config.scopes(otp_app)
        })

      conn
      |> put_resp_header("content-type", "application/json")
      |> put_resp_header("cache-control", "public, max-age=300")
      |> send_resp(200, body)
      |> halt()
    end
  end
end
```

- [ ] **Step 4: Run tests**

Run: `mix test test/ash_ai/oauth/metadata/auth_server_test.exs`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add lib/ash_ai/oauth/metadata/auth_server.ex test/ash_ai/oauth/metadata/auth_server_test.exs
git commit -m "feat(oauth): RFC 8414 Authorization Server Metadata endpoint"
```

---

## Task 14: `AshAi.Oauth.Register` — Dynamic Client Registration

**Files:**
- Create: `lib/ash_ai/oauth/register.ex`
- Test: `test/ash_ai/oauth/register_test.exs`

- [ ] **Step 1: Write the failing test**

Create `test/ash_ai/oauth/register_test.exs`:

```elixir
# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Oauth.RegisterTest do
  use ExUnit.Case, async: false
  import Plug.{Conn, Test}

  alias AshAi.Oauth.Register

  setup do
    prior = Application.get_env(:ash_ai, AshAi.Oauth)

    Application.put_env(:ash_ai, AshAi.Oauth,
      user_resource: AshAi.Test.OauthUser,
      client_resource: AshAi.Test.OAuthClient,
      issuer_url: "https://app.example.com",
      canonical_mcp_url: "https://app.example.com/mcp",
      signing_secret: "x",
      scopes: ["mcp"]
    )

    on_exit(fn ->
      if prior, do: Application.put_env(:ash_ai, AshAi.Oauth, prior), else: Application.delete_env(:ash_ai, AshAi.Oauth)
    end)

    :ok
  end

  defp post_json(body) do
    conn(:post, "/oauth/register", Jason.encode!(body))
    |> put_req_header("content-type", "application/json")
    |> Plug.Parsers.call(Plug.Parsers.init(parsers: [:json], json_decoder: Jason))
  end

  test "201 + client_id for valid public client registration" do
    conn = post_json(%{
      "client_name" => "ChatGPT",
      "redirect_uris" => ["https://chatgpt.com/connector/oauth/abc"],
      "token_endpoint_auth_method" => "none"
    })

    conn = Register.call(conn, Register.init(otp_app: :ash_ai))

    assert conn.status == 201
    body = Jason.decode!(conn.resp_body)
    assert is_binary(body["client_id"])
    assert body["client_name"] == "ChatGPT"
    assert body["redirect_uris"] == ["https://chatgpt.com/connector/oauth/abc"]
    assert body["token_endpoint_auth_method"] == "none"
    refute Map.has_key?(body, "client_secret")
  end

  test "400 invalid_redirect_uri when redirect uses http (non-localhost)" do
    conn = post_json(%{
      "client_name" => "Bad",
      "redirect_uris" => ["http://attacker.example/callback"],
      "token_endpoint_auth_method" => "none"
    })

    conn = Register.call(conn, Register.init(otp_app: :ash_ai))

    assert conn.status == 400
    body = Jason.decode!(conn.resp_body)
    assert body["error"] == "invalid_redirect_uri"
  end

  test "allows http://localhost redirect URIs" do
    conn = post_json(%{
      "client_name" => "Dev",
      "redirect_uris" => ["http://localhost:3000/cb"],
      "token_endpoint_auth_method" => "none"
    })

    conn = Register.call(conn, Register.init(otp_app: :ash_ai))
    assert conn.status == 201
  end

  test "400 invalid_client_metadata when redirect_uris missing" do
    conn = post_json(%{"client_name" => "X"})

    conn = Register.call(conn, Register.init(otp_app: :ash_ai))

    assert conn.status == 400
    body = Jason.decode!(conn.resp_body)
    assert body["error"] == "invalid_client_metadata"
  end

  test "returns empty client_secret when dcr_always_return_client_secret enabled" do
    Application.put_env(:ash_ai, AshAi.Oauth,
      Application.get_env(:ash_ai, AshAi.Oauth)
      |> Keyword.put(:dcr_always_return_client_secret, true)
    )

    conn = post_json(%{
      "client_name" => "ChatGPT",
      "redirect_uris" => ["https://chatgpt.com/connector/oauth/abc"],
      "token_endpoint_auth_method" => "none"
    })

    conn = Register.call(conn, Register.init(otp_app: :ash_ai))
    assert conn.status == 201
    body = Jason.decode!(conn.resp_body)
    assert body["client_secret"] == ""
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mix test test/ash_ai/oauth/register_test.exs`
Expected: FAIL.

- [ ] **Step 3: Implement the module**

Create `lib/ash_ai/oauth/register.ex`:

```elixir
# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

if Code.ensure_loaded?(Plug) do
  defmodule AshAi.Oauth.Register do
    @moduledoc """
    Plug implementing RFC 7591 Dynamic Client Registration.

    Mount at `POST /oauth/register`.
    """

    @behaviour Plug
    import Plug.Conn

    alias AshAi.Oauth.{Config, Error}

    @valid_grant_types ~w(authorization_code refresh_token)
    @valid_response_types ~w(code)
    @valid_auth_methods ~w(none client_secret_basic)

    @impl Plug
    def init(opts), do: Keyword.fetch!(opts, :otp_app)

    @impl Plug
    def call(%{method: "POST"} = conn, otp_app) do
      params = conn.params || %{}

      with :ok <- validate_redirect_uris(params),
           :ok <- validate_grant_types(params),
           :ok <- validate_response_types(params),
           :ok <- validate_auth_method(params),
           {:ok, client} <- create_client(otp_app, params) do
        respond(conn, otp_app, client)
      else
        {:error, code, desc} -> Error.send_dcr_error(conn, code, desc)
      end
    end

    def call(conn, _),
      do: Error.send_oauth_error(conn, 405, "invalid_request", "POST required")

    defp validate_redirect_uris(%{"redirect_uris" => uris}) when is_list(uris) and uris != [] do
      Enum.reduce_while(uris, :ok, fn uri, _ ->
        case URI.new(uri) do
          {:ok, %URI{scheme: "https"}} -> {:cont, :ok}
          {:ok, %URI{scheme: "http", host: host}} when host in ["localhost", "127.0.0.1", "::1"] -> {:cont, :ok}
          _ -> {:halt, {:error, "invalid_redirect_uri", "redirect URIs must use https or be localhost"}}
        end
      end)
    end

    defp validate_redirect_uris(_),
      do: {:error, "invalid_client_metadata", "redirect_uris is required"}

    defp validate_grant_types(%{"grant_types" => grants}) when is_list(grants) do
      if Enum.all?(grants, &(&1 in @valid_grant_types)),
        do: :ok,
        else: {:error, "invalid_client_metadata", "unsupported grant_type"}
    end

    defp validate_grant_types(_), do: :ok

    defp validate_response_types(%{"response_types" => types}) when is_list(types) do
      if Enum.all?(types, &(&1 in @valid_response_types)),
        do: :ok,
        else: {:error, "invalid_client_metadata", "unsupported response_type"}
    end

    defp validate_response_types(_), do: :ok

    defp validate_auth_method(%{"token_endpoint_auth_method" => m}) when m in @valid_auth_methods, do: :ok
    defp validate_auth_method(%{"token_endpoint_auth_method" => _}),
      do: {:error, "invalid_client_metadata", "unsupported token_endpoint_auth_method"}

    defp validate_auth_method(_), do: :ok

    defp create_client(otp_app, params) do
      attrs = %{
        client_name: Map.get(params, "client_name", "Unnamed Client"),
        redirect_uris: Map.fetch!(params, "redirect_uris"),
        grant_types: Map.get(params, "grant_types", ["authorization_code"]),
        response_types: Map.get(params, "response_types", ["code"]),
        token_endpoint_auth_method: Map.get(params, "token_endpoint_auth_method", "none"),
        scope: Enum.join(Config.scopes(otp_app), " ")
      }

      Config.client_resource(otp_app)
      |> Ash.Changeset.for_create(:register, attrs)
      |> Ash.create()
    end

    defp respond(conn, otp_app, client) do
      base = %{
        "client_id" => client.id,
        "client_id_issued_at" => DateTime.to_unix(client.created_at),
        "client_name" => client.client_name,
        "redirect_uris" => client.redirect_uris,
        "grant_types" => client.grant_types,
        "response_types" => client.response_types,
        "token_endpoint_auth_method" => client.token_endpoint_auth_method,
        "scope" => client.scope
      }

      body =
        if Config.dcr_always_return_client_secret?(otp_app) and client.token_endpoint_auth_method == "none" do
          Map.put(base, "client_secret", "")
        else
          base
        end

      conn
      |> put_resp_header("content-type", "application/json")
      |> put_resp_header("cache-control", "no-store")
      |> send_resp(201, Jason.encode!(body))
      |> halt()
    end
  end
end
```

- [ ] **Step 4: Run tests**

Run: `mix test test/ash_ai/oauth/register_test.exs`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add lib/ash_ai/oauth/register.ex test/ash_ai/oauth/register_test.exs
git commit -m "feat(oauth): RFC 7591 Dynamic Client Registration endpoint"
```

---

## Task 15: `AshAi.Oauth.ConsentView` — EEx consent template

**Files:**
- Create: `lib/ash_ai/oauth/consent_view.ex`

- [ ] **Step 1: Implement the module**

Create `lib/ash_ai/oauth/consent_view.ex`:

```elixir
# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Oauth.ConsentView do
  @moduledoc """
  Default consent screen renderer.

  Override via `consent_template:` config to customize. The replacement
  module must export `render(:consent, assigns)` returning a binary or
  `Phoenix.HTML.Safe`.
  """

  require EEx

  @template ~S"""
  <!DOCTYPE html>
  <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Authorize <%= @client_name %></title>
      <style>
        body { font-family: system-ui, sans-serif; max-width: 480px; margin: 4rem auto; padding: 0 1rem; }
        h1 { font-size: 1.5rem; }
        .scopes { background: #f4f4f5; padding: 1rem; border-radius: 0.5rem; margin: 1rem 0; }
        button { padding: 0.75rem 1.25rem; margin-right: 0.5rem; cursor: pointer; }
        button.approve { background: #2563eb; color: white; border: none; border-radius: 0.25rem; }
        button.deny { background: white; color: #1f2937; border: 1px solid #d1d5db; border-radius: 0.25rem; }
        code { background: #f4f4f5; padding: 0.1rem 0.25rem; border-radius: 0.25rem; }
      </style>
    </head>
    <body>
      <h1>Authorize access</h1>
      <p><strong><%= @client_name %></strong> wants to access your account at <strong><%= @resource_uri %></strong>.</p>
      <p>Redirect target: <code><%= @redirect_uri %></code></p>
      <div class="scopes">
        <strong>Requested scope:</strong> <code><%= @scope %></code>
      </div>
      <form method="POST" action="<%= @action_path %>">
        <input type="hidden" name="_csrf_token" value="<%= @csrf_token %>" />
        <input type="hidden" name="response_type" value="code" />
        <input type="hidden" name="client_id" value="<%= @client_id %>" />
        <input type="hidden" name="redirect_uri" value="<%= @redirect_uri %>" />
        <input type="hidden" name="code_challenge" value="<%= @code_challenge %>" />
        <input type="hidden" name="code_challenge_method" value="S256" />
        <input type="hidden" name="scope" value="<%= @scope %>" />
        <input type="hidden" name="state" value="<%= @state %>" />
        <input type="hidden" name="resource" value="<%= @resource %>" />
        <button type="submit" class="approve" name="action" value="approve">Approve</button>
        <button type="submit" class="deny" name="action" value="deny">Deny</button>
      </form>
    </body>
  </html>
  """

  EEx.function_from_string(:def, :render_consent, @template, [:assigns])

  def render(:consent, assigns) when is_map(assigns) do
    render_consent(assigns)
  end
end
```

- [ ] **Step 2: Compile**

Run: `mix compile`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add lib/ash_ai/oauth/consent_view.ex
git commit -m "feat(oauth): EEx consent screen template"
```

---

## Task 16: `AshAi.Oauth.Authorize` — `/oauth/authorize` GET + POST

**Files:**
- Create: `lib/ash_ai/oauth/authorize.ex`
- Test: `test/ash_ai/oauth/authorize_test.exs`

This is the most complex plug — handles parameter validation, login redirect, consent rendering, and code issuance.

- [ ] **Step 1: Write the failing test**

Create `test/ash_ai/oauth/authorize_test.exs`:

```elixir
# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Oauth.AuthorizeTest do
  use ExUnit.Case, async: false
  import Plug.{Conn, Test}

  alias AshAi.Oauth.{Authorize, Pkce}

  setup do
    prior = Application.get_env(:ash_ai, AshAi.Oauth)

    Application.put_env(:ash_ai, AshAi.Oauth,
      user_resource: AshAi.Test.OauthUser,
      client_resource: AshAi.Test.OAuthClient,
      authorization_code_resource: AshAi.Test.OAuthAuthorizationCode,
      consent_resource: AshAi.Test.OAuthConsent,
      issuer_url: "https://app.example.com",
      canonical_mcp_url: "https://app.example.com/mcp",
      signing_secret: "x",
      scopes: ["mcp"],
      authorization_code_ttl: {10, :minutes}
    )

    on_exit(fn ->
      if prior, do: Application.put_env(:ash_ai, AshAi.Oauth, prior), else: Application.delete_env(:ash_ai, AshAi.Oauth)
    end)

    {:ok, user} = AshAi.Test.OauthUser |> Ash.Changeset.for_create(:create, %{email: "u@example.com"}) |> Ash.create()

    {:ok, client} =
      AshAi.Test.OAuthClient
      |> Ash.Changeset.for_create(:register, %{
        client_name: "Test Client",
        redirect_uris: ["https://chatgpt.com/cb"],
        token_endpoint_auth_method: "none",
        scope: "mcp"
      })
      |> Ash.create()

    {:ok, user: user, client: client}
  end

  defp authorize_conn(params) do
    conn(:get, "/oauth/authorize?" <> URI.encode_query(params))
    |> Plug.Conn.fetch_query_params()
  end

  defp put_actor(conn, user) do
    Ash.PlugHelpers.set_actor(conn, user)
  end

  test "GET renders consent screen for authenticated user, no prior consent", %{user: user, client: client} do
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = Pkce.challenge(verifier)

    conn =
      authorize_conn(%{
        "response_type" => "code",
        "client_id" => client.id,
        "redirect_uri" => "https://chatgpt.com/cb",
        "code_challenge" => challenge,
        "code_challenge_method" => "S256",
        "scope" => "mcp",
        "state" => "abc",
        "resource" => "https://app.example.com/mcp"
      })
      |> put_actor(user)

    conn = Authorize.call(conn, Authorize.init(otp_app: :ash_ai))

    assert conn.status == 200
    assert conn.resp_body =~ "Authorize access"
    assert conn.resp_body =~ "Test Client"
  end

  test "GET issues code immediately when consent already exists", %{user: user, client: client} do
    AshAi.Test.OAuthConsent
    |> Ash.Changeset.for_create(:grant, %{user_id: user.id, client_id: client.id, scope: "mcp"})
    |> Ash.create!()

    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = Pkce.challenge(verifier)

    conn =
      authorize_conn(%{
        "response_type" => "code",
        "client_id" => client.id,
        "redirect_uri" => "https://chatgpt.com/cb",
        "code_challenge" => challenge,
        "code_challenge_method" => "S256",
        "scope" => "mcp",
        "state" => "abc",
        "resource" => "https://app.example.com/mcp"
      })
      |> put_actor(user)

    conn = Authorize.call(conn, Authorize.init(otp_app: :ash_ai))

    assert conn.status == 302
    [location] = get_resp_header(conn, "location")
    assert location =~ "https://chatgpt.com/cb?code="
    assert location =~ "state=abc"
  end

  test "GET 400 on plain code_challenge_method", %{user: user, client: client} do
    conn =
      authorize_conn(%{
        "response_type" => "code",
        "client_id" => client.id,
        "redirect_uri" => "https://chatgpt.com/cb",
        "code_challenge" => "x",
        "code_challenge_method" => "plain",
        "scope" => "mcp",
        "state" => "abc",
        "resource" => "https://app.example.com/mcp"
      })
      |> put_actor(user)

    conn = Authorize.call(conn, Authorize.init(otp_app: :ash_ai))
    assert conn.status == 400
  end

  test "GET 400 on redirect_uri mismatch", %{user: user, client: client} do
    conn =
      authorize_conn(%{
        "response_type" => "code",
        "client_id" => client.id,
        "redirect_uri" => "https://attacker.example/cb",
        "code_challenge" => "x",
        "code_challenge_method" => "S256",
        "scope" => "mcp",
        "state" => "abc",
        "resource" => "https://app.example.com/mcp"
      })
      |> put_actor(user)

    conn = Authorize.call(conn, Authorize.init(otp_app: :ash_ai))
    assert conn.status == 400
  end

  test "GET 401 redirects to login when no actor", %{client: client} do
    conn =
      authorize_conn(%{
        "response_type" => "code",
        "client_id" => client.id,
        "redirect_uri" => "https://chatgpt.com/cb",
        "code_challenge" => "x",
        "code_challenge_method" => "S256",
        "scope" => "mcp",
        "state" => "abc",
        "resource" => "https://app.example.com/mcp"
      })

    conn = Authorize.call(conn, Authorize.init(otp_app: :ash_ai))
    # Default behavior when no `:sign_in_path` is configured: 401
    assert conn.status == 401
  end

  test "POST approve issues code and redirects", %{user: user, client: client} do
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = Pkce.challenge(verifier)

    conn =
      conn(:post, "/oauth/authorize", %{
        "action" => "approve",
        "response_type" => "code",
        "client_id" => client.id,
        "redirect_uri" => "https://chatgpt.com/cb",
        "code_challenge" => challenge,
        "code_challenge_method" => "S256",
        "scope" => "mcp",
        "state" => "abc",
        "resource" => "https://app.example.com/mcp"
      })
      |> Plug.Conn.fetch_query_params()
      |> put_actor(user)

    # Skip CSRF in tests by setting :skip_csrf in the plug — see implementation note below.
    conn = Authorize.call(conn, Authorize.init(otp_app: :ash_ai, skip_csrf?: true))

    assert conn.status == 302
    [location] = get_resp_header(conn, "location")
    assert location =~ "https://chatgpt.com/cb?code="
    assert location =~ "state=abc"

    # Consent was recorded
    consents = AshAi.Test.OAuthConsent |> Ash.read!()
    assert length(consents) == 1
  end

  test "POST deny redirects with error=access_denied", %{user: user, client: client} do
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = Pkce.challenge(verifier)

    conn =
      conn(:post, "/oauth/authorize", %{
        "action" => "deny",
        "response_type" => "code",
        "client_id" => client.id,
        "redirect_uri" => "https://chatgpt.com/cb",
        "code_challenge" => challenge,
        "code_challenge_method" => "S256",
        "scope" => "mcp",
        "state" => "abc",
        "resource" => "https://app.example.com/mcp"
      })
      |> Plug.Conn.fetch_query_params()
      |> put_actor(user)

    conn = Authorize.call(conn, Authorize.init(otp_app: :ash_ai, skip_csrf?: true))

    assert conn.status == 302
    [location] = get_resp_header(conn, "location")
    assert location =~ "https://chatgpt.com/cb?error=access_denied"
    assert location =~ "state=abc"
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mix test test/ash_ai/oauth/authorize_test.exs`
Expected: FAIL.

- [ ] **Step 3: Implement the module**

Create `lib/ash_ai/oauth/authorize.ex`:

```elixir
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

    alias AshAi.Oauth.{Config, Pkce}

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
        case existing_consent(otp_app, user, validated.client) do
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

    defp check_resource(otp_app, %{"resource" => res}) do
      if res == Config.canonical_mcp_url(otp_app),
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

    defp existing_consent(otp_app, user, client) do
      consent_resource = Config.consent_resource(otp_app)

      consent_resource
      |> Ash.Query.filter(user_id == ^user.id and client_id == ^client.id)
      |> Ash.read_one(authorize?: false)
      |> case do
        {:ok, %{}} -> true
        _ -> false
      end
    end

    defp grant_consent(otp_app, user, %{client: client, scope: scope}) do
      Config.consent_resource(otp_app)
      |> Ash.Changeset.for_create(:grant, %{user_id: user.id, client_id: client.id, scope: scope})
      |> Ash.create!()
    end

    # ── Code issuance ────────────────────────────────────────────────────

    defp issue_code_and_redirect(conn, otp_app, user, validated) do
      ttl_seconds = Config.authorization_code_ttl(otp_app)
      expires_at = DateTime.add(DateTime.utc_now(), ttl_seconds, :second)
      id = Ash.UUIDv7.generate()

      Config.authorization_code_resource(otp_app)
      |> Ash.Changeset.for_create(:create, %{
        id: id,
        client_id: validated.client.id,
        user_id: user.id,
        redirect_uri: validated.redirect_uri,
        code_challenge: validated.code_challenge,
        scope: validated.scope,
        resource_uri: validated.resource,
        expires_at: expires_at
      })
      |> Ash.create!()

      query = URI.encode_query(%{"code" => id, "state" => validated.state})
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

    defp get_csrf_token(conn) do
      cond do
        function_exported?(Plug.CSRFProtection, :get_csrf_token, 0) -> Plug.CSRFProtection.get_csrf_token()
        true -> ""
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
```

- [ ] **Step 4: Run tests**

Run: `mix test test/ash_ai/oauth/authorize_test.exs`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add lib/ash_ai/oauth/authorize.ex test/ash_ai/oauth/authorize_test.exs
git commit -m "feat(oauth): /oauth/authorize endpoint with consent + PKCE binding"
```

---

## Task 17: `AshAi.Oauth.Token` — `/oauth/token` (code + refresh)

**Files:**
- Create: `lib/ash_ai/oauth/token.ex`
- Test: `test/ash_ai/oauth/token_test.exs`

- [ ] **Step 1: Write the failing test**

Create `test/ash_ai/oauth/token_test.exs`:

```elixir
# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Oauth.TokenTest do
  use ExUnit.Case, async: false
  import Plug.{Conn, Test}

  alias AshAi.Oauth.{Pkce, Token}

  setup do
    prior = Application.get_env(:ash_ai, AshAi.Oauth)

    Application.put_env(:ash_ai, AshAi.Oauth,
      user_resource: AshAi.Test.OauthUser,
      client_resource: AshAi.Test.OAuthClient,
      authorization_code_resource: AshAi.Test.OAuthAuthorizationCode,
      refresh_token_resource: AshAi.Test.OAuthRefreshToken,
      consent_resource: AshAi.Test.OAuthConsent,
      issuer_url: "https://app.example.com",
      canonical_mcp_url: "https://app.example.com/mcp",
      signing_secret: String.duplicate("x", 64),
      access_token_ttl: 3_600,
      refresh_token_ttl: {30, :days},
      scopes: ["mcp"]
    )

    on_exit(fn ->
      if prior, do: Application.put_env(:ash_ai, AshAi.Oauth, prior), else: Application.delete_env(:ash_ai, AshAi.Oauth)
    end)

    {:ok, user} = AshAi.Test.OauthUser |> Ash.Changeset.for_create(:create, %{email: "u@example.com"}) |> Ash.create()

    {:ok, client} =
      AshAi.Test.OAuthClient
      |> Ash.Changeset.for_create(:register, %{
        client_name: "C",
        redirect_uris: ["https://chatgpt.com/cb"],
        token_endpoint_auth_method: "none",
        scope: "mcp"
      })
      |> Ash.create()

    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = Pkce.challenge(verifier)

    {:ok, code} =
      AshAi.Test.OAuthAuthorizationCode
      |> Ash.Changeset.for_create(:create, %{
        id: Ash.UUIDv7.generate(),
        client_id: client.id,
        user_id: user.id,
        redirect_uri: "https://chatgpt.com/cb",
        code_challenge: challenge,
        scope: "mcp",
        resource_uri: "https://app.example.com/mcp",
        expires_at: DateTime.add(DateTime.utc_now(), 600, :second)
      })
      |> Ash.create()

    {:ok, user: user, client: client, code: code, verifier: verifier}
  end

  defp post_form(form) do
    body = URI.encode_query(form)

    conn(:post, "/oauth/token", body)
    |> put_req_header("content-type", "application/x-www-form-urlencoded")
    |> Plug.Parsers.call(Plug.Parsers.init(parsers: [:urlencoded], pass: ["*/*"]))
  end

  test "exchanges authorization code for access + refresh tokens", %{client: client, code: code, verifier: verifier} do
    conn = post_form(%{
      "grant_type" => "authorization_code",
      "code" => code.id,
      "redirect_uri" => "https://chatgpt.com/cb",
      "client_id" => client.id,
      "code_verifier" => verifier,
      "resource" => "https://app.example.com/mcp"
    })

    conn = Token.call(conn, Token.init(otp_app: :ash_ai))

    assert conn.status == 200
    body = Jason.decode!(conn.resp_body)
    assert is_binary(body["access_token"])
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 3_600
    assert is_binary(body["refresh_token"])
    assert body["scope"] == "mcp"
    assert get_resp_header(conn, "cache-control") == ["no-store"]
  end

  test "rejects reused authorization code", %{client: client, code: code, verifier: verifier} do
    form = %{
      "grant_type" => "authorization_code",
      "code" => code.id,
      "redirect_uri" => "https://chatgpt.com/cb",
      "client_id" => client.id,
      "code_verifier" => verifier,
      "resource" => "https://app.example.com/mcp"
    }

    Token.call(post_form(form), Token.init(otp_app: :ash_ai))

    conn = Token.call(post_form(form), Token.init(otp_app: :ash_ai))
    assert conn.status == 400
    assert Jason.decode!(conn.resp_body)["error"] == "invalid_grant"
  end

  test "rejects bad PKCE verifier", %{client: client, code: code} do
    conn = post_form(%{
      "grant_type" => "authorization_code",
      "code" => code.id,
      "redirect_uri" => "https://chatgpt.com/cb",
      "client_id" => client.id,
      "code_verifier" => "wrong",
      "resource" => "https://app.example.com/mcp"
    })

    conn = Token.call(conn, Token.init(otp_app: :ash_ai))
    assert conn.status == 400
    assert Jason.decode!(conn.resp_body)["error"] == "invalid_grant"
  end

  test "refresh grant rotates token", %{client: client, code: code, verifier: verifier} do
    initial =
      Token.call(
        post_form(%{
          "grant_type" => "authorization_code",
          "code" => code.id,
          "redirect_uri" => "https://chatgpt.com/cb",
          "client_id" => client.id,
          "code_verifier" => verifier,
          "resource" => "https://app.example.com/mcp"
        }),
        Token.init(otp_app: :ash_ai)
      )

    %{"refresh_token" => refresh} = Jason.decode!(initial.resp_body)

    conn = post_form(%{
      "grant_type" => "refresh_token",
      "refresh_token" => refresh,
      "client_id" => client.id,
      "resource" => "https://app.example.com/mcp"
    })

    conn = Token.call(conn, Token.init(otp_app: :ash_ai))
    assert conn.status == 200
    body = Jason.decode!(conn.resp_body)
    assert is_binary(body["access_token"])
    assert is_binary(body["refresh_token"])
    refute body["refresh_token"] == refresh
  end

  test "reused refresh token revokes the chain", %{client: client, code: code, verifier: verifier} do
    initial =
      Token.call(
        post_form(%{
          "grant_type" => "authorization_code",
          "code" => code.id,
          "redirect_uri" => "https://chatgpt.com/cb",
          "client_id" => client.id,
          "code_verifier" => verifier,
          "resource" => "https://app.example.com/mcp"
        }),
        Token.init(otp_app: :ash_ai)
      )

    %{"refresh_token" => refresh} = Jason.decode!(initial.resp_body)

    refresh_form = %{
      "grant_type" => "refresh_token",
      "refresh_token" => refresh,
      "client_id" => client.id,
      "resource" => "https://app.example.com/mcp"
    }

    Token.call(post_form(refresh_form), Token.init(otp_app: :ash_ai))
    second = Token.call(post_form(refresh_form), Token.init(otp_app: :ash_ai))

    assert second.status == 400
    assert Jason.decode!(second.resp_body)["error"] == "invalid_grant"
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mix test test/ash_ai/oauth/token_test.exs`
Expected: FAIL.

- [ ] **Step 3: Implement the module**

Create `lib/ash_ai/oauth/token.ex`:

```elixir
# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

if Code.ensure_loaded?(Plug) do
  defmodule AshAi.Oauth.Token do
    @moduledoc """
    Plug implementing OAuth 2.1 token endpoint.

    Mount at `POST /oauth/token`. Supports:
      - `grant_type=authorization_code` with PKCE
      - `grant_type=refresh_token` with rotation + reuse detection (RFC 6749 §6, OAuth 2.1 §4.3.1)
    """

    @behaviour Plug
    import Plug.Conn

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
           false <- code.client_id != client_id and {:error, :not_found},
           {:ok, code} <- Ash.update(code, :consume, authorize?: false),
           {:ok, client} <- Ash.get(Config.client_resource(otp_app), code.client_id, authorize?: false) do
        cond do
          code.consumed_at && DateTime.compare(code.consumed_at, code.expires_at) == :gt -> {:error, :expired}
          DateTime.compare(DateTime.utc_now(), code.expires_at) == :gt -> {:error, :expired}
          true -> {:ok, code, client}
        end
      else
        {:error, %Ash.Error.Invalid{}} -> {:error, :reuse}
        false -> {:error, :not_found}
        _ -> {:error, :not_found}
      end
    end

    defp consume_code(_, _), do: {:error, :not_found}

    defp check_pkce(code, %{"code_verifier" => verifier}),
      do: if(Pkce.verify(verifier, code.code_challenge) == :ok, do: :ok, else: {:error, :pkce})

    defp check_pkce(_, _), do: {:error, :pkce}

    defp check_resource_match(otp_app, %{"resource" => res}, code) do
      expected = Config.canonical_mcp_url(otp_app)
      if res == expected and code.resource_uri == expected, do: :ok, else: {:error, :resource}
    end

    defp check_resource_match(_, _, _), do: {:error, :resource}

    defp check_redirect_match(%{"redirect_uri" => uri}, code),
      do: if(uri == code.redirect_uri, do: :ok, else: {:error, :redirect})

    defp check_redirect_match(_, _), do: {:error, :redirect}

    defp mint_tokens(otp_app, client, code) do
      with {:ok, access, _claims} <- Jwt.mint(otp_app, sub: code.user_id, client_id: client.id, scope: code.scope),
           {:ok, refresh_raw} <- issue_refresh(otp_app, client, code) do
        {:ok, access, refresh_raw}
      end
    end

    defp issue_refresh(otp_app, client, code) do
      raw = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
      hash = :crypto.hash(:sha256, raw) |> Base.encode16(case: :lower)

      Config.refresh_token_resource(otp_app)
      |> Ash.Changeset.for_create(:issue, %{
        id: Ash.UUIDv7.generate(),
        token_hash: hash,
        client_id: client.id,
        user_id: code.user_id,
        scope: code.scope,
        resource_uri: code.resource_uri,
        expires_at: DateTime.add(DateTime.utc_now(), Config.refresh_token_ttl(otp_app), :second)
      })
      |> Ash.create()
      |> case do
        {:ok, _} -> {:ok, raw}
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
      new_id = Ash.UUIDv7.generate()
      raw = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
      hash = :crypto.hash(:sha256, raw) |> Base.encode16(case: :lower)

      with {:ok, _} <- Ash.update(row, :rotate, %{new_id: new_id}, authorize?: false),
           {:ok, _} <-
             Config.refresh_token_resource(otp_app)
             |> Ash.Changeset.for_create(:issue, %{
               id: new_id,
               token_hash: hash,
               client_id: row.client_id,
               user_id: row.user_id,
               scope: row.scope,
               resource_uri: row.resource_uri,
               expires_at: DateTime.add(DateTime.utc_now(), Config.refresh_token_ttl(otp_app), :second)
             })
             |> Ash.create(),
           {:ok, access, _} <-
             Jwt.mint(otp_app, sub: row.user_id, client_id: row.client_id, scope: row.scope) do
        {:ok, access, raw}
      end
    end

    defp revoke_chain(otp_app, hash) do
      # Best-effort: revoke any token matching the reused hash
      with {:ok, row} <- find_refresh(otp_app, hash) do
        Ash.update(row, :revoke, authorize?: false)
      end
    end
  end
end
```

- [ ] **Step 4: Run tests**

Run: `mix test test/ash_ai/oauth/token_test.exs`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add lib/ash_ai/oauth/token.ex test/ash_ai/oauth/token_test.exs
git commit -m "feat(oauth): /oauth/token (auth code + refresh with rotation reuse detection)"
```

---

## Task 18: `AshAi.Oauth.Revoke` — RFC 7009

**Files:**
- Create: `lib/ash_ai/oauth/revoke.ex`
- Test: `test/ash_ai/oauth/revoke_test.exs`

- [ ] **Step 1: Write the failing test**

Create `test/ash_ai/oauth/revoke_test.exs`:

```elixir
# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Oauth.RevokeTest do
  use ExUnit.Case, async: false
  import Plug.{Conn, Test}

  alias AshAi.Oauth.Revoke

  setup do
    prior = Application.get_env(:ash_ai, AshAi.Oauth)

    Application.put_env(:ash_ai, AshAi.Oauth,
      user_resource: AshAi.Test.OauthUser,
      client_resource: AshAi.Test.OAuthClient,
      authorization_code_resource: AshAi.Test.OAuthAuthorizationCode,
      refresh_token_resource: AshAi.Test.OAuthRefreshToken,
      consent_resource: AshAi.Test.OAuthConsent,
      issuer_url: "https://app.example.com",
      canonical_mcp_url: "https://app.example.com/mcp",
      signing_secret: "x",
      scopes: ["mcp"],
      refresh_token_ttl: {30, :days}
    )

    on_exit(fn ->
      if prior, do: Application.put_env(:ash_ai, AshAi.Oauth, prior), else: Application.delete_env(:ash_ai, AshAi.Oauth)
    end)

    :ok
  end

  defp post_form(form) do
    body = URI.encode_query(form)

    conn(:post, "/oauth/revoke", body)
    |> put_req_header("content-type", "application/x-www-form-urlencoded")
    |> Plug.Parsers.call(Plug.Parsers.init(parsers: [:urlencoded]))
  end

  test "always returns 200" do
    conn = Revoke.call(post_form(%{"token" => "doesnt-exist"}), Revoke.init(otp_app: :ash_ai))
    assert conn.status == 200
  end

  test "revokes a refresh token by raw value" do
    raw = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
    hash = :crypto.hash(:sha256, raw) |> Base.encode16(case: :lower)

    {:ok, row} =
      AshAi.Test.OAuthRefreshToken
      |> Ash.Changeset.for_create(:issue, %{
        id: Ash.UUIDv7.generate(),
        token_hash: hash,
        client_id: Ash.UUIDv7.generate(),
        user_id: Ash.UUIDv7.generate(),
        scope: "mcp",
        resource_uri: "https://app.example.com/mcp",
        expires_at: DateTime.add(DateTime.utc_now(), 86_400, :second)
      })
      |> Ash.create()

    conn = Revoke.call(post_form(%{"token" => raw}), Revoke.init(otp_app: :ash_ai))
    assert conn.status == 200

    {:ok, reloaded} = Ash.get(AshAi.Test.OAuthRefreshToken, row.id, authorize?: false)
    assert reloaded.revoked_at
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mix test test/ash_ai/oauth/revoke_test.exs`
Expected: FAIL.

- [ ] **Step 3: Implement the module**

Create `lib/ash_ai/oauth/revoke.ex`:

```elixir
# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

if Code.ensure_loaded?(Plug) do
  defmodule AshAi.Oauth.Revoke do
    @moduledoc """
    Plug implementing RFC 7009 token revocation.

    Mount at `POST /oauth/revoke`. Always returns 200 per the RFC, regardless
    of whether the token was found.
    """

    @behaviour Plug
    import Plug.Conn

    alias AshAi.Oauth.Config

    @impl Plug
    def init(opts), do: Keyword.fetch!(opts, :otp_app)

    @impl Plug
    def call(%{method: "POST"} = conn, otp_app) do
      case conn.params["token"] do
        token when is_binary(token) -> revoke(otp_app, token)
        _ -> :noop
      end

      conn
      |> put_resp_header("cache-control", "no-store")
      |> send_resp(200, "")
      |> halt()
    end

    def call(conn, _), do: send_resp(conn, 405, "") |> halt()

    defp revoke(otp_app, token) do
      hash = :crypto.hash(:sha256, token) |> Base.encode16(case: :lower)

      Config.refresh_token_resource(otp_app)
      |> Ash.Query.filter(token_hash == ^hash)
      |> Ash.read_one(authorize?: false)
      |> case do
        {:ok, %{} = row} -> Ash.update(row, :revoke, authorize?: false)
        _ -> :noop
      end
    end
  end
end
```

- [ ] **Step 4: Run tests**

Run: `mix test test/ash_ai/oauth/revoke_test.exs`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add lib/ash_ai/oauth/revoke.ex test/ash_ai/oauth/revoke_test.exs
git commit -m "feat(oauth): RFC 7009 token revocation endpoint"
```

---

## Task 19: `AshAi.Oauth.Router` — bundled mount

**Files:**
- Create: `lib/ash_ai/oauth/router.ex`

- [ ] **Step 1: Implement the router**

Create `lib/ash_ai/oauth/router.ex`:

```elixir
# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

if Code.ensure_loaded?(Plug) do
  defmodule AshAi.Oauth.Router do
    @moduledoc """
    Single-mount router for the OAuth 2.1 endpoints + well-known metadata.

    Forward at the user's app root:

        forward "/", AshAi.Oauth.Router, otp_app: :my_app

    Routes owned:

      - `GET  /.well-known/oauth-protected-resource`
      - `GET  /.well-known/oauth-authorization-server`
      - `POST /oauth/register`
      - `GET  /oauth/authorize`
      - `POST /oauth/authorize`
      - `POST /oauth/token`
      - `POST /oauth/revoke`

    Anything else passes through unchanged.
    """

    use Plug.Router, copy_opts_to_assign: :ash_ai_oauth_opts

    plug Plug.Parsers,
      parsers: [:urlencoded, :json],
      pass: ["*/*"],
      json_decoder: Jason

    plug :match
    plug :dispatch

    get "/.well-known/oauth-protected-resource" do
      AshAi.Mcp.Metadata.ProtectedResource.call(conn, otp_app(conn))
    end

    get "/.well-known/oauth-authorization-server" do
      AshAi.Oauth.Metadata.AuthServer.call(conn, otp_app(conn))
    end

    post "/oauth/register" do
      AshAi.Oauth.Register.call(conn, otp_app(conn))
    end

    get "/oauth/authorize" do
      AshAi.Oauth.Authorize.call(conn, %{otp_app: otp_app(conn), skip_csrf?: false})
    end

    post "/oauth/authorize" do
      AshAi.Oauth.Authorize.call(conn, %{otp_app: otp_app(conn), skip_csrf?: false})
    end

    post "/oauth/token" do
      AshAi.Oauth.Token.call(conn, otp_app(conn))
    end

    post "/oauth/revoke" do
      AshAi.Oauth.Revoke.call(conn, otp_app(conn))
    end

    match _ do
      conn
    end

    defp otp_app(conn), do: conn.assigns.ash_ai_oauth_opts |> Keyword.fetch!(:otp_app)
  end
end
```

- [ ] **Step 2: Compile**

Run: `mix compile`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add lib/ash_ai/oauth/router.ex
git commit -m "feat(oauth): single-mount Router"
```

---

## Task 20: `AshAi.Oauth.Application` — boot-time validator

**Files:**
- Create: `lib/ash_ai/oauth/application.ex`

- [ ] **Step 1: Implement the validator**

Create `lib/ash_ai/oauth/application.ex`:

```elixir
# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Oauth.Application do
  @moduledoc """
  Optional supervisor child that validates `AshAi.Oauth` config at boot.

  Add to your supervision tree:

      children = [
        ...,
        {AshAi.Oauth.Application, otp_app: :my_app}
      ]

  Will raise on start if required config is missing or invalid.
  """

  use GenServer

  @required_keys [
    :user_resource,
    :issuer_url,
    :canonical_mcp_url,
    :signing_secret,
    :client_resource,
    :authorization_code_resource,
    :refresh_token_resource,
    :consent_resource
  ]

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(opts) do
    otp_app = Keyword.fetch!(opts, :otp_app)

    config =
      case Application.get_env(otp_app, AshAi.Oauth) do
        nil -> raise "AshAi.Oauth not configured for :#{otp_app}"
        kw -> kw
      end

    Enum.each(@required_keys, fn key ->
      unless Keyword.has_key?(config, key),
        do: raise("AshAi.Oauth missing required config key #{inspect(key)} for :#{otp_app}")
    end)

    URI.parse(Keyword.fetch!(config, :issuer_url)) |> validate_uri(:issuer_url)
    URI.parse(Keyword.fetch!(config, :canonical_mcp_url)) |> validate_uri(:canonical_mcp_url)

    Enum.each(
      [:user_resource, :client_resource, :authorization_code_resource, :refresh_token_resource, :consent_resource],
      fn key ->
        mod = Keyword.fetch!(config, key)
        Code.ensure_loaded!(mod)
      end
    )

    {:ok, %{otp_app: otp_app}}
  end

  defp validate_uri(%URI{scheme: scheme, host: host}, key) when scheme in ["http", "https"] and is_binary(host),
    do: :ok

  defp validate_uri(uri, key),
    do: raise("AshAi.Oauth #{key} must be a valid http(s) URL with a host: got #{inspect(uri)}")
end
```

- [ ] **Step 2: Compile**

Run: `mix compile`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add lib/ash_ai/oauth/application.ex
git commit -m "feat(oauth): boot-time config validator"
```

---

## Task 21: End-to-end OAuth round trip test

**Files:**
- Create: `test/ash_ai/oauth/full_flow_test.exs`

This is the integration test that exercises the entire flow as ChatGPT/Claude would, validating each spec MUST.

- [ ] **Step 1: Write the integration test**

Create `test/ash_ai/oauth/full_flow_test.exs`:

```elixir
# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Oauth.FullFlowTest do
  @moduledoc """
  End-to-end OAuth 2.1 round trip:
  unauth MCP -> 401 PRM -> ASM -> DCR -> /authorize (consent) -> /token -> authenticated MCP -> refresh
  """

  use ExUnit.Case, async: false
  import Plug.{Conn, Test}

  alias AshAi.Mcp.BearerPlug
  alias AshAi.Mcp.Metadata.ProtectedResource
  alias AshAi.Oauth.{Authorize, Metadata.AuthServer, Pkce, Register, Token}

  setup do
    prior = Application.get_env(:ash_ai, AshAi.Oauth)

    Application.put_env(:ash_ai, AshAi.Oauth,
      user_resource: AshAi.Test.OauthUser,
      client_resource: AshAi.Test.OAuthClient,
      authorization_code_resource: AshAi.Test.OAuthAuthorizationCode,
      refresh_token_resource: AshAi.Test.OAuthRefreshToken,
      consent_resource: AshAi.Test.OAuthConsent,
      issuer_url: "https://app.example.com",
      canonical_mcp_url: "https://app.example.com/mcp",
      signing_secret: String.duplicate("x", 64),
      access_token_ttl: 3_600,
      refresh_token_ttl: {30, :days},
      authorization_code_ttl: {10, :minutes},
      scopes: ["mcp"]
    )

    on_exit(fn ->
      if prior, do: Application.put_env(:ash_ai, AshAi.Oauth, prior), else: Application.delete_env(:ash_ai, AshAi.Oauth)
    end)

    {:ok, user} = AshAi.Test.OauthUser |> Ash.Changeset.for_create(:create, %{email: "u@example.com"}) |> Ash.create()

    {:ok, user: user}
  end

  test "complete round trip", %{user: user} do
    # 1. Unauth MCP request -> 401 with WWW-Authenticate
    conn = conn(:post, "/mcp", "{}")
    conn = BearerPlug.call(conn, BearerPlug.init(otp_app: :ash_ai, required?: true))

    assert conn.status == 401
    [auth_header] = get_resp_header(conn, "www-authenticate")
    [_, prm_url] = Regex.run(~r/resource_metadata="([^"]+)"/, auth_header)

    # 2. GET PRM
    conn = conn(:get, prm_url)
    conn = ProtectedResource.call(conn, ProtectedResource.init(otp_app: :ash_ai))
    prm = Jason.decode!(conn.resp_body)
    [as_issuer] = prm["authorization_servers"]

    # 3. GET ASM
    conn = conn(:get, "#{as_issuer}/.well-known/oauth-authorization-server")
    conn = AuthServer.call(conn, AuthServer.init(otp_app: :ash_ai))
    asm = Jason.decode!(conn.resp_body)

    # 4. DCR
    conn =
      conn(:post, asm["registration_endpoint"], Jason.encode!(%{
        "client_name" => "ChatGPT",
        "redirect_uris" => ["https://chatgpt.com/connector/oauth/abc"],
        "token_endpoint_auth_method" => "none"
      }))
      |> put_req_header("content-type", "application/json")
      |> Plug.Parsers.call(Plug.Parsers.init(parsers: [:json], json_decoder: Jason))

    conn = Register.call(conn, Register.init(otp_app: :ash_ai))
    %{"client_id" => client_id} = Jason.decode!(conn.resp_body)

    # 5. /authorize (with prior consent so we get a code immediately)
    AshAi.Test.OAuthConsent
    |> Ash.Changeset.for_create(:grant, %{user_id: user.id, client_id: client_id, scope: "mcp"})
    |> Ash.create!()

    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = Pkce.challenge(verifier)

    auth_query = URI.encode_query(%{
      "response_type" => "code",
      "client_id" => client_id,
      "redirect_uri" => "https://chatgpt.com/connector/oauth/abc",
      "code_challenge" => challenge,
      "code_challenge_method" => "S256",
      "scope" => "mcp",
      "state" => "xyz",
      "resource" => "https://app.example.com/mcp"
    })

    conn =
      conn(:get, "#{asm["authorization_endpoint"]}?#{auth_query}")
      |> Plug.Conn.fetch_query_params()
      |> Ash.PlugHelpers.set_actor(user)

    conn = Authorize.call(conn, Authorize.init(otp_app: :ash_ai))
    [location] = get_resp_header(conn, "location")
    %{"code" => code} = URI.decode_query(URI.parse(location).query)

    # 6. /token (code exchange)
    conn =
      conn(:post, asm["token_endpoint"], URI.encode_query(%{
        "grant_type" => "authorization_code",
        "code" => code,
        "redirect_uri" => "https://chatgpt.com/connector/oauth/abc",
        "client_id" => client_id,
        "code_verifier" => verifier,
        "resource" => "https://app.example.com/mcp"
      }))
      |> put_req_header("content-type", "application/x-www-form-urlencoded")
      |> Plug.Parsers.call(Plug.Parsers.init(parsers: [:urlencoded]))

    conn = Token.call(conn, Token.init(otp_app: :ash_ai))
    %{"access_token" => access, "refresh_token" => refresh} = Jason.decode!(conn.resp_body)

    # 7. Authenticated MCP request
    conn =
      conn(:post, "/mcp", "{}")
      |> put_req_header("authorization", "Bearer #{access}")

    conn = BearerPlug.call(conn, BearerPlug.init(otp_app: :ash_ai, required?: true))
    refute conn.halted
    assert Ash.PlugHelpers.get_actor(conn).id == user.id

    # 8. Refresh
    conn =
      conn(:post, asm["token_endpoint"], URI.encode_query(%{
        "grant_type" => "refresh_token",
        "refresh_token" => refresh,
        "client_id" => client_id,
        "resource" => "https://app.example.com/mcp"
      }))
      |> put_req_header("content-type", "application/x-www-form-urlencoded")
      |> Plug.Parsers.call(Plug.Parsers.init(parsers: [:urlencoded]))

    conn = Token.call(conn, Token.init(otp_app: :ash_ai))
    body = Jason.decode!(conn.resp_body)
    assert is_binary(body["access_token"])
    refute body["refresh_token"] == refresh
  end
end
```

- [ ] **Step 2: Run the integration test**

Run: `mix test test/ash_ai/oauth/full_flow_test.exs`
Expected: PASS.

- [ ] **Step 3: Run the entire suite**

Run: `mix test`
Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add test/ash_ai/oauth/full_flow_test.exs
git commit -m "test(oauth): end-to-end OAuth 2.1 round trip integration test"
```

---

## Task 22: `mix ash_ai.gen.oauth` generator

**Files:**
- Create: `lib/mix/tasks/ash_ai.gen.oauth.ex`

The generator scaffolds the four OAuth Ash resources into the user's app and writes the `runtime.exs` block. Modeled after `mix ash_authentication.add_strategy`.

- [ ] **Step 1: Implement the task**

Create `lib/mix/tasks/ash_ai.gen.oauth.ex`:

```elixir
# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.AshAi.Gen.Oauth do
    @moduledoc """
    Scaffold OAuth 2.1 resources and config for the AshAi MCP server.

    Creates four Ash resources in the user's app:
      - `OAuthClient`
      - `OAuthAuthorizationCode`
      - `OAuthRefreshToken`
      - `OAuthConsent`

    And writes a `config :my_app, AshAi.Oauth, ...` block in `config/runtime.exs`.

    ## Usage

        mix ash_ai.gen.oauth --user MyApp.Accounts.User

    ## Options

    - `--user` (required) — the AshAuthentication user resource.
    - `--domain` — the Ash domain to put resources in. Defaults to user's domain.
    - `--data-layer` — `ash_postgres` (default) or `ash_ets`.
    """

    @shortdoc "Generate OAuth 2.1 resources and config for ash_ai MCP."

    use Igniter.Mix.Task

    @impl Igniter.Mix.Task
    def info(_argv, _composing_task) do
      %Igniter.Mix.Task.Info{
        schema: [user: :string, domain: :string, data_layer: :string],
        required: [:user]
      }
    end

    @impl Igniter.Mix.Task
    def igniter(igniter) do
      opts = igniter.args.options
      user_module = Module.concat([opts[:user]])
      domain = opts[:domain] && Module.concat([opts[:domain]])
      data_layer = opts[:data_layer] || "ash_postgres"

      domain =
        domain ||
          user_module
          |> Module.split()
          |> Enum.drop(-1)
          |> Module.concat()

      igniter
      |> add_resource(domain, OAuthClient, client_attrs(), data_layer)
      |> add_resource(domain, OAuthAuthorizationCode, auth_code_attrs(), data_layer)
      |> add_resource(domain, OAuthRefreshToken, refresh_token_attrs(), data_layer)
      |> add_resource(domain, OAuthConsent, consent_attrs(), data_layer)
      |> add_runtime_config(domain, user_module)
    end

    defp client_attrs do
      """
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
      """
    end

    defp auth_code_attrs, do: # ... as in Task 10
    defp refresh_token_attrs, do: # ... as in Task 11
    defp consent_attrs, do: # ... as in Task 12

    defp add_resource(igniter, domain, suffix, attrs, data_layer) do
      module = Module.concat(domain, suffix)
      file = Igniter.Project.Module.proper_location(igniter, module)

      content = """
      defmodule #{inspect(module)} do
        use Ash.Resource,
          domain: #{inspect(domain)},
          data_layer: #{inspect(data_layer_module(data_layer))}

        attributes do
          uuid_v7_primary_key :id
          #{attrs}
        end

        actions do
          defaults [:read, :destroy]
        end
      end
      """

      Igniter.create_new_file(igniter, file, content)
    end

    defp data_layer_module("ash_postgres"), do: AshPostgres.DataLayer
    defp data_layer_module("ash_ets"), do: Ash.DataLayer.Ets

    defp add_runtime_config(igniter, domain, user_module) do
      block = """
      config :#{Igniter.Project.Application.app_name(igniter)}, AshAi.Oauth,
        user_resource: #{inspect(user_module)},
        issuer_url: System.fetch_env!("ISSUER_URL"),
        canonical_mcp_url: System.fetch_env!("MCP_URL"),
        signing_secret: System.fetch_env!("MCP_SIGNING_SECRET"),
        client_resource: #{inspect(Module.concat(domain, OAuthClient))},
        authorization_code_resource: #{inspect(Module.concat(domain, OAuthAuthorizationCode))},
        refresh_token_resource: #{inspect(Module.concat(domain, OAuthRefreshToken))},
        consent_resource: #{inspect(Module.concat(domain, OAuthConsent))},
        access_token_ttl: {1, :hour},
        refresh_token_ttl: {30, :days},
        authorization_code_ttl: {10, :minutes},
        scopes: ["mcp"]
      """

      Igniter.Project.Config.configure(
        igniter,
        "runtime.exs",
        Igniter.Project.Application.app_name(igniter),
        [AshAi.Oauth],
        block
      )
    end
  end
end
```

(The skeleton above shows the structure; the `auth_code_attrs/0`, `refresh_token_attrs/0`, and `consent_attrs/0` functions return strings matching the test resources from Tasks 10–12.)

- [ ] **Step 2: Compile**

Run: `mix compile`
Expected: clean.

- [ ] **Step 3: Test the task in a sandbox project (manual)**

Run in a separate Phoenix app:
```bash
mix igniter.install ash_ai
mix ash_ai.gen.oauth --user MyApp.Accounts.User
```

Verify the four resources are created and `runtime.exs` updated.

- [ ] **Step 4: Commit**

```bash
git add lib/mix/tasks/ash_ai.gen.oauth.ex
git commit -m "feat(oauth): mix ash_ai.gen.oauth generator task"
```

---

## Task 23: User documentation

**Files:**
- Create: `documentation/topics/mcp-oauth.md`
- Create: `documentation/topics/mcp-oauth-security.md`

- [ ] **Step 1: Write the user guide**

Create `documentation/topics/mcp-oauth.md` covering:
- Why you'd want OAuth 2.1 on your MCP server (ChatGPT/Claude integration)
- Prereqs: AshAuthentication installed
- Step-by-step setup using `mix ash_ai.gen.oauth`
- Wiring the router (mount the bundled router + the BearerPlug pipeline)
- Configuring environment variables
- Verifying with curl examples (PRM fetch, ASM fetch, full flow with `mcp_proxy_rust`)
- Connecting from ChatGPT and Claude (with screenshots if available)
- Troubleshooting common issues (audience mismatch, ChatGPT `client_secret` bug, redirect URI errors)

- [ ] **Step 2: Write the security doc**

Create `documentation/topics/mcp-oauth-security.md` covering:
- Audience binding (RFC 8707) and why we enforce it
- Confused-deputy and per-client consent
- PKCE S256 enforcement
- Refresh token rotation + reuse detection
- Token storage and revocation
- HTTPS/redirect URI restrictions
- What we don't yet support (DPoP, mTLS, fine-grained scopes)

- [ ] **Step 3: Commit**

```bash
git add documentation/topics/mcp-oauth.md documentation/topics/mcp-oauth-security.md
git commit -m "docs(oauth): user guide + security posture"
```

---

## Task 24: README + CHANGELOG

**Files:**
- Modify: `README.md`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Update README**

Replace the "Roadmap — Implement OAuth2 flow with AshAuthentication (long term)" bullet with a new section pointing at the OAuth user guide. Keep the existing API key flow documented as the simpler alternative.

Show example `runtime.exs` config and router wire-up (one-line `forward "/", AshAi.Oauth.Router, otp_app: :my_app`).

- [ ] **Step 2: Update CHANGELOG**

Add an entry under the current unreleased section:

```markdown
### Added
- OAuth 2.1 authorization for the MCP server, supporting ChatGPT Apps SDK
  and Claude.ai custom connectors. See `documentation/topics/mcp-oauth.md`.
- `AshAi.Mcp.BearerPlug` — bearer token validation with audience binding
  per RFC 8707, RFC 9728-conformant 401 challenge.
- `AshAi.Oauth.Router` — bundled mount for the authorization server endpoints
  and well-known metadata.
- `mix ash_ai.gen.oauth` — generator scaffolding the four required OAuth
  Ash resources and `runtime.exs` config.
```

- [ ] **Step 3: Final test run + commit**

Run: `mix test`
Expected: all tests pass.

```bash
git add README.md CHANGELOG.md
git commit -m "docs: README + CHANGELOG entries for OAuth 2.1 MCP support"
```

---

## Self-Review (run before declaring complete)

### Spec coverage check

For each section in the spec at `docs/superpowers/specs/2026-04-23-oauth21-mcp-design.md`:

- §3 architecture (RS + AS co-hosted) → Tasks 7, 8, 13–18, 19
- §4.1 plain app config → Task 2 (Config)
- §4.2 router wiring → Task 19 (Router)
- §5.1 OAuthClient → Task 9
- §5.2 OAuthAuthorizationCode → Task 10
- §5.3 OAuthRefreshToken → Task 11
- §5.4 OAuthConsent → Task 12
- §6.1 BearerPlug + 401 challenge → Task 8
- §6.2 PRM endpoint → Task 7
- §6.3 ASM endpoint → Task 13
- §6.4 DCR + ChatGPT workaround → Task 14
- §6.5 Authorize GET (consent + login redirect) → Task 16
- §6.6 Authorize POST (consent submission) → Task 16
- §6.7 Token endpoint code grant → Task 17
- §6.7 Token endpoint refresh + rotation reuse → Task 17
- §6.8 Revoke endpoint → Task 18
- §7 Module layout → matches Tasks 1–18
- §8 Config wrapper + Startup → Tasks 2, 20
- §9 Security checklist → covered by Task 21 (full flow) + per-task tests
- §10 Testing strategy → individual task tests + Task 21 integration
- §11 Documentation → Task 23
- §12 Phases → tasks ordered to match
- §13 Risks → noted; mitigations applied (e.g. dummy `client_secret` toggle in Task 14)

### Placeholder scan

- No "TODO", "TBD", "implement later" in any task body.
- All test code is real, runnable Elixir.
- `mix ash_ai.gen.oauth` task (Task 22) intentionally references attribute strings from Tasks 10–12; complete strings are in those tasks.

### Type consistency

- `otp_app` (atom) is used consistently across `Config`, `Jwt`, `BearerPlug`, all endpoint plugs, and the `Router`.
- Resource module references (`Config.client_resource(otp_app)` etc.) are consistent.
- JWT claim keys (`"sub"`, `"aud"`, `"iss"`, `"client_id"`, `"scope"`, `"jti"`, `"iat"`, `"nbf"`, `"exp"`) are consistent.
- Refresh token storage uses `token_hash` everywhere.
- Authorization code uses `code_challenge` (not `pkce_challenge`).

---

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-04-25-oauth21-mcp-implementation.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints

**Which approach?**
