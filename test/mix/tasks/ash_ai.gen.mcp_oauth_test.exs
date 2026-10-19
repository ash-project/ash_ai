# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule Mix.Tasks.AshAi.Gen.McpOauthTest do
  use ExUnit.Case

  import Igniter.Test

  @controller "lib/test_web/controllers/mcp_auth_controller.ex"

  defp project do
    phx_test_project()
    |> Igniter.Project.Module.create_module(Test.AshRepo, "use AshPostgres.Repo, otp_app: :test")
    |> apply_igniter!()
  end

  defp source(igniter, path) do
    igniter.rewrite |> Rewrite.source!(path) |> Rewrite.Source.get(:content)
  end

  # The test project's formatter doesn't know the Ash DSLs, so it adds the
  # parentheses an application's formatter would leave off
  defp assert_code(igniter, path, snippets) do
    contents = normalize(source(igniter, path))

    for snippet <- List.wrap(snippets) do
      assert contents =~ normalize(snippet), "expected #{path} to contain:\n\n#{snippet}"
    end

    igniter
  end

  defp normalize(code) do
    code
    |> String.replace("(", " ")
    |> String.replace(")", "")
    |> String.replace(~r/\s+/, " ")
  end

  describe "with a user resource" do
    setup do
      igniter =
        Igniter.compose_task(project(), "ash_ai.gen.mcp_oauth", ["--user", "Test.Accounts.User"])

      %{igniter: igniter}
    end

    test "adds ash_cloak and cloak", %{igniter: igniter} do
      igniter
      |> assert_has_patch("mix.exs", """
      + |      {:ash_cloak, "~> 0.4"},
      """)
      |> assert_has_patch("mix.exs", """
      + |      {:cloak, "~> 1.1"},
      """)
    end

    test "generates a vault with a key for each environment", %{igniter: igniter} do
      igniter
      |> assert_creates("lib/test/vault.ex")
      |> assert_has_patch("lib/test/application.ex", """
      + |      Test.Vault,
      """)
      |> assert_code("config/dev.exs", [
        "config :test, Test.Vault",
        "Cloak.Ciphers.AES.GCM",
        ~s|mcp_allowed_private_hosts: ["localhost"]|
      ])
      |> assert_code("config/test.exs", "Cloak.Ciphers.AES.GCM")
      |> assert_code("config/runtime.exs", ~s|System.get_env("CLOAK_KEY")|)
    end

    test "generates encrypted resources, with tokens belonging to the user", %{igniter: igniter} do
      igniter = apply_igniter!(igniter)

      assert_code(igniter, "lib/test/mcp_auth/token.ex", [
        "belongs_to :user, Test.Accounts.User",
        "reference :user, on_delete: :delete",
        "identity :unique_owner, [:server, :user_id]",
        "upsert_fields [:encrypted_data, :updated_at]",
        "attribute :refresh_locked_until, :utc_datetime_usec",
        "update :lock_refresh do"
      ])

      for path <- ["token.ex", "client.ex", "pending_authorization.ex"] do
        assert_code(igniter, "lib/test/mcp_auth/#{path}", [
          "vault Test.Vault",
          "attributes [:data]",
          "repo Test.AshRepo"
        ])
      end

      assert_code(igniter, "lib/test/mcp_auth.ex", [
        "resource Test.McpAuth.Token",
        "resource Test.McpAuth.PendingAuthorization",
        "def options(owner)",
        "base_url = TestWeb.Endpoint.url()",
        ~s|redirect_uri: base_url <> "/mcp-auth/callback"|,
        ~s|client_metadata_url: base_url <> "/mcp-auth/client-metadata.json"|,
        "def disconnect_all(owner)",
        "Ash.Query.filter(user_id == ^owner)"
      ])
    end

    test "generates a store that keys tokens by the user and locks refreshes", %{igniter: igniter} do
      igniter
      |> apply_igniter!()
      |> assert_code("lib/test/mcp_auth/store.ex", [
        "@behaviour AshAi.Mcp.OAuth.Store",
        "user_id == ^owner",
        "Ash.Changeset.for_update(:lock_refresh, %{lock: lock})",
        "refresh_locked_until < now()",
        "Ash.Query.lock(:for_update)"
      ])
    end

    test "generates the controller and routes", %{igniter: igniter} do
      igniter
      |> assert_creates(@controller)
      |> assert_code(@controller, [
        "AshAi.Mcp.OAuth.handle_callback(params, user.id",
        "AshAi.Mcp.OAuth.disconnect(server_url, user.id",
        "pop_return_to(conn, params[\"state\"])",
        "inspect(kind(reason))"
      ])
      |> assert_code("lib/test_web/router.ex", [
        """
        scope "/mcp-auth", TestWeb do
          pipe_through :browser

          post "/authorize", McpAuthController, :authorize
          get "/callback", McpAuthController, :callback
          delete "/connection", McpAuthController, :disconnect
        end
        """,
        ~s|forward "/client-metadata.json", AshAi.Mcp.OAuth.ClientMetadataPlug|
      ])
    end
  end

  test "without a user resource, tokens are keyed by an encoded owner and no routes are added" do
    igniter =
      project()
      |> Igniter.compose_task("ash_ai.gen.mcp_oauth", [])
      |> apply_igniter!()
      |> assert_code("lib/test/mcp_auth/token.ex", "attribute :owner, :string, allow_nil?: false")
      |> assert_code("lib/test/mcp_auth/store.ex", "owner == ^Jason.encode!(owner)")
      |> assert_code("lib/test/mcp_auth.ex", "Ash.Query.filter(owner == ^Jason.encode!(owner))")

    refute source(igniter, "lib/test/mcp_auth/token.ex") =~ "belongs_to"
    refute Rewrite.has_source?(igniter.rewrite, @controller)
  end

  test "uses an existing vault instead of generating one" do
    project()
    |> Igniter.Project.Module.create_module(Test.Secrets, "use Cloak.Vault, otp_app: :test")
    |> apply_igniter!()
    |> Igniter.compose_task("ash_ai.gen.mcp_oauth", ["--vault", "Test.Secrets"])
    |> refute_creates("lib/test/vault.ex")
    |> apply_igniter!()
    |> assert_code("lib/test/mcp_auth/token.ex", "vault Test.Secrets")
  end

  test "needs an AshPostgres repo" do
    phx_test_project()
    |> Igniter.compose_task("ash_ai.gen.mcp_oauth", [])
    |> assert_has_issue("ash_ai.gen.mcp_oauth needs an AshPostgres repo.")
  end
end
