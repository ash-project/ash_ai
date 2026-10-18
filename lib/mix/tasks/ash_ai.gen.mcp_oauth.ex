# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule Mix.Tasks.AshAi.Gen.McpOauth.Docs do
  @moduledoc false

  def short_doc do
    "Generates encrypted storage and routes for connecting to MCP servers that use OAuth"
  end

  def example do
    "mix ash_ai.gen.mcp_oauth --user MyApp.Accounts.User"
  end

  def long_doc do
    """
    #{short_doc()}

    `AshAi.Mcp.OAuth` keeps tokens, client registrations, and authorizations in
    progress in an `AshAi.Mcp.OAuth.Store` that your application provides. This
    generates one backed by `ash_postgres`, with the secrets encrypted by
    `ash_cloak`, and the routes that send a user to authorize an MCP server and
    bring them back. See the "MCP Client Authorization" guide to write a store of
    your own instead.

    ## Example

    ```bash
    #{example()}
    ```

    ## Options

    * `--user` - The user resource whose tokens are stored. Defaults to `YourApp.Accounts.User`
      when it exists. Tokens then belong to a user and are deleted with them, and the routes are
      generated, reading the user from `conn.assigns.current_user`. Without a user resource, tokens
      are stored under an opaque owner and the routes are left to you.
    * `--domain` - The domain for the generated resources. Defaults to `YourApp.McpAuth`.
    * `--vault` - The `Cloak.Vault` that encrypts the secrets. Defaults to `YourApp.Vault`, which
      is generated if it doesn't exist.
    * `--route` - Where the routes are mounted. Defaults to `/mcp-auth`.
    * `--yes` - Skip confirmation prompts.

    ## What gets generated

    * The `ash_cloak` and `cloak` dependencies.
    * A vault, unless one exists, started by your application. Its key is configured in
      `config/dev.exs` and `config/test.exs`, and read from the `CLOAK_KEY` environment variable
      in production.
    * Resources whose `data` is encrypted:
      * `Token` - the tokens a user holds for an MCP server, deleted with the user.
      * `Client` - clients registered for each MCP server through Dynamic Client Registration.
      * `PendingAuthorization` - authorizations in progress, keyed by a digest of their `state`.
        Abandoned ones are deleted after an hour.
    * `YourApp.McpAuth.Store`, the `AshAi.Mcp.OAuth.Store`. Token refreshes take a lease on the
      token row, so they're serialized across nodes without holding a database connection.
    * `YourApp.McpAuth.options/1`, the `AshAi.Mcp.OAuth` options for a user,
      `YourApp.McpAuth.allowed_private_hosts/0`, which allows `localhost` in development, and
      `YourApp.McpAuth.disconnect_all/1`, which revokes a user's tokens. Call it before deleting a
      user, since deleting the user deletes their tokens without revoking them.
    * With a user resource and a Phoenix router, `YourAppWeb.McpAuthController` and its routes:
      * `POST /mcp-auth/authorize` sends the user to authorize an MCP server.
      * `GET /mcp-auth/callback` stores the token and sends the user back.
      * `DELETE /mcp-auth/connection` disconnects the user from an MCP server, revoking their
        tokens there.
      * `GET /mcp-auth/client-metadata.json` serves the Client ID Metadata Document, which
        authorization servers are offered when your endpoint's URL is HTTPS.
    """
  end
end

if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.AshAi.Gen.McpOauth do
    @shortdoc "#{__MODULE__.Docs.short_doc()}"

    @moduledoc __MODULE__.Docs.long_doc()

    use Igniter.Mix.Task

    @impl Igniter.Mix.Task
    def info(_argv, _composing_task) do
      %Igniter.Mix.Task.Info{
        group: :ash_ai,
        example: __MODULE__.Docs.example(),
        composes: ["ash.gen.domain"],
        schema: [user: :string, domain: :string, vault: :string, route: :string, yes: :boolean],
        defaults: [route: "/mcp-auth", yes: false]
      }
    end

    @impl Igniter.Mix.Task
    def igniter(igniter) do
      if Code.ensure_loaded?(AshPostgres.Igniter) do
        {igniter, repo} =
          AshPostgres.Igniter.select_repo(igniter,
            label: "Which repo should store MCP OAuth credentials?"
          )

        if repo do
          generate(igniter, repo)
        else
          Igniter.add_issue(igniter, "ash_ai.gen.mcp_oauth needs an AshPostgres repo.")
        end
      else
        Igniter.add_issue(igniter, """
        ash_ai.gen.mcp_oauth stores credentials with ash_postgres. Install it first:

            mix igniter.install ash_postgres
        """)
      end
    end

    defp generate(igniter, repo) do
      {igniter, user} = user_module(igniter)
      domain = module_option(igniter, :domain, "McpAuth")

      names = %{
        otp_app: Igniter.Project.Application.app_name(igniter),
        app_name: inspect(Igniter.Project.Module.module_name_prefix(igniter)),
        repo: repo,
        user: user,
        domain: domain,
        vault: module_option(igniter, :vault, "Vault"),
        token: Module.concat(domain, Token),
        client: Module.concat(domain, Client),
        pending: Module.concat(domain, PendingAuthorization),
        store: Module.concat(domain, Store),
        route: String.trim_trailing(igniter.args.options[:route], "/")
      }

      {igniter, web} = web(igniter, user)

      igniter
      |> ensure_deps()
      |> Igniter.Project.Formatter.import_dep(:ash_cloak)
      |> ensure_vault(names)
      |> Igniter.compose_task("ash.gen.domain", [inspect(domain), "--ignore-if-exists"])
      |> create_resource(names.token, token_contents(names), names)
      |> create_resource(names.client, client_contents(names), names)
      |> create_resource(names.pending, pending_contents(names), names)
      |> Igniter.Project.Module.create_module(names.store, store_contents(names))
      |> add_options(names, web)
      |> add_web(names, web)
      |> Igniter.Project.Config.configure(
        "dev.exs",
        names.otp_app,
        [:mcp_allowed_private_hosts],
        ["localhost"]
      )
      |> Ash.Igniter.codegen("add_mcp_oauth")
      |> Igniter.add_notice(notice(names, web))
    end

    defp ensure_deps(igniter) do
      missing =
        Enum.reject([ash_cloak: "~> 0.4", cloak: "~> 1.1"], fn {dep, _requirement} ->
          Igniter.Project.Deps.has_dep?(igniter, dep)
        end)

      igniter =
        Enum.reduce(missing, igniter, fn dep, igniter ->
          Igniter.Project.Deps.add_dep(igniter, dep)
        end)

      if missing == [] or igniter.assigns[:test_mode?] do
        igniter
      else
        Igniter.apply_and_fetch_dependencies(igniter, yes: igniter.args.options[:yes])
      end
    end

    defp ensure_vault(igniter, names) do
      {exists?, igniter} = Igniter.Project.Module.module_exists(igniter, names.vault)

      if exists? do
        igniter
      else
        igniter
        |> Igniter.Project.Module.create_module(names.vault, """
        @moduledoc "Encrypts data at rest. Its key is configured for each environment in `config/`."

        use Cloak.Vault, otp_app: :#{names.otp_app}
        """)
        |> Igniter.Project.Application.add_new_child(names.vault)
        |> configure_cipher("dev.exs", names, generated_key())
        |> configure_cipher("test.exs", names, generated_key())
        |> Igniter.Project.Config.configure_runtime_env(
          :prod,
          names.otp_app,
          [names.vault, :ciphers],
          {:code,
           ciphers("""
           Base.decode64!(
             System.get_env("CLOAK_KEY") ||
               raise "environment variable CLOAK_KEY is missing. Generate a key with: 32 |> :crypto.strong_rand_bytes() |> Base.encode64()"
           )
           """)}
        )
      end
    end

    defp configure_cipher(igniter, file, names, key) do
      Igniter.Project.Config.configure(
        igniter,
        file,
        names.otp_app,
        [names.vault, :ciphers],
        {:code, ciphers(key)}
      )
    end

    defp generated_key do
      ~s|Base.decode64!("#{Base.encode64(:crypto.strong_rand_bytes(32))}")|
    end

    defp ciphers(key) do
      Sourceror.parse_string!("""
      [default: {Cloak.Ciphers.AES.GCM, tag: "AES.GCM.V1", key: #{String.trim(key)}, iv_length: 12}]
      """)
    end

    defp create_resource(igniter, resource, contents, names) do
      igniter
      |> Igniter.Project.Module.create_module(resource, contents)
      |> Ash.Domain.Igniter.add_resource_reference(names.domain, resource)
    end

    defp resource_header(names, table) do
      """
      use Ash.Resource,
        otp_app: :#{names.otp_app},
        domain: #{inspect(names.domain)},
        data_layer: AshPostgres.DataLayer,
        extensions: [AshCloak]

      postgres do
        table "#{table}"
        repo #{inspect(names.repo)}
      #{if names[:references], do: names.references}
      end

      cloak do
        vault #{inspect(names.vault)}
        attributes [:data]
        decrypt_by_default [:data]
      end
      """
    end

    # The lease the store's `with_lock/4` takes on a token row while it
    # refreshes or revokes the tokens
    defp lease_actions do
      """
        update :lock_refresh do
          argument :lock, :string, allow_nil?: false
          change set_attribute(:refresh_lock, arg(:lock))
          change atomic_update(:refresh_locked_until, expr(from_now(60, :second)))
        end

        update :unlock_refresh do
          change set_attribute(:refresh_lock, nil)
          change set_attribute(:refresh_locked_until, nil)
        end
      """
    end

    defp lease_attributes do
      """
        # A lease on refreshing these tokens, taken by the store's `with_lock/4`
        attribute :refresh_lock, :string
        attribute :refresh_locked_until, :utc_datetime_usec
      """
    end

    defp token_contents(%{user: nil} = names) do
      ~s'''
      @moduledoc """
      The OAuth tokens an owner holds for an MCP server, stored by
      `#{inspect(names.store)}`. `owner` is the owner given to `AshAi.Mcp.OAuth`,
      JSON-encoded, and `data` is an `AshAi.Mcp.OAuth.Token` as
      `AshAi.Mcp.OAuth.Token.to_map/1` returns it, encrypted.
      """

      #{resource_header(names, "mcp_oauth_tokens")}

      actions do
        defaults [:read, :destroy]

        create :upsert do
          accept [:server, :owner, :data]
          upsert? true
          upsert_identity :unique_owner
          upsert_fields [:encrypted_data, :updated_at]
        end

      #{lease_actions()}
      end

      attributes do
        uuid_v7_primary_key :id
        attribute :server, :string, allow_nil?: false
        attribute :owner, :string, allow_nil?: false
        attribute :data, :map, allow_nil?: false, sensitive?: true
      #{lease_attributes()}
        timestamps()
      end

      identities do
        identity :unique_owner, [:server, :owner]
      end
      '''
    end

    defp token_contents(names) do
      names =
        Map.put(names, :references, """
          references do
            reference :user, on_delete: :delete
          end
        """)

      ~s'''
      @moduledoc """
      The OAuth tokens a user holds for an MCP server, stored by
      `#{inspect(names.store)}` and deleted with the user. `data` is an
      `AshAi.Mcp.OAuth.Token` as `AshAi.Mcp.OAuth.Token.to_map/1` returns it,
      encrypted.
      """

      #{resource_header(names, "mcp_oauth_tokens")}

      actions do
        defaults [:read, :destroy]

        create :upsert do
          accept [:server, :user_id, :data]
          upsert? true
          upsert_identity :unique_owner
          upsert_fields [:encrypted_data, :updated_at]
        end

      #{lease_actions()}
      end

      attributes do
        uuid_v7_primary_key :id
        attribute :server, :string, allow_nil?: false
        attribute :data, :map, allow_nil?: false, sensitive?: true
      #{lease_attributes()}
        timestamps()
      end

      relationships do
        belongs_to :user, #{inspect(names.user)}, allow_nil?: false
      end

      identities do
        identity :unique_owner, [:server, :user_id]
      end
      '''
    end

    defp client_contents(names) do
      ~s'''
      @moduledoc """
      An OAuth client registered for an MCP server through Dynamic Client
      Registration, stored by `#{inspect(names.store)}`. `data` is an
      `AshAi.Mcp.OAuth.Client` as `AshAi.Mcp.OAuth.Client.to_map/1` returns it,
      encrypted.
      """

      #{resource_header(names, "mcp_oauth_clients")}

      actions do
        defaults [:read]

        create :upsert do
          accept [:server, :issuer, :data]
          upsert? true
          upsert_identity :unique_server_issuer
          upsert_fields [:encrypted_data, :updated_at]
        end
      end

      attributes do
        uuid_v7_primary_key :id
        attribute :server, :string, allow_nil?: false
        attribute :issuer, :string, allow_nil?: false
        attribute :data, :map, allow_nil?: false, sensitive?: true
        timestamps()
      end

      identities do
        identity :unique_server_issuer, [:server, :issuer]
      end
      '''
    end

    defp pending_contents(names) do
      ~s'''
      @moduledoc """
      An authorization in progress, from `AshAi.Mcp.OAuth.authorize_url/3` until
      the callback, stored by `#{inspect(names.store)}`. `id` is a digest of its
      `state`, and `data` is an `AshAi.Mcp.OAuth.Pending` as
      `AshAi.Mcp.OAuth.Pending.to_map/1` returns it, encrypted, since it holds the
      PKCE verifier.
      """

      #{resource_header(names, "mcp_oauth_pending_authorizations")}

      actions do
        defaults [:read, :destroy, create: [:id, :data]]
      end

      attributes do
        attribute :id, :string, primary_key?: true, allow_nil?: false
        attribute :data, :map, allow_nil?: false, sensitive?: true
        create_timestamp :inserted_at
      end
      '''
    end

    defp store_contents(names) do
      {owner_field, owner_value} =
        if names.user, do: {"user_id", "owner"}, else: {"owner", "Jason.encode!(owner)"}

      ~s'''
      @moduledoc """
      The `AshAi.Mcp.OAuth.Store` for `#{inspect(names.domain)}`'s resources.

      Their secrets are encrypted with `#{inspect(names.vault)}`. Token refreshes
      run under a lease on the token row, so a rotating refresh token is spent
      once even with several nodes.
      """

      @behaviour AshAi.Mcp.OAuth.Store

      require Ash.Query
      import Ash.Expr, only: [expr: 1]

      alias AshAi.Mcp.OAuth
      alias #{inspect(names.domain)}.{Client, PendingAuthorization, Token}

      # Pending authorizations are rejected after `:pending_ttl` (10 minutes by
      # default). Abandoned ones are deleted once they are this old.
      @prune_pending_after_seconds 3_600

      # How long a request waits for another's refresh before giving up
      @lock_wait_ms 30_000

      @impl true
      def get_token(server, owner, _opts) do
        Token
        |> Ash.Query.filter(server == ^server and #{owner_field} == ^#{owner_value})
        |> Ash.read_one!(authorize?: false)
        |> from_record(&OAuth.Token.from_map/1)
      end

      @impl true
      def put_token(server, owner, token, _opts) do
        Token
        |> Ash.Changeset.for_create(:upsert, %{
          server: server,
          #{owner_field}: #{owner_value},
          data: OAuth.Token.to_map(token)
        })
        |> Ash.create(authorize?: false)
        |> ok()
      end

      @impl true
      def delete_token(server, owner, _opts) do
        Token
        |> Ash.Query.filter(server == ^server and #{owner_field} == ^#{owner_value})
        |> Ash.bulk_destroy!(:destroy, %{}, authorize?: false, strategy: [:atomic, :stream])

        :ok
      end

      @impl true
      def get_client(server, issuer, _opts) do
        Client
        |> Ash.Query.filter(server == ^server and issuer == ^issuer)
        |> Ash.read_one!(authorize?: false)
        |> from_record(&OAuth.Client.from_map/1)
      end

      @impl true
      def put_client(server, client, _opts) do
        Client
        |> Ash.Changeset.for_create(:upsert, %{
          server: server,
          issuer: client.issuer,
          data: OAuth.Client.to_map(client)
        })
        |> Ash.create(authorize?: false)
        |> ok()
      end

      # Refreshing or revoking tokens takes requests to the authorization server,
      # so it runs under a lease on the token row rather than a database lock: a
      # lock would hold a connection while others wait and while the requests
      # run, which a slow authorization server could turn into an exhausted
      # connection pool. The lease lasts 60 seconds, so one left by a crashed
      # process expires.
      @impl true
      def with_lock(server, owner, fun, _opts) do
        lock = Ash.UUID.generate()
        deadline = System.monotonic_time(:millisecond) + @lock_wait_ms

        case acquire(server, owner, lock, deadline) do
          :acquired ->
            try do
              fun.()
            after
              release(server, owner, lock)
            end

          # No tokens means nothing to refresh or revoke
          :no_token ->
            fun.()

          :timeout ->
            {:error, :refresh_in_progress}
        end
      end

      # One conditional update takes the lease, and waiting holds nothing
      defp acquire(server, owner, lock, deadline) do
        case token_record(server, owner) do
          nil ->
            :no_token

          token ->
            token
            |> Ash.Changeset.for_update(:lock_refresh, %{lock: lock})
            |> Ash.Changeset.filter(
              expr(is_nil(refresh_locked_until) or refresh_locked_until < now())
            )
            |> Ash.update(authorize?: false)
            |> case do
              {:ok, _token} ->
                :acquired

              {:error, error} ->
                cond do
                  not stale?(error) -> raise Ash.Error.to_error_class(error)
                  System.monotonic_time(:millisecond) >= deadline -> :timeout
                  true -> Process.sleep(100) && acquire(server, owner, lock, deadline)
                end
            end
        end
      end

      # Only this lease, in case it expired and someone else holds a new one
      defp release(server, owner, lock) do
        Token
        |> Ash.Query.filter(
          server == ^server and #{owner_field} == ^#{owner_value} and refresh_lock == ^lock
        )
        |> Ash.bulk_update!(:unlock_refresh, %{}, authorize?: false, strategy: [:atomic, :stream])
      end

      defp token_record(server, owner) do
        Token
        |> Ash.Query.filter(server == ^server and #{owner_field} == ^#{owner_value})
        |> Ash.read_one!(authorize?: false)
      end

      # The update's filter didn't match: someone else holds the lease
      defp stale?(error) do
        error
        |> Ash.Error.to_error_class()
        |> Map.get(:errors, [])
        |> Enum.any?(&is_struct(&1, Ash.Error.Changes.StaleRecord))
      end

      @impl true
      def put_pending(pending, _opts) do
        prune_pending()

        PendingAuthorization
        |> Ash.Changeset.for_create(:create, %{
          id: pending_id(pending.state),
          data: OAuth.Pending.to_map(pending)
        })
        |> Ash.create(authorize?: false)
        |> ok()
      end

      # Reading under a row lock and deleting in the same transaction hands each
      # pending authorization to one caller only
      @impl true
      def take_pending(state, _opts) do
        {:ok, result} =
          #{inspect(names.repo)}.transaction(fn ->
            PendingAuthorization
            |> Ash.Query.filter(id == ^pending_id(state))
            |> Ash.Query.lock(:for_update)
            |> Ash.read_one!(authorize?: false)
            |> case do
              nil ->
                :error

              record ->
                Ash.destroy!(record, authorize?: false)
                {:ok, OAuth.Pending.from_map(record.data)}
            end
          end)

        result
      end

      # Only a digest of `state` is stored, so the table doesn't hold usable values
      defp pending_id(state), do: Base.url_encode64(:crypto.hash(:sha256, state), padding: false)

      defp prune_pending do
        PendingAuthorization
        |> Ash.Query.filter(inserted_at < ago(@prune_pending_after_seconds, :second))
        |> Ash.bulk_destroy!(:destroy, %{}, authorize?: false, strategy: [:atomic, :stream])
      end

      defp from_record(nil, _from_map), do: :error
      defp from_record(record, from_map), do: {:ok, from_map.(record.data)}

      defp ok({:ok, _record}), do: :ok
      defp ok({:error, error}), do: {:error, error}
      '''
    end

    defp add_options(igniter, names, web) do
      Igniter.Project.Module.find_and_update_module!(igniter, names.domain, fn zipper ->
        case Igniter.Code.Function.move_to_def(zipper, :options, 1) do
          {:ok, _zipper} -> {:ok, zipper}
          :error -> {:ok, Igniter.Code.Common.add_code(zipper, options_contents(names, web))}
        end
      end)
    end

    defp options_contents(names, web) do
      {base_url, client_metadata} =
        if web do
          {"#{inspect(web.endpoint)}.url()",
           """

           # Authorization servers fetch the Client ID Metadata Document
           # themselves, so it's only offered from a public HTTPS URL
           defp client_metadata("https://" <> _ = base_url),
             do: [client_metadata_url: base_url <> "#{names.route}/client-metadata.json"]

           defp client_metadata(_base_url), do: []
           """}
        else
          {~s|"https://your-app.example" # TODO: your application's URL|,
           "\ndefp client_metadata(_base_url), do: []\n"}
        end

      {owner_doc, owner_filter, disconnect_doc} =
        if names.user do
          {"the id of the user whose tokens to use", "user_id == ^owner",
           "Call it before deleting a user, since deleting the user deletes their tokens\nwithout revoking them."}
        else
          {"whose tokens to use", "owner == ^Jason.encode!(owner)",
           "Call it when an owner goes away, before deleting their tokens."}
        end

      ~s'''
      @doc """
      The `AshAi.Mcp.OAuth` options for `owner`, #{owner_doc}.

      Use them as an MCP server's auth, and pass them to
      `AshAi.Mcp.OAuth.authorize_url/3` and `AshAi.Mcp.OAuth.handle_callback/3`:

          AshAi.Mcp.Client.server(
            name: "linear",
            url: "https://mcp.linear.app/mcp",
            auth: {AshAi.Mcp.OAuth, #{inspect(names.domain)}.options(user.id)},
            allowed_private_hosts: #{inspect(names.domain)}.allowed_private_hosts()
          )
      """
      def options(owner) do
        base_url = #{base_url}

        [
          store: #{inspect(names.store)},
          owner: owner,
          redirect_uri: base_url <> "#{names.route}/callback",
          client_name: "#{names.app_name}",
          allowed_private_hosts: allowed_private_hosts()
        ] ++ client_metadata(base_url)
      end

      @doc """
      Hosts that MCP servers and authorization servers may resolve to on a
      private network, set with `config :#{names.otp_app}, :mcp_allowed_private_hosts`.
      Development allows `localhost`.
      """
      def allowed_private_hosts,
        do: Application.get_env(:#{names.otp_app}, :mcp_allowed_private_hosts, [])

      @doc """
      Disconnects `owner` from every MCP server they're connected to, revoking
      their tokens where the servers support it, and returns each server's
      `AshAi.Mcp.OAuth.disconnect/3` result.

      #{disconnect_doc}
      """
      def disconnect_all(owner) do
        require Ash.Query

        #{inspect(names.token)}
        |> Ash.Query.filter(#{owner_filter})
        |> Ash.read!(authorize?: false)
        |> Map.new(&{&1.server, AshAi.Mcp.OAuth.disconnect(&1.server, owner, options(owner))})
      end
      #{client_metadata}
      '''
    end

    defp web(igniter, nil), do: {igniter, nil}

    defp web(igniter, _user) do
      {igniter, router} =
        Igniter.Libs.Phoenix.select_router(
          igniter,
          "Which router should the MCP OAuth routes be added to?"
        )

      if router do
        {igniter, endpoints} = Igniter.Libs.Phoenix.endpoints_for_router(igniter, router)

        case endpoints do
          [endpoint | _] ->
            {igniter,
             %{
               router: router,
               endpoint: endpoint,
               web_module: Igniter.Libs.Phoenix.web_module(igniter),
               controller: Igniter.Libs.Phoenix.web_module_name(igniter, "McpAuthController")
             }}

          [] ->
            {Igniter.add_warning(
               igniter,
               "No endpoint uses #{inspect(router)}, so the MCP OAuth routes weren't added."
             ), nil}
        end
      else
        {Igniter.add_warning(
           igniter,
           "No Phoenix router was found or selected, so the MCP OAuth routes weren't added."
         ), nil}
      end
    end

    defp add_web(igniter, _names, nil), do: igniter

    defp add_web(igniter, names, web) do
      igniter
      |> Igniter.Project.Module.create_module(web.controller, controller_contents(names, web))
      |> Igniter.Libs.Phoenix.add_scope(
        names.route,
        """
        pipe_through :browser

        post "/authorize", McpAuthController, :authorize
        get "/callback", McpAuthController, :callback
        delete "/connection", McpAuthController, :disconnect
        """,
        router: web.router,
        arg2: web.web_module
      )
      |> Igniter.Libs.Phoenix.add_scope(
        names.route,
        """
        forward "/client-metadata.json", AshAi.Mcp.OAuth.ClientMetadataPlug,
          {#{inspect(names.domain)}, :options, [nil]}
        """,
        router: web.router
      )
    end

    defp controller_contents(names, web) do
      ~s'''
      @moduledoc """
      Connects users to MCP servers that use OAuth.

      `POST #{names.route}/authorize` sends the user to authorize an MCP server. It
      takes `server_url`, and optionally `return_to`, a path in this app to come
      back to, and `challenge`, the `www_authenticate` of an
      `{:authorization_required, info}` or `{:insufficient_scope, info}` error. A
      paused `AshAi.ToolLoop` carries those errors in `paused_calls`. For example:

          <.form for={%{}} action={~p"#{names.route}/authorize"} method="post">
            <input type="hidden" name="server_url" value={@server_url} />
            <input type="hidden" name="return_to" value={@return_to} />
            <input type="hidden" name="challenge" value={@info.www_authenticate} />
            <.button>Connect</.button>
          </.form>

      `GET #{names.route}/callback` is where the authorization server sends the
      user back. It stores the token and redirects to `return_to`.

      `DELETE #{names.route}/connection` disconnects the user from an MCP server,
      revoking their tokens there when it supports revocation. It takes
      `server_url`, and optionally `return_to`:

          <.form for={%{}} action={~p"#{names.route}/connection"} method="delete">
            <input type="hidden" name="server_url" value={@server_url} />
            <.button>Disconnect</.button>
          </.form>
      """

      use #{inspect(web.web_module)}, :controller

      require Logger

      plug :require_user

      def authorize(conn, %{"server_url" => server_url} = params) do
        user = conn.assigns.current_user
        return_to = return_to(params["return_to"])
        options = #{inspect(names.domain)}.options(user.id) ++ challenge(params["challenge"])

        case AshAi.Mcp.OAuth.authorize_url(server_url, user.id, options) do
          {:ok, url, pending} ->
            conn
            |> put_return_to(pending.state, return_to)
            |> redirect(external: url)

          {:error, reason} ->
            Logger.warning(
              "Couldn't start authorizing \#{inspect(server_url)}: \#{inspect(kind(reason))}"
            )

            conn
            |> put_flash(:error, "Couldn't connect to that MCP server.")
            |> redirect(to: return_to)
        end
      end

      def callback(conn, params) do
        user = conn.assigns.current_user
        {return_to, conn} = pop_return_to(conn, params["state"])

        # Completes only for the user who started the authorization
        case AshAi.Mcp.OAuth.handle_callback(params, user.id, #{inspect(names.domain)}.options(user.id)) do
          {:ok, _token, _pending} ->
            conn
            |> put_flash(:info, "Connected.")
            |> redirect(to: return_to)

          {:error, reason} ->
            Logger.warning("Couldn't complete an MCP authorization: \#{inspect(kind(reason))}")

            conn
            |> put_flash(:error, "Couldn't connect to that MCP server.")
            |> redirect(to: return_to)
        end
      end

      def disconnect(conn, %{"server_url" => server_url} = params) do
        user = conn.assigns.current_user
        return_to = return_to(params["return_to"])

        case AshAi.Mcp.OAuth.disconnect(server_url, user.id, #{inspect(names.domain)}.options(user.id)) do
          {:ok, _result} ->
            conn
            |> put_flash(:info, "Disconnected.")
            |> redirect(to: return_to)

          # The tokens are deleted even when the server couldn't revoke them
          {:error, {:revocation_failed, reason}} ->
            Logger.warning(
              "Couldn't revoke access to \#{inspect(server_url)}: \#{inspect(kind(reason))}"
            )

            conn
            |> put_flash(
              :info,
              "Disconnected. The MCP server couldn't revoke access, so you may want to revoke it in its settings too."
            )
            |> redirect(to: return_to)

          {:error, reason} ->
            Logger.warning(
              "Couldn't disconnect from \#{inspect(server_url)}: \#{inspect(kind(reason))}"
            )

            conn
            |> put_flash(:error, "Couldn't disconnect from that MCP server.")
            |> redirect(to: return_to)
        end
      end

      defp require_user(conn, _opts) do
        if conn.assigns[:current_user] do
          conn
        else
          conn
          |> put_flash(:error, "Sign in to connect an MCP server.")
          |> redirect(to: "/")
          |> halt()
        end
      end

      defp challenge(challenge) when is_binary(challenge) and challenge != "",
        do: [challenge: challenge]

      defp challenge(_challenge), do: []

      # Only paths in this app, so the redirect can't be aimed elsewhere
      defp return_to("/" <> _ = path) do
        if String.starts_with?(path, "//") or String.contains?(path, "\\\\"),
          do: "/",
          else: path
      end

      defp return_to(_path), do: "/"

      # Each authorization in progress returns to its own page, for the few
      # most recent ones, so two at once don't send the user to the wrong place
      defp put_return_to(conn, state, return_to) do
        put_session(conn, :mcp_oauth_return_to, Enum.take([{state, return_to} | return_tos(conn)], 5))
      end

      defp pop_return_to(conn, state) do
        case List.keytake(return_tos(conn), state, 0) do
          {{_state, return_to}, rest} -> {return_to, put_session(conn, :mcp_oauth_return_to, rest)}
          nil -> {"/", conn}
        end
      end

      defp return_tos(conn) do
        case get_session(conn, :mcp_oauth_return_to) do
          return_tos when is_list(return_tos) -> return_tos
          _other -> []
        end
      end

      # Errors can carry text from the MCP server or its authorization server,
      # so only their kind is logged
      defp kind(reason) when is_tuple(reason) and is_atom(elem(reason, 0)), do: elem(reason, 0)
      defp kind(reason) when is_atom(reason), do: reason
      defp kind(_reason), do: :error
      '''
    end

    defp notice(names, web) do
      routes =
        if web do
          """
          When an MCP call returns `{:error, {:authorization_required, info}}` (or a tool
          loop pauses with it), POST `server_url`, `return_to`, and `challenge`
          (`info.www_authenticate`) to #{names.route}/authorize. DELETE `server_url` to
          #{names.route}/connection to disconnect. See `#{inspect(web.controller)}`.

          Call `#{inspect(names.domain)}.disconnect_all(user.id)` before deleting a user, so
          their tokens are revoked and not just deleted.
          """
        else
          """
          No routes were generated. Add a callback route at #{names.route}/callback that calls
          `AshAi.Mcp.OAuth.handle_callback/3` with the signed-in owner, and send users to
          `AshAi.Mcp.OAuth.authorize_url/3`. Then set the URL in `#{inspect(names.domain)}.options/1`.
          """
        end

      """
      AshAi MCP OAuth:

      Credentials are encrypted with #{inspect(names.vault)}. Set the CLOAK_KEY
      environment variable in production (generate a key with
      `32 |> :crypto.strong_rand_bytes() |> Base.encode64()`), and keep it: tokens
      encrypted with a lost key can't be read, and users have to authorize again.

      Use `#{inspect(names.domain)}.options(user.id)` as an MCP server's auth:

          AshAi.Mcp.Client.server(
            name: "linear",
            url: "https://mcp.linear.app/mcp",
            auth: {AshAi.Mcp.OAuth, #{inspect(names.domain)}.options(user.id)},
            allowed_private_hosts: #{inspect(names.domain)}.allowed_private_hosts()
          )

      #{routes}
      """
    end

    defp module_option(igniter, option, default_suffix) do
      case igniter.args.options[option] do
        nil -> Igniter.Project.Module.module_name(igniter, default_suffix)
        module -> Igniter.Project.Module.parse(module)
      end
    end

    defp user_module(igniter) do
      if igniter.args.options[:user] do
        {igniter, Igniter.Project.Module.parse(igniter.args.options[:user])}
      else
        default = Igniter.Project.Module.module_name(igniter, "Accounts.User")
        {exists?, igniter} = Igniter.Project.Module.module_exists(igniter, default)
        {igniter, if(exists?, do: default)}
      end
    end
  end
else
  defmodule Mix.Tasks.AshAi.Gen.McpOauth do
    @shortdoc "#{__MODULE__.Docs.short_doc()} | Install `igniter` to use"

    @moduledoc __MODULE__.Docs.long_doc()

    use Mix.Task

    def run(_argv) do
      Mix.shell().error("""
      The task 'ash_ai.gen.mcp_oauth' requires igniter. Please install igniter and try again.

      For more information, see: https://hexdocs.pm/igniter/readme.html#installation
      """)

      exit({:shutdown, 1})
    end
  end
end
