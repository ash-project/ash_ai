# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule Mix.Tasks.AshAi.Gen.Chat.Docs do
  @moduledoc false

  def short_doc do
    "Generates the resources and views for a conversational UI backed by `ash_postgres` and `ash_oban`"
  end

  def example do
    "mix ash_ai.gen.chat --user Your.User.Resource --live"
  end

  def long_doc do
    """
    #{short_doc()}

    Creates a `YourApp.Chat.Conversation` and a `YourApp.Chat.Message` resource, backed by postgres and ash_oban.

    ## Examples

    ### Resources only, no UI:

    ```bash
    mix ash_ai.gen.chat --user MyApp.Accounts.User
    # Creates: MyApp.Chat domain with Conversation and Message resources
    ```

    ### Full-page LiveView with a named domain and Anthropic provider:

    ```bash
    mix ash_ai.gen.chat --user MyApp.Accounts.User --live --provider anthropic --domain MyApp.SupportChat
    # Creates: MyApp.SupportChat resources and SupportChatLive mounted at /chat
    ```

    ### Embeddable LiveComponent with a custom domain and Gemini provider:

    ```bash
    mix ash_ai.gen.chat --user MyApp.Accounts.User --live-component --domain MyApp.SupportChat --provider gemini
    # Creates: MyApp.SupportChat resources and SupportChatComponent
    ```

    ### Both LiveView and LiveComponent with all options:

    ```bash
    mix ash_ai.gen.chat --user MyApp.Accounts.User --live --live-component --domain MyApp.SupportChat --route /support/chat --provider anthropic
    # Creates: MyApp.SupportChat resources, SupportChatLive at /support/chat, and SupportChatComponent
    ```

    ## Options

    * `--user` - The user resource.
    * `--domain` - The domain module to place the resources in. E.g., `--domain MyApp.SupportChat` generates `MyApp.SupportChat.Conversation` and `MyApp.SupportChat.Message`. Defaults to `YourApp.Chat`.
    * `--route` - A URL prefix for the chat routes. E.g., `--route support` mounts routes at `/support/chat`.
    * `--provider` - The LLM provider to use: `openai` (default), `anthropic`, or `gemini`.
    * `--extend` - Extensions to apply to the generated resources, passed through to `mix ash.gen.resource`.
    * `--live` - Generate a full-page Phoenix LiveView for the chat UI.
    * `--live-component` - Generate a reusable Phoenix LiveComponent for embedding the chat UI in existing pages.

    ## Tool Call/Result UI Extraction

    Generated chat UI modules delegate tool call and tool result parsing to `AshAi.ChatUI.Tools.extract/1`.
    This keeps generated modules small while preserving a stable override seam.

    Override in generated modules if you need custom parsing:

    ```elixir
    @chat_ui_tools MyApp.ChatUITools
    ```

    ## Starter Tools

    Generated chat domains include a small default tool set so tool calling works immediately:

    * `:chat_list_conversations` - lists conversations visible to the actor.
    * `:chat_message_history` - fetches messages for a specific conversation.

    Add your own domain tools for app-specific behavior.
    """
  end
end

if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.AshAi.Gen.Chat do
    @shortdoc "#{__MODULE__.Docs.short_doc()}"

    @moduledoc __MODULE__.Docs.long_doc()

    use Igniter.Mix.Task

    @impl Igniter.Mix.Task
    def info(_argv, _composing_task) do
      %Igniter.Mix.Task.Info{
        group: :ash_ai,
        example: __MODULE__.Docs.example(),
        schema: [
          user: :string,
          domain: :string,
          route: :string,
          provider: :string,
          extend: :string,
          live: :boolean,
          live_component: :boolean,
          yes: :boolean
        ],
        defaults: [live: false, live_component: false, yes: false, provider: "openai"]
      }
    end

    @impl Igniter.Mix.Task
    def igniter(igniter) do
      {igniter, user} = user_module(igniter)

      chat =
        if igniter.args.options[:domain] do
          Igniter.Project.Module.parse(igniter.args.options[:domain])
        else
          Igniter.Project.Module.module_name(igniter, "Chat")
        end

      conversation = Module.concat([chat, Conversation])
      message = Module.concat([chat, Message])
      otp_app = Igniter.Project.Application.app_name(igniter)

      igniter
      |> ensure_deps(otp_app)
      |> configure()
      |> create_conversation(conversation, message, user)
      |> create_message(chat, conversation, message, otp_app)
      |> add_chat_live(chat, conversation, message, user)
      |> add_chat_live_component(chat, conversation, message, user)
      |> add_code_interfaces(chat, conversation, message, user)
      |> add_triggers(message, conversation, user)
      |> Ash.Igniter.codegen("add_ai_chat")
      |> Igniter.add_notice("""
      AshAi:

      The chat feature has been generated using the #{to_string(igniter.args.options[:provider])} provider via ReqLLM.
      Please see ReqLLM's documentation if you need to configure a different model or provider settings.
      Generated chat includes starter tools (`:chat_list_conversations`, `:chat_message_history`) so tool calling works out of the box.
      `tools: true` includes all tools available in your AshAi domains. Change to `tools: [:a, :list, :of, :tools]` to scope tool access.
      """)
      |> maybe_add_live_component_notice(chat)
    end

    defp ensure_deps(igniter, otp_app) do
      {igniter, install_ash_phoenix?} =
        if Igniter.Project.Deps.has_dep?(igniter, :ash_phoenix) do
          {igniter, false}
        else
          {Igniter.Project.Deps.add_dep(igniter, {:ash_phoenix, "~> 2.0"}), true}
        end

      {igniter, install_ash_oban?} =
        if Igniter.Project.Deps.has_dep?(igniter, :ash_oban) do
          {igniter, false}
        else
          {Igniter.Project.Deps.add_dep(igniter, {:ash_oban, "~> 0.4"}), true}
        end

      {igniter, install_mdex?} =
        if Igniter.Project.Deps.has_dep?(igniter, :mdex) do
          {igniter, false}
        else
          {Igniter.Project.Deps.add_dep(igniter, {:mdex, "~> 0.7"}), true}
        end

      igniter
      |> then(fn igniter ->
        if install_ash_phoenix? || install_ash_oban? || install_mdex? do
          if igniter.assigns[:test_mode?] do
            igniter
          else
            Igniter.apply_and_fetch_dependencies(igniter, yes: igniter.args.options[:yes])
          end
        else
          igniter
        end
      end)
      |> then(fn igniter ->
        if install_ash_phoenix? do
          Igniter.compose_task(igniter, "ash_phoenix.install")
        else
          igniter
        end
      end)
      |> then(fn igniter ->
        if install_ash_oban? do
          igniter
          |> Igniter.compose_task("oban.install")
          |> Igniter.compose_task("ash_oban.install")
        else
          igniter
        end
      end)
      |> Igniter.Project.Config.configure(
        "config.exs",
        otp_app,
        [Oban, :queues, :chat_responses, :limit],
        10
      )
      |> Igniter.Project.Config.configure(
        "config.exs",
        otp_app,
        [Oban, :queues, :conversations, :limit],
        10
      )
    end

    defp create_conversation(igniter, conversation, message, user) do
      generate_name = Module.concat([conversation, Changes, GenerateName])
      provider = llm_provider_config(igniter.args.options[:provider])

      relate_actor_change =
        if user do
          "    change relate_actor(:user)\n"
        else
          ""
        end

      igniter
      |> Igniter.compose_task(
        "ash.gen.resource",
        [
          inspect(conversation),
          "--attribute",
          "title:string:public",
          "--uuid-v7-primary-key",
          "id",
          "--default-actions",
          "read,destroy",
          "--relationship",
          "has_many:messages:#{inspect(message)}:public",
          "--timestamps",
          "--extend",
          "postgres,AshOban",
          "--extend",
          igniter.args.options[:extend] || ""
        ] ++
          user_relationship(user)
      )
      |> Ash.Resource.Igniter.add_new_action(conversation, :create, """
      create :create do
        accept [:title]
      #{relate_actor_change}      end
      """)
      |> Ash.Resource.Igniter.add_new_calculation(conversation, :needs_name, """
      calculate :needs_title, :boolean do
        calculation expr(is_nil(title) and (count(messages) > 3 or (count(messages) > 1 and inserted_at < ago(10, :minute))))
      end
      """)
      |> Ash.Resource.Igniter.add_new_action(conversation, :generate_name, """
      update :generate_name do
        accept []
        transaction? false
        require_atomic? false
        change #{inspect(generate_name)}
      end
      """)
      |> Igniter.Project.Module.create_module(generate_name, """
      use Ash.Resource.Change
      require Ash.Query

      alias ReqLLM.Context

      @impl true
      def change(changeset, _opts, context) do
        Ash.Changeset.before_transaction(changeset, fn changeset ->
          conversation = changeset.data

          messages =
            #{inspect(message)}
            |> Ash.Query.filter(conversation_id == ^conversation.id)
            |> Ash.Query.limit(10)
            |> Ash.Query.select([:text, :source])
            |> Ash.Query.sort(inserted_at: :asc)
            |> Ash.read!()

          prompt_messages =
            [
              Context.system(\"""
              Provide a short name for the current conversation.
              2-8 words, preferring more succinct names.
              RESPOND WITH ONLY THE NEW CONVERSATION NAME.
              \""")
            ] ++
              Enum.map(messages, fn message ->
                if message.source == :agent do
                  Context.assistant(message.text)
                else
                  Context.user(message.text)
                end
              end)

          ReqLLM.generate_text("#{provider.model}", prompt_messages)
          |> case do
            {:ok, response} ->
              Ash.Changeset.force_change_attribute(
                changeset,
                :title,
                ReqLLM.Response.text(response)
              )

            {:error, error} ->
              {:error, error}
          end
        end)
      end
      """)
      |> then(fn igniter ->
        if user do
          Ash.Resource.Igniter.add_new_action(igniter, conversation, :my_conversations, """
          read :my_conversations do
            filter expr(user_id == ^actor(:id))
          end
          """)
        else
          igniter
        end
      end)
    end

    defp create_message(igniter, chat, conversation, message, otp_app) do
      create_conversation_if_not_provided =
        Module.concat([message, Changes, CreateConversationIfNotProvided])

      respond = Module.concat([message, Changes, Respond])
      provider = llm_provider_config(igniter.args.options[:provider])

      source = Module.concat([message, Types, Source])

      igniter
      |> Igniter.compose_task("ash.gen.enum", [
        inspect(source),
        "agent,user"
      ])
      |> Igniter.compose_task(
        "ash.gen.resource",
        [
          inspect(message),
          "--default-actions",
          "read,destroy",
          "--relationship",
          "belongs_to:conversation:#{inspect(conversation)}:public:required",
          "--relationship",
          "belongs_to:response_to:__MODULE__:public",
          "--timestamps",
          "--extend",
          "postgres,AshOban",
          "--extend",
          igniter.args.options[:extend] || ""
        ]
      )
      |> Ash.Resource.Igniter.add_new_attribute(message, :id, """
      uuid_v7_primary_key :id, writable?: true
      """)
      |> Ash.Resource.Igniter.add_new_attribute(message, :text, """
      attribute :text, :string do
        constraints allow_empty?: true, trim?: false
        public? true
        allow_nil? false
      end
      """)
      |> Ash.Resource.Igniter.add_new_attribute(message, :tool_calls, """
      attribute :tool_calls, {:array, :map}
      """)
      |> Ash.Resource.Igniter.add_new_attribute(message, :tool_results, """
      attribute :tool_results, {:array, :map}
      """)
      |> Ash.Resource.Igniter.add_new_attribute(message, :source, """
      attribute :source, #{inspect(source)} do
        allow_nil? false
        public? true
        default :user
      end
      """)
      |> Ash.Resource.Igniter.add_new_attribute(message, :complete, """
      attribute :complete, :boolean do
        allow_nil? false
        default true
      end
      """)
      |> Ash.Resource.Igniter.add_new_relationship(message, :response, """
      has_one :response, __MODULE__ do
        public? true
        destination_attribute :response_to_id
      end
      """)
      |> Igniter.Project.Module.create_module(
        create_conversation_if_not_provided,
        """
        use Ash.Resource.Change

        @impl true
        def change(changeset, _opts, context) do
          if changeset.arguments[:conversation_id] do
            Ash.Changeset.force_change_attribute(
              changeset,
              :conversation_id,
              changeset.arguments.conversation_id
            )
          else
            Ash.Changeset.before_action(changeset, fn changeset ->
              conversation = #{inspect(chat)}.create_conversation!(Ash.Context.to_opts(context))

              Ash.Changeset.force_change_attribute(changeset, :conversation_id, conversation.id)
            end)
          end
        end
        """
      )
      |> Ash.Resource.Igniter.add_new_action(message, :for_conversation, """
      read :for_conversation do
        pagination keyset?: true, required?: false
        argument :conversation_id, :uuid, allow_nil?: false

        prepare build(default_sort: [inserted_at: :desc])
        filter expr(conversation_id == ^arg(:conversation_id))
      end
      """)
      |> Ash.Resource.Igniter.add_new_action(message, :create, """
      create :create do
        accept [:text]
        validate match(:text, ~r/\\S/) do
          message "Message cannot be empty"
        end
        argument :conversation_id, :uuid do
          public? false
        end

        change #{inspect(create_conversation_if_not_provided)}
        change run_oban_trigger(:respond)
      end
      """)
      |> Ash.Resource.Igniter.add_new_action(message, :respond, """
      update :respond do
        accept []
        require_atomic? false
        transaction? false
        change #{inspect(respond)}
      end
      """)
      |> Ash.Resource.Igniter.add_new_action(message, :upsert_response, """
      create :upsert_response do
        upsert? true
        accept [:id, :response_to_id, :conversation_id]
        argument :complete, :boolean, default: false
        argument :text, :string, allow_nil?: false, constraints: [trim?: false, allow_empty?: true]
        argument :tool_calls, {:array, :map}
        argument :tool_results, {:array, :map}

        # if updating
        #   if complete, set the text to the provided text
        #   if streaming still, add the text to the provided text
        change atomic_update(:text, {:atomic, expr(
          if ^arg(:complete) do
            ^arg(:text)
          else
            text <> ^arg(:text)
          end
        )})

      change atomic_update(
                :tool_calls,
                {:atomic,
                expr(
                  if not is_nil(^arg(:tool_calls)) do
                    fragment(
                      "? || ?",
                      tool_calls,
                      type(
                        ^arg(:tool_calls),
                        {:array, :map}
                      )
                    )
                  else
                    tool_calls
                  end
                )}
              )

      change atomic_update(
                :tool_results,
                {:atomic,
                expr(
                  if not is_nil(^arg(:tool_results)) do
                    fragment(
                      "? || ?",
                      tool_results,
                      type(
                        ^arg(:tool_results),
                        {:array, :map}
                      )
                    )
                  else
                    tool_results
                  end
                )}
              )

        # if creating, set the text attribute to the provided text
        change set_attribute(:text, arg(:text))
        change set_attribute(:complete, arg(:complete))
        change set_attribute(:source, :agent)
        change set_attribute(:tool_results, arg(:tool_results))
        change set_attribute(:tool_calls, arg(:tool_calls))

        # on update, only set complete to its new value
        upsert_fields [:complete]
      end
      """)
      |> Ash.Resource.Igniter.add_new_calculation(message, :needs_response, """
      calculate :needs_response, :boolean do
        calculation expr(source == :user and not exists(response))
      end
      """)
      |> Igniter.Project.Module.create_module(respond, """
      use Ash.Resource.Change
      require Ash.Query

      alias ReqLLM.Context

      @impl true
      def change(changeset, _opts, context) do
        Ash.Changeset.before_transaction(changeset, fn changeset ->
          message = changeset.data

          messages =
            #{inspect(message)}
            |> Ash.Query.filter(conversation_id == ^message.conversation_id)
            |> Ash.Query.filter(id != ^message.id)
            |> Ash.Query.select([:text, :source, :tool_calls, :tool_results])
            |> Ash.Query.sort(inserted_at: :asc)
            |> Ash.read!()
            |> Enum.concat([%{source: :user, text: message.text}])

          prompt_messages =
            [
              Context.system(\"""
            You are a helpful chat bot.
            Your job is to use the tools at your disposal to assist the user.
            \""")
            ] ++ message_chain(messages)

          new_message_id = Ash.UUIDv7.generate()

          final_state =
            prompt_messages
            |> AshAi.ToolLoop.stream(
              otp_app: :#{otp_app},
              tools: true,
              model: "#{provider.model}",
              actor: context.actor,
              tenant: context.tenant,
              context: Map.new(Ash.Context.to_opts(context))
            )
            |> Enum.reduce(%{text: "", tool_calls: [], tool_results: [], stream_error: nil}, fn
              {:content, content}, acc ->
                if content not in [nil, ""] do
                  #{inspect(message)}
                  |> Ash.Changeset.for_create(
                    :upsert_response,
                    %{
                      id: new_message_id,
                      response_to_id: message.id,
                      conversation_id: message.conversation_id,
                      text: content
                    },
                    actor: %AshAi{}
                  )
                  |> Ash.create!()
                end

                %{acc | text: acc.text <> (content || "")}

              {:tool_call, tool_call}, acc ->
                %{acc | tool_calls: append_event(acc.tool_calls, tool_call)}

              {:tool_result, %{id: id, result: result}}, acc ->
                %{
                  acc
                  | tool_results:
                      append_event(acc.tool_results, normalize_tool_result(id, result))
                }

              {:error, reason}, acc ->
                %{acc | stream_error: reason}

              {:done, _}, acc ->
                acc

              _, acc ->
                acc
            end)

          stream_error_text = stream_error_text(final_state.stream_error)

          final_text =
            cond do
              stream_error_text && String.trim(final_state.text || "") != "" ->
                final_state.text <> "\\n\\n" <> stream_error_text

              stream_error_text ->
                stream_error_text

              String.trim(final_state.text || "") == "" &&
                  (final_state.tool_calls != [] || final_state.tool_results != []) ->
                "Completed tool call."

              true ->
                final_state.text
            end

          if final_state.stream_error ||
               final_state.tool_calls != [] ||
               final_state.tool_results != [] ||
               final_text != "" do
            #{inspect(message)}
            |> Ash.Changeset.for_create(
              :upsert_response,
              %{
                id: new_message_id,
                response_to_id: message.id,
                conversation_id: message.conversation_id,
                complete: true,
                tool_calls: final_state.tool_calls,
                tool_results: final_state.tool_results,
                text: final_text
              },
              actor: %AshAi{}
            )
            |> Ash.create!()
          end

          changeset
        end)
      end

      defp message_chain(messages) do
        Enum.map(messages, fn
          %{source: :agent, text: text} ->
            # Historical tool call replay can break provider request validation for prior call IDs.
            # Keep replay text-only; current turn tool usage is handled by AshAi.ToolLoop.
            Context.assistant(text || "")

          %{source: :user, text: text} ->
            Context.user(text || "")
        end)
      end

      defp append_event(items, value) when is_list(items), do: items ++ [value]
      defp append_event(_items, value), do: [value]

      defp normalize_tool_result(tool_call_id, {:ok, content, _raw}) do
        %{
          tool_call_id: tool_call_id,
          content: content,
          is_error: false
        }
      end

      defp normalize_tool_result(tool_call_id, {:error, content}) do
        %{
          tool_call_id: tool_call_id,
          content: content,
          is_error: true
        }
      end

      defp stream_error_text(nil), do: nil

      defp stream_error_text(:max_iterations_reached) do
        "I hit a response limit while generating this reply. Please try again."
      end

      defp stream_error_text(_reason) do
        "I hit an error while generating this response. Please try again."
      end
      """)
    end

    defp set_conversation_pub_sub(igniter, conversation, endpoint) do
      igniter
      |> Spark.Igniter.add_extension(conversation, Ash.Resource, :notifiers, Ash.Notifier.PubSub)
      |> Igniter.Project.Module.find_and_update_module!(conversation, fn zipper ->
        with {:ok, zipper} <- ensure_pub_sub(zipper, endpoint),
             {:ok, zipper} <- ensure_prefix(zipper),
             {:ok, zipper} <-
               add_new_publish(zipper, :create, :publish_all, """
               publish_all :create, ["conversations", :user_id] do
                 transform &(&1.data)
               end
               """),
             {:ok, zipper} <-
               add_new_publish(zipper, :update, :publish_all, """
               publish_all :update, ["conversations", :user_id] do
                 transform &(&1.data)
               end
               """) do
          {:ok, zipper}
        else
          _ ->
            {:ok, zipper}
        end
      end)
    end

    defp set_message_pub_sub(igniter, message, endpoint) do
      igniter
      |> Spark.Igniter.add_extension(message, Ash.Resource, :notifiers, Ash.Notifier.PubSub)
      |> Igniter.Project.Module.find_and_update_module!(message, fn zipper ->
        with {:ok, zipper} <- ensure_pub_sub(zipper, endpoint),
             {:ok, zipper} <- ensure_prefix(zipper),
             {:ok, zipper} <-
               add_new_publish(zipper, :create, """
                publish :create, ["messages", :conversation_id] do
                  transform fn %{data: message} ->
                    %{
                      text: message.text,
                      id: message.id,
                      source: message.source,
                      complete: message.complete,
                      tool_calls: message.tool_calls,
                      tool_results: message.tool_results
                    }
                  end
                end
               """),
             {:ok, zipper} <-
               add_new_publish(zipper, :upsert_response, """
                publish :upsert_response, ["messages", :conversation_id] do
                  transform fn %{data: message} ->
                    %{
                      text: message.text,
                      id: message.id,
                      source: message.source,
                      complete: message.complete,
                      tool_calls: message.tool_calls,
                      tool_results: message.tool_results
                    }
                  end
                end
               """) do
          {:ok, zipper}
        else
          _ ->
            {:ok, zipper}
        end
      end)
    end

    defp add_new_publish(zipper, name, type \\ :publish, code) do
      Igniter.Code.Common.within(zipper, fn zipper ->
        case Igniter.Code.Function.move_to_function_call_in_current_scope(
               zipper,
               type,
               [2, 3],
               &Igniter.Code.Function.argument_equals?(&1, 0, name)
             ) do
          {:ok, _} ->
            {:ok, zipper}

          :error ->
            {:ok, Igniter.Code.Common.add_code(zipper, code)}
        end
      end)
    end

    defp ensure_pub_sub(zipper, endpoint) do
      with {:ok, zipper} <-
             Igniter.Code.Function.move_to_function_call_in_current_scope(zipper, :pub_sub, 1),
           {:ok, zipper} <- Igniter.Code.Common.move_to_do_block(zipper) do
        {:ok, zipper}
      else
        _ ->
          zipper =
            Igniter.Code.Common.add_code(zipper, """
            pub_sub do
              module #{inspect(endpoint)}
              prefix "chat"
            end
            """)

          with {:ok, zipper} <-
                 Igniter.Code.Function.move_to_function_call_in_current_scope(zipper, :pub_sub, 1),
               {:ok, zipper} <- Igniter.Code.Common.move_to_do_block(zipper) do
            {:ok, zipper}
          else
            _ ->
              :error
          end
      end
    end

    defp ensure_prefix(zipper) do
      Igniter.Code.Common.within(zipper, fn zipper ->
        case Igniter.Code.Function.move_to_function_call_in_current_scope(zipper, :prefix, 1) do
          {:ok, _zipper} ->
            {:ok, zipper}

          :error ->
            {:ok,
             Igniter.Code.Common.add_code(zipper, """
             prefix "chat"
             """)}
        end
      end)
    end

    defp add_code_interfaces(igniter, chat, conversation, message, user) do
      igniter
      |> Spark.Igniter.add_extension(chat, Ash.Domain, :extensions, AshPhoenix)
      |> Spark.Igniter.add_extension(chat, Ash.Domain, :extensions, AshAi)
      |> Ash.Domain.Igniter.add_new_code_interface(
        chat,
        conversation,
        :create_conversation,
        "define :create_conversation, action: :create"
      )
      |> Ash.Domain.Igniter.add_new_code_interface(
        chat,
        conversation,
        :get_conversation,
        "define :get_conversation, action: :read, get_by: [:id]"
      )
      |> Ash.Domain.Igniter.add_new_code_interface(
        chat,
        message,
        :message_history,
        """
        define :message_history,
          action: :for_conversation,
          args: [:conversation_id],
          default_options: [query: [sort: [inserted_at: :desc]]]
        """
      )
      |> Ash.Domain.Igniter.add_new_code_interface(
        chat,
        message,
        :create_message,
        "define :create_message, action: :create"
      )
      |> then(fn igniter ->
        if user do
          Ash.Domain.Igniter.add_new_code_interface(
            igniter,
            chat,
            conversation,
            :my_conversations,
            "define :my_conversations"
          )
        else
          Ash.Domain.Igniter.add_new_code_interface(
            igniter,
            chat,
            conversation,
            :list_conversations,
            "define :list_conversations, action: :read"
          )
        end
      end)
      |> add_default_tools(chat, conversation, message, user)
    end

    defp add_default_tools(igniter, chat, conversation, message, user) do
      list_action = if(user, do: :my_conversations, else: :read)

      Igniter.Project.Module.find_and_update_module!(igniter, chat, fn zipper ->
        with {:ok, zipper} <- ensure_tools(zipper),
             {:ok, zipper} <-
               add_new_domain_tool(
                 zipper,
                 :chat_list_conversations,
                 conversation,
                 list_action,
                 "List chat conversations visible to the current actor."
               ),
             {:ok, zipper} <-
               add_new_domain_tool(
                 zipper,
                 :chat_message_history,
                 message,
                 :for_conversation,
                 "Read chat messages for a conversation_id."
               ) do
          {:ok, zipper}
        else
          _ ->
            {:ok, zipper}
        end
      end)
    end

    defp ensure_tools(zipper) do
      with {:ok, zipper} <-
             Igniter.Code.Function.move_to_function_call_in_current_scope(zipper, :tools, 1),
           {:ok, zipper} <- Igniter.Code.Common.move_to_do_block(zipper) do
        {:ok, zipper}
      else
        _ ->
          zipper =
            Igniter.Code.Common.add_code(zipper, """
            tools do
            end
            """)

          with {:ok, zipper} <-
                 Igniter.Code.Function.move_to_function_call_in_current_scope(zipper, :tools, 1),
               {:ok, zipper} <- Igniter.Code.Common.move_to_do_block(zipper) do
            {:ok, zipper}
          else
            _ ->
              :error
          end
      end
    end

    defp add_new_domain_tool(zipper, tool_name, resource, action, description) do
      Igniter.Code.Common.within(zipper, fn zipper ->
        case Igniter.Code.Function.move_to_function_call_in_current_scope(
               zipper,
               :tool,
               [3, 4],
               &Igniter.Code.Function.argument_equals?(&1, 0, tool_name)
             ) do
          {:ok, _} ->
            {:ok, zipper}

          :error ->
            {:ok,
             Igniter.Code.Common.add_code(
               zipper,
               """
               tool #{inspect(tool_name)}, #{inspect(resource)}, :#{action} do
                 description #{inspect(description)}
               end
               """
             )}
        end
      end)
    end

    defp add_chat_live(igniter, chat, conversation, message, user) do
      if igniter.args.options[:live] do
        web_module = Igniter.Libs.Phoenix.web_module(igniter)
        chat_suffix = chat |> Module.split() |> List.last()
        chat_live = Igniter.Libs.Phoenix.web_module_name(igniter, "#{chat_suffix}Live")
        live_user_auth = Igniter.Libs.Phoenix.web_module_name(igniter, "LiveUserAuth")
        route = igniter.args.options[:route] || "/chat"

        {igniter, router} =
          Igniter.Libs.Phoenix.select_router(
            igniter,
            "Which `Phoenix.Router` should be we add the chat routes to?"
          )

        if router do
          {igniter, endpoint} =
            Igniter.Libs.Phoenix.select_endpoint(
              igniter,
              router,
              "Which `Phoenix.Endpoint` should be we use for pubsub events?"
            )

          if endpoint do
            {live_user_auth_exists?, igniter} =
              Igniter.Project.Module.module_exists(igniter, live_user_auth)

            on_mount =
              if live_user_auth_exists? do
                "on_mount {#{inspect(live_user_auth)}, :live_user_required}"
              else
                "# on_mount {#{inspect(live_user_auth)}, :live_user_required}"
              end

            Igniter.Project.Module.create_module(
              igniter,
              chat_live,
              chat_live_contents(web_module, on_mount, endpoint, chat, user, route)
            )
            |> set_message_pub_sub(message, endpoint)
            |> set_conversation_pub_sub(conversation, endpoint)
            |> add_chat_live_route(chat_live, router, route)
          else
            Igniter.add_warning(
              igniter,
              "Could not find an endpoint for pubsub, or no endpoint was selected, liveviews have been skipped."
            )
          end
        else
          Igniter.add_warning(
            igniter,
            "Could not find a router for placing routes in, or no router was selected, liveviews have been skipped."
          )
        end
      else
        igniter
      end
    end

    defp add_chat_live_route(igniter, chat_live, router, route) do
      live_module = inspect(Module.split(chat_live) |> Enum.drop(1) |> Module.concat())

      live =
        """
            live \"#{route}\", #{live_module}
            live \"#{route}/:conversation_id\", #{live_module}
        """

      if router do
        Igniter.Project.Module.find_and_update_module!(igniter, router, fn zipper ->
          with {:ok, zipper} <-
                 Igniter.Code.Common.move_to(
                   zipper,
                   &Igniter.Code.Function.function_call?(&1, :ash_authentication_live_session, [
                     1,
                     2,
                     3
                   ])
                 ),
               {:ok, zipper} <- Igniter.Code.Common.move_to_do_block(zipper) do
            {:ok, Igniter.Code.Common.add_code(zipper, live, placement: :before)}
          else
            :error ->
              {:warning,
               """
               AshAi: Couldn't add the chat routes to `#{inspect(router)}`.
               Please add them manually.

               #{live}
               """}
          end
        end)
      else
        Igniter.add_notice(
          igniter,
          """
          AshAi: Could not determine a phoenix router, could not add the chat route manually:

              #{live}
          """
        )
      end
    end

    defp add_chat_live_component(igniter, chat, conversation, message, user) do
      if igniter.args.options[:live_component] do
        web_module = Igniter.Libs.Phoenix.web_module(igniter)
        chat_suffix = chat |> Module.split() |> List.last()
        component_name = "#{chat_suffix}Component"
        chat_component = Igniter.Libs.Phoenix.web_module_name(igniter, component_name)

        {igniter, endpoint} =
          Igniter.Libs.Phoenix.select_endpoint(
            igniter,
            nil,
            "Which `Phoenix.Endpoint` should we use for pubsub events?"
          )

        if endpoint do
          Igniter.Project.Module.create_module(
            igniter,
            chat_component,
            chat_live_component_contents(web_module, endpoint, chat, user)
          )
          |> set_message_pub_sub(message, endpoint)
          |> set_conversation_pub_sub(conversation, endpoint)
        else
          Igniter.add_warning(
            igniter,
            "Could not find an endpoint for pubsub, or no endpoint was selected, live component has been skipped."
          )
        end
      else
        igniter
      end
    end

    defp maybe_add_live_component_notice(igniter, chat) do
      if igniter.args.options[:live_component] do
        web_module = Igniter.Libs.Phoenix.web_module(igniter)
        chat_suffix = chat |> Module.split() |> List.last()
        component_module = Module.concat([web_module, :"#{chat_suffix}Component"])

        Igniter.add_notice(igniter, """
        AshAi LiveComponent:

        A #{inspect(component_module)} has been generated.

        To embed the chat component in your LiveView:

            <.live_component
              module={#{inspect(component_module)}}
              id="chat"
              current_user={@current_user}
              conversation_id={@conversation_id}
              hide_sidebar={false}
            />

        Your parent LiveView must:

        1. Subscribe to PubSub topics and forward broadcasts:

            def mount(_params, _session, socket) do
              if connected?(socket) do
                #{inspect(component_module)}.subscribe(socket.assigns.current_user)
              end
              {:ok, socket}
            end

            def handle_info(%Phoenix.Socket.Broadcast{} = broadcast, socket) do
              send_update(#{inspect(component_module)}, id: "chat", broadcast: broadcast)
              {:noreply, socket}
            end

        2. Handle navigation requests from the component:

            def handle_info({:chat_component_navigate, nil}, socket) do
              # Handle new chat - update conversation_id assign or navigate
              {:noreply, assign(socket, :conversation_id, nil)}
            end

            def handle_info({:chat_component_navigate, conversation_id}, socket) do
              # Handle conversation selection - update conversation_id assign or navigate
              {:noreply, assign(socket, :conversation_id, conversation_id)}
            end
        """)
      else
        igniter
      end
    end

    defp llm_provider_config(provider) do
      case to_string(provider) do
        "openai" ->
          %{
            env_var: "OPENAI_API_KEY",
            req_llm_key: :openai_api_key,
            model: "openai:gpt-4o"
          }

        "anthropic" ->
          %{
            env_var: "ANTHROPIC_API_KEY",
            req_llm_key: :anthropic_api_key,
            model: "anthropic:claude-sonnet-4-5"
          }

        "gemini" ->
          %{
            env_var: "GOOGLE_API_KEY",
            req_llm_key: :google_api_key,
            model: "google:gemini-1.5-pro"
          }

        _ ->
          %{
            env_var: "OPENAI_API_KEY",
            req_llm_key: :openai_api_key,
            model: "openai:gpt-4o"
          }
      end
    end

    defp configure(igniter) do
      provider = llm_provider_config(igniter.args.options[:provider])
      env_var = provider.env_var

      api_key_code =
        quote do
          System.get_env(unquote(env_var))
        end

      igniter
      |> Igniter.Project.Config.configure_new(
        "runtime.exs",
        :req_llm,
        [provider.req_llm_key],
        {:code, api_key_code}
      )
      |> Igniter.Project.IgniterConfig.add_extension(Igniter.Extensions.Phoenix)
    end

    defp user_relationship(nil), do: []

    defp user_relationship(user) do
      ["--relationship", "belongs_to:user:#{inspect(user)}:public:required"]
    end

    defp user_module(igniter) do
      if igniter.args.options[:user] do
        {igniter, Igniter.Project.Module.parse(igniter.args.options[:user])}
      else
        default =
          Igniter.Project.Module.module_name(igniter, "Accounts.User")

        {exists?, igniter} = Igniter.Project.Module.module_exists(igniter, default)

        if exists? do
          {igniter, default}
        else
          igniter =
            Igniter.add_warning(igniter, """
            `ash_ai.gen.chat` works better if a user module is known.
            We could not find one automatically, and one was not provided.

            Please abort this command and provide one using the `--user` flag,
            or install `AshAuthentication` before-hand, being sure its installed
            before this command is run.
            """)

          {igniter, nil}
        end
      end
    end

    defp add_triggers(igniter, message, conversation, user) do
      actor_persister =
        if user do
          Igniter.Project.Module.module_name(igniter, "AiAgentActorPersister")
        end

      respond_worker_module_name = Module.concat([message, "Workers.Respond"])
      respond_scheduler_module_name = Module.concat([message, "Schedulers.Respond"])

      name_conversation_worker_module_name =
        Module.concat([message, "Workers.NameConversation"])

      name_conversation_scheduler_module_name =
        Module.concat([message, "Schedulers.NameConversation"])

      igniter
      |> then(fn igniter ->
        if actor_persister do
          Igniter.Project.Module.find_and_update_or_create_module(
            igniter,
            actor_persister,
            """
            use AshOban.ActorPersister

            def store(%#{inspect(user)}{id: id}), do: %{"type" => "user", "id" => id}

            def lookup(%{"type" => "user", "id" => id}) do
              with {:ok, user} <- Ash.get(#{inspect(user)}, id, authorize?: false) do
                # you can change the behavior of actions
                # or what your policies allow
                # using the `chat_agent?` metadata
                {:ok, Ash.Resource.set_metadata(user, %{chat_agent?: true})}
              end
            end

            # This allows you to set a default actor
            # in cases where no actor was present
            # when scheduling.
            def lookup(nil), do: {:ok, nil}
            """,
            fn zipper -> {:ok, zipper} end
          )
        else
          igniter
        end
      end)
      |> add_new_trigger(message, :respond, """
      trigger :respond do
        #{if actor_persister, do: "actor_persister #{inspect(actor_persister)}"}
        action :respond
        queue :chat_responses
        lock_for_update? false
        scheduler_cron false
        worker_module_name #{inspect(respond_worker_module_name)}
        scheduler_module_name #{inspect(respond_scheduler_module_name)}
        where expr(needs_response)
      end
      """)
      |> add_new_trigger(conversation, :respond, """
      trigger :name_conversation do
        action :generate_name
        queue :conversations
        lock_for_update? false
        worker_module_name #{inspect(name_conversation_worker_module_name)}
        scheduler_module_name #{inspect(name_conversation_scheduler_module_name)}
        where expr(needs_title)
      end
      """)
    end

    defp add_new_trigger(igniter, conversation, name, code) do
      apply(AshOban.Igniter, :add_new_trigger, [igniter, conversation, name, code])
    end

    defp chat_live_contents(web_module, on_mount, endpoint, chat, user, route) do
      interface_name =
        if user do
          "my_conversations"
        else
          "list_conversations"
        end

      actor_required? = !!user

      list_conversations_call =
        if user do
          "#{inspect(chat)}.#{interface_name}!(actor: socket.assigns.current_user)"
        else
          "#{inspect(chat)}.#{interface_name}!()"
        end

      get_conversation_call =
        if user do
          "#{inspect(chat)}.get_conversation!(conversation_id, actor: socket.assigns.current_user)"
        else
          "#{inspect(chat)}.get_conversation!(conversation_id)"
        end

      form_with_conversation_call =
        if user do
          "#{inspect(chat)}.form_to_create_message(actor: socket.assigns.current_user, private_arguments: %{conversation_id: socket.assigns.conversation.id})"
        else
          "#{inspect(chat)}.form_to_create_message(private_arguments: %{conversation_id: socket.assigns.conversation.id})"
        end

      form_without_conversation_call =
        if user do
          "#{inspect(chat)}.form_to_create_message(actor: socket.assigns.current_user)"
        else
          "#{inspect(chat)}.form_to_create_message()"
        end

      """
      use #{web_module}, :live_view
      @actor_required? #{actor_required?}
      @chat_ui_tools AshAi.ChatUI.Tools
      #{on_mount}
        def render(assigns) do
          ~H\"""
          <div class="drawer md:drawer-open bg-base-200 min-h-dvh max-h-dvh">
            <input id="ash-ai-drawer" type="checkbox" class="drawer-toggle" />
            <div class="drawer-content flex flex-col">
              <.flash kind={:info} flash={@flash} />
              <.flash kind={:error} flash={@flash} />
              <div
                :if={Phoenix.Flash.get(@flash, :warning)}
                class="alert alert-warning m-4 mb-0 text-sm"
              >
                {Phoenix.Flash.get(@flash, :warning)}
              </div>
              <div class="navbar bg-base-300 w-full">
                <div class="flex-none md:hidden">
                  <label for="ash-ai-drawer" aria-label="open sidebar" class="btn btn-square btn-ghost">
                    <svg
                      xmlns="http://www.w3.org/2000/svg"
                      fill="none"
                      viewBox="0 0 24 24"
                      class="inline-block h-6 w-6 stroke-current"
                    >
                      <path
                        stroke-linecap="round"
                        stroke-linejoin="round"
                        stroke-width="2"
                        d="M4 6h16M4 12h16M4 18h16"
                      >
                      </path>
                    </svg>
                  </label>
                </div>
                <img
                  src="https://github.com/ash-project/ash_ai/blob/main/logos/ash_ai.png?raw=true"
                  alt="Logo"
                  class="h-12"
                  height="48"
                />
                <div class="mx-2 flex-1 px-2">
                  <p :if={@conversation}>{build_conversation_title_string(@conversation.title)}</p>
                  <p class="text-xs">AshAi</p>
                </div>
              </div>
              <div class="flex-1 flex flex-col overflow-y-scroll bg-base-200 max-h-[calc(100dvh-8rem)]">
                <div
                  id="message-container"
                  phx-update="stream"
                  class="flex-1 overflow-y-auto overflow-x-hidden px-4 py-2 flex flex-col-reverse"
                >
                  <%= for {id, message} <- @streams.messages do %>
                    <div
                      id={id}
                      class={[
                        "chat",
                        message.source == :user && "chat-end",
                        message.source == :agent && "chat-start"
                      ]}
                    >
                      <div :if={message.source == :agent} class="chat-image avatar">
                        <div class="w-10 rounded-full bg-base-300 p-1">
                          <img
                            src="https://github.com/ash-project/ash_ai/blob/main/logos/ash_ai.png?raw=true"
                            alt="Logo"
                          />
                        </div>
                      </div>
                      <div :if={message.source == :user} class="chat-image avatar avatar-placeholder">
                        <div class="w-10 rounded-full bg-base-300">
                          <.icon name="hero-user-solid" class="block" />
                        </div>
                      </div>
                      <div
                        :if={message.source == :agent && tool_calls(message) != []}
                        class="mt-2 flex w-full max-w-[36rem] min-w-0 flex-wrap gap-1 text-[11px] opacity-80"
                      >
                        <%= for tool_call <- tool_calls(message) do %>
                          <span class="badge badge-outline badge-info max-w-full min-w-0 justify-start overflow-hidden text-ellipsis whitespace-nowrap">
                            tool: {tool_call.name}
                            <span :if={tool_call.arguments != %{}}>
                              ({tool_call.arguments_preview})
                            </span>
                          </span>
                        <% end %>
                      </div>
                      <div
                        :if={message.source == :agent && tool_results(message) != []}
                        class="chat-footer mt-1 flex w-full max-w-[36rem] min-w-0 flex-col gap-1"
                      >
                        <%= for tool_result <- tool_results(message) do %>
                          <div
                            class={[
                              "rounded max-w-full overflow-hidden px-2 py-1 text-xs leading-relaxed break-words",
                              tool_result.is_error && "bg-error/20",
                              !tool_result.is_error && "bg-base-300"
                            ]}
                          >
                            <span class="font-semibold">
                              {if tool_result.is_error, do: "tool_error", else: "tool_result"}
                            </span>
                            <span :if={tool_result.name}> ({tool_result.name})</span>
                            <span class="break-all">
                              : {tool_result.content_preview}
                            </span>
                          </div>
                        <% end %>
                      </div>
                      <div :if={String.trim(message.text || "") != ""} class="chat-bubble">
                        <%= to_markdown(message.text || "") %>
                      </div>
                    </div>
                  <% end %>
                </div>
              </div>
              <div :if={@agent_responding} class="px-4 py-2 text-xs opacity-80 flex items-center gap-2">
                <span class="loading loading-dots loading-sm" />
                <span>AshAi is responding...</span>
              </div>
              <div class="p-4 border-t">
                <.form
                  :let={form}
                  for={@message_form}
                  phx-change="validate_message"
                  phx-debounce="blur"
                  phx-submit="send_message"
                  class="flex items-center gap-4"
                >
                  <div class="flex-1">
                    <input
                      name={form[:text].name}
                      value={form[:text].value}
                      type="text"
                      phx-mounted={JS.focus()}
                      placeholder="Type your message..."
                      class="input input-primary w-full mb-0"
                      autocomplete="off"
                    />
                  </div>
                  <button type="submit" class="btn btn-primary rounded-full">
                    <.icon name="hero-paper-airplane" /> Send
                  </button>
                </.form>
              </div>
            </div>

            <div class="drawer-side border-r bg-base-300 min-w-72">
              <div class="py-4 px-6">
                <div class="text-lg mb-4">
                  Conversations
                </div>
                <div class="mb-4">
                  <.link navigate={~p"#{route}"} class="btn btn-primary btn-lg mb-2">
                    <div class="rounded-full bg-primary-content text-primary w-6 h-6 flex items-center justify-center">
                      <.icon name="hero-plus" />
                    </div>
                    <span>New Chat</span>
                  </.link>
                </div>
                <ul class="flex flex-col-reverse" phx-update="stream" id="conversations-list">
                  <%= for {id, conversation} <- @streams.conversations do %>
                    <li id={id}>
                      <.link
                        navigate={~p"#{route}/\#{conversation.id}"}
                        phx-click="select_conversation"
                        phx-value-id={conversation.id}
                        class={"block py-2 px-3 transition border-l-4 pl-2 mb-2 \#{if @conversation && @conversation.id == conversation.id, do: "border-primary font-medium", else: "border-transparent"}"}
                      >
                        {build_conversation_title_string(conversation.title)}
                      </.link>
                    </li>
                  <% end %>
                </ul>
              </div>
            </div>
          </div>
          \"""
        end

        def build_conversation_title_string(title) do
          cond do
            title == nil -> "Untitled conversation"
            is_binary(title) && String.length(title) > 25 -> String.slice(title, 0, 25) <> "..."
            is_binary(title) && String.length(title) <= 25 -> title
          end
        end

        def mount(_params, _session, socket) do
          socket = assign_new(socket, :current_user, fn -> nil end)

          if socket.assigns.current_user do
            #{inspect(endpoint)}.subscribe("chat:conversations:\#{socket.assigns.current_user.id}")
          end

          conversations =
            if @actor_required? && is_nil(socket.assigns.current_user) do
              []
            else
              #{list_conversations_call}
            end

          socket =
            socket
            |> assign(:page_title, "Chat")
            |> stream(:conversations, conversations)
            |> assign(:agent_responding, false)
            |> assign(:tool_data_warning_shown?, false)
            |> assign(:messages, [])

          {:ok, socket}
        end

        def handle_params(%{"conversation_id" => conversation_id}, _, socket) do
          if @actor_required? && is_nil(socket.assigns.current_user) do
            {:noreply,
             socket
             |> put_flash(:error, "You must sign in to access conversations")
             |> push_navigate(to: ~p"#{route}")}
          else
          conversation =
            #{get_conversation_call}

          messages = #{inspect(chat)}.message_history!(conversation.id, stream?: true)

          cond do
            socket.assigns[:conversation] && socket.assigns[:conversation].id == conversation.id ->
              :ok

            socket.assigns[:conversation] ->
              #{inspect(endpoint)}.unsubscribe("chat:messages:\#{socket.assigns.conversation.id}")
              #{inspect(endpoint)}.subscribe("chat:messages:\#{conversation.id}")
            true ->
              #{inspect(endpoint)}.subscribe("chat:messages:\#{conversation.id}")
          end

          socket
          |> maybe_warn_tool_data(messages)
          |> assign(:conversation, conversation)
          |> assign(:agent_responding, agent_response_pending?(messages))
          |> stream(:messages, messages)
          |> assign_message_form()
          |> then(&{:noreply, &1})
          end
        end

        def handle_params(_, _, socket) do
          if socket.assigns[:conversation] do
            #{inspect(endpoint)}.unsubscribe("chat:messages:\#{socket.assigns.conversation.id}")
          end

          socket
          |> assign(:conversation, nil)
          |> assign(:agent_responding, false)
          |> stream(:messages, [])
          |> assign_message_form()
          |> then(&{:noreply, &1})
        end

        def handle_event("validate_message", %{"form" => params}, socket) do
          {:noreply, assign(socket, :message_form, AshPhoenix.Form.validate(socket.assigns.message_form, params))}
        end

        def handle_event("send_message", %{"form" => params}, socket) do
          if @actor_required? && is_nil(socket.assigns.current_user) do
            {:noreply, put_flash(socket, :error, "You must sign in to send messages")}
          else
          case AshPhoenix.Form.submit(socket.assigns.message_form, params: params) do
            {:ok, message} ->
              if socket.assigns.conversation do
                socket
                |> assign(:agent_responding, true)
                |> assign_message_form()
                |> stream_insert(:messages, message, at: 0)
                |> then(&{:noreply, &1})
              else
                {:noreply,
                 socket
                 |> push_navigate(to: ~p"#{route}/\#{message.conversation_id}")}
              end

            {:error, form} ->
              {:noreply, assign(socket, :message_form, form)}
          end
          end
        end

        def handle_info(
              %Phoenix.Socket.Broadcast{
                topic: "chat:messages:" <> conversation_id,
                payload: message
              },
              socket
            ) do
          if socket.assigns.conversation && socket.assigns.conversation.id == conversation_id do
            socket =
              socket
              |> maybe_warn_tool_data(message)
              |> stream_insert(:messages, message, at: 0)
              |> update_agent_responding(message)

            {:noreply, socket}
          else
            {:noreply, socket}
          end
        end

        def handle_info(
              %Phoenix.Socket.Broadcast{
                topic: "chat:conversations:" <> _,
                payload: conversation
              },
              socket
            ) do
          socket =
            if socket.assigns.conversation && socket.assigns.conversation.id == conversation.id do
              assign(socket, :conversation, conversation)
            else
              socket
            end

          {:noreply, stream_insert(socket, :conversations, conversation)}
        end

        defp assign_message_form(socket) do
          form =
            if socket.assigns.conversation do
              #{form_with_conversation_call}
              |> to_form()
            else
              #{form_without_conversation_call}
              |> to_form()
            end

          assign(
            socket,
            :message_form,
            form
          )
        end

        defp tool_calls(message), do: safe_extract(message).tool_calls

        defp tool_results(message), do: safe_extract(message).tool_results

        defp safe_extract(message) do
          case @chat_ui_tools.extract(message) do
            {:ok, extracted} ->
              extracted

            {:error, _} ->
              %{tool_calls: [], tool_results: []}
          end
        end

        defp maybe_warn_tool_data(socket, messages) when is_list(messages) do
          Enum.reduce(messages, socket, fn message, acc ->
            maybe_warn_tool_data(acc, message)
          end)
        end

        defp maybe_warn_tool_data(socket, message) do
          if agent_message?(message) do
            case @chat_ui_tools.extract(message) do
              {:ok, _} ->
                socket

              {:error, _} ->
                maybe_put_tool_data_warning(socket)
            end
          else
            socket
          end
        end

        defp maybe_put_tool_data_warning(socket) do
          if socket.assigns[:tool_data_warning_shown?] do
            socket
          else
            socket
            |> put_flash(:warning, "Some tool call data could not be displayed.")
            |> assign(:tool_data_warning_shown?, true)
          end
        end

        defp message_source(%{source: source}), do: source
        defp message_source(%{"source" => source}), do: source
        defp message_source(_), do: nil

        defp message_complete?(%{complete: complete}), do: complete in [true, "true"]
        defp message_complete?(%{"complete" => complete}), do: complete in [true, "true"]
        defp message_complete?(_), do: false

        defp user_message?(message), do: message_source(message) in [:user, "user"]
        defp agent_message?(message), do: message_source(message) in [:agent, "agent"]

        defp update_agent_responding(socket, message) do
          cond do
            user_message?(message) ->
              assign(socket, :agent_responding, true)

            agent_message?(message) ->
              assign(socket, :agent_responding, !message_complete?(message))

            true ->
              socket
          end
        end

        defp agent_response_pending?(messages) do
          case Enum.find(messages, fn message -> user_message?(message) or agent_message?(message) end) do
            nil -> false
            message -> user_message?(message) || !message_complete?(message)
          end
        end

        defp to_markdown(text) do
          # Note that you must pass the "unsafe: true" option to first generate the raw HTML
          # in order to sanitize it. https://hexdocs.pm/mdex/MDEx.html#module-sanitize
          MDEx.to_html(text,
            extension: [
              strikethrough: true,
              tagfilter: true,
              table: true,
              autolink: true,
              tasklist: true,
              footnotes: true,
              shortcodes: true
            ],
            parse: [
              smart: true,
              relaxed_tasklist_matching: true,
              relaxed_autolinks: true
            ],
            render: [
              github_pre_lang: true,
              unsafe: true
            ],
            sanitize: MDEx.Document.default_sanitize_options()
          )
          |> case do
            {:ok, html} ->
              html
              |> Phoenix.HTML.raw()
            {:error, _} -> text
          end
        end
      """
    end

    defp chat_live_component_contents(web_module, endpoint, chat, user) do
      interface_name =
        if user do
          "my_conversations"
        else
          "list_conversations"
        end

      actor_required? =
        if user do
          "true"
        else
          "false"
        end

      """
      use #{inspect(web_module)}, :live_component
      @chat_ui_tools AshAi.ChatUI.Tools

      @impl true
      def update(%{broadcast: broadcast}, socket) do
        {:ok, handle_broadcast(socket, broadcast)}
      end

      def update(assigns, socket) do
        socket = assign(socket, assigns)

        socket =
          if !socket.assigns[:initialized] do
            conversations =
              if #{actor_required?} && is_nil(socket.assigns.current_user) do
                []
              else
                #{inspect(chat)}.#{interface_name}!(actor: socket.assigns.current_user)
              end

            socket
            |> assign(:initialized, true)
            |> assign_new(:hide_sidebar, fn -> false end)
            |> assign_new(:conversation, fn -> nil end)
            |> assign_new(:conversation_id, fn -> nil end)
            |> assign_new(:agent_responding, fn -> false end)
            |> assign_new(:tool_data_warning_shown?, fn -> false end)
            |> stream(:conversations, conversations)
            |> stream(:messages, [])
            |> assign_message_form()
          else
            socket
          end

        socket =
          cond do
            socket.assigns[:conversation_id] &&
                socket.assigns[:conversation_id] != get_current_conversation_id(socket) ->
              load_conversation(socket, socket.assigns.conversation_id)

            !socket.assigns[:conversation_id] && socket.assigns.conversation ->
              clear_conversation(socket)

            true ->
              socket
          end

        {:ok, socket}
      end

      @doc \"\"\"
      Subscribes the calling process to PubSub topics for the given user.

      Call this from your parent LiveView's `mount/3`:

          if connected?(socket) do
            MyAppWeb.ChatComponent.subscribe(socket.assigns.current_user, socket)
          end
      \"\"\"
      def subscribe(current_user, _socket) do
        if current_user do
          #{inspect(endpoint)}.subscribe("chat:conversations:\#{current_user.id}")
        end
      end

      @impl true
      def render(assigns) do
        ~H\"""
        <div id={@id} class="flex bg-base-200 min-h-full max-h-full">
          <div :if={!@hide_sidebar} class="w-72 border-r bg-base-300 flex flex-col overflow-y-auto">
            <div class="py-4 px-6">
              <div class="text-lg mb-4">
                Conversations
              </div>
              <div class="mb-4">
                <button phx-click="new_chat" phx-target={@myself} class="btn btn-primary btn-lg mb-2">
                  <div class="rounded-full bg-primary-content text-primary w-6 h-6 flex items-center justify-center">
                    <.icon name="hero-plus" />
                  </div>
                  <span>New Chat</span>
                </button>
              </div>
              <ul class="flex flex-col-reverse" phx-update="stream" id={"\#{@id}-conversations-list"}>
                <%= for {id, conversation} <- @streams.conversations do %>
                  <li id={id}>
                    <button
                      phx-click="select_conversation"
                      phx-target={@myself}
                      phx-value-id={conversation.id}
                      class={"block py-2 px-3 transition border-l-4 pl-2 mb-2 w-full text-left \#{if @conversation && @conversation.id == conversation.id, do: "border-primary font-medium", else: "border-transparent"}"}
                    >
                      {build_conversation_title_string(conversation.title)}
                    </button>
                  </li>
                <% end %>
              </ul>
            </div>
          </div>

          <div class="flex-1 flex flex-col">
            <.flash kind={:info} flash={@flash} />
            <.flash kind={:error} flash={@flash} />
            <div
              :if={Phoenix.Flash.get(@flash, :warning)}
              class="alert alert-warning m-4 mb-0 text-sm"
            >
              {Phoenix.Flash.get(@flash, :warning)}
            </div>
            <div class="navbar bg-base-300 w-full">
              <img
                src="https://github.com/ash-project/ash_ai/blob/main/logos/ash_ai.png?raw=true"
                alt="Logo"
                class="h-12"
                height="48"
              />
              <div class="mx-2 flex-1 px-2">
                <p :if={@conversation}>{build_conversation_title_string(@conversation.title)}</p>
                <p class="text-xs">AshAi</p>
              </div>
            </div>

            <div class="flex-1 flex flex-col overflow-y-scroll bg-base-200">
              <div
                id={"\#{@id}-message-container"}
                phx-update="stream"
                class="flex-1 overflow-y-auto overflow-x-hidden px-4 py-2 flex flex-col-reverse"
              >
                <%= for {id, message} <- @streams.messages do %>
                  <div
                    id={id}
                    class={[
                      "chat",
                      message.source == :user && "chat-end",
                      message.source == :agent && "chat-start"
                    ]}
                  >
                    <div :if={message.source == :agent} class="chat-image avatar">
                      <div class="w-10 rounded-full bg-base-300 p-1">
                        <img
                          src="https://github.com/ash-project/ash_ai/blob/main/logos/ash_ai.png?raw=true"
                          alt="Logo"
                        />
                      </div>
                    </div>
                    <div :if={message.source == :user} class="chat-image avatar avatar-placeholder">
                      <div class="w-10 rounded-full bg-base-300">
                        <.icon name="hero-user-solid" class="block" />
                      </div>
                    </div>
                    <div
                      :if={message.source == :agent && tool_calls(message) != []}
                      class="mt-2 flex w-full max-w-[36rem] min-w-0 flex-wrap gap-1 text-[11px] opacity-80"
                    >
                      <%= for tool_call <- tool_calls(message) do %>
                        <span class="badge badge-outline badge-info max-w-full min-w-0 justify-start overflow-hidden text-ellipsis whitespace-nowrap">
                          tool: {tool_call.name}
                          <span :if={tool_call.arguments != %{}}>
                            ({tool_call.arguments_preview})
                          </span>
                        </span>
                      <% end %>
                    </div>
                    <div
                      :if={message.source == :agent && tool_results(message) != []}
                      class="chat-footer mt-1 flex w-full max-w-[36rem] min-w-0 flex-col gap-1"
                    >
                      <%= for tool_result <- tool_results(message) do %>
                        <div
                          class={[
                            "rounded max-w-full overflow-hidden px-2 py-1 text-xs leading-relaxed break-words",
                            tool_result.is_error && "bg-error/20",
                            !tool_result.is_error && "bg-base-300"
                          ]}
                        >
                          <span class="font-semibold">
                            {if tool_result.is_error, do: "tool_error", else: "tool_result"}
                          </span>
                          <span :if={tool_result.name}> ({tool_result.name})</span>
                          <span class="break-all">
                            : {tool_result.content_preview}
                          </span>
                        </div>
                      <% end %>
                    </div>
                    <div :if={String.trim(message.text || "") != ""} class="chat-bubble">
                      <%= to_markdown(message.text || "") %>
                    </div>
                  </div>
                <% end %>
              </div>
            </div>
            <div :if={@agent_responding} class="px-4 py-2 text-xs opacity-80 flex items-center gap-2">
              <span class="loading loading-dots loading-sm" />
              <span>AshAi is responding...</span>
            </div>
            <div class="p-4 border-t">
              <.form
                :let={form}
                for={@message_form}
                phx-change="validate_message"
                phx-target={@myself}
                phx-debounce="blur"
                phx-submit="send_message"
                class="flex items-center gap-4"
              >
                <div class="flex-1">
                  <input
                    name={form[:text].name}
                    value={form[:text].value}
                    type="text"
                    phx-mounted={JS.focus()}
                    placeholder="Type your message..."
                    class="input input-primary w-full mb-0"
                    autocomplete="off"
                  />
                </div>
                <button type="submit" class="btn btn-primary rounded-full">
                  <.icon name="hero-paper-airplane" /> Send
                </button>
              </.form>
            </div>
          </div>
        </div>
        \"""
      end

      @impl true
      def handle_event("validate_message", %{"form" => params}, socket) do
        {:noreply, assign(socket, :message_form, AshPhoenix.Form.validate(socket.assigns.message_form, params))}
      end

      @impl true
      def handle_event("send_message", %{"form" => params}, socket) do
        if #{actor_required?} && is_nil(socket.assigns.current_user) do
          {:noreply, put_flash(socket, :error, "You must sign in to send messages")}
        else
          case AshPhoenix.Form.submit(socket.assigns.message_form, params: params) do
            {:ok, message} ->
              if socket.assigns.conversation do
                socket
                |> assign(:agent_responding, true)
                |> assign_message_form()
                |> stream_insert(:messages, message, at: 0)
                |> then(&{:noreply, &1})
              else
                send(self(), {:chat_component_navigate, message.conversation_id})
                {:noreply, assign_message_form(socket)}
              end

            {:error, form} ->
              {:noreply, assign(socket, :message_form, form)}
          end
        end
      end

      @impl true
      def handle_event("select_conversation", %{"id" => id}, socket) do
        send(self(), {:chat_component_navigate, id})
        {:noreply, socket}
      end

      @impl true
      def handle_event("new_chat", _, socket) do
        send(self(), {:chat_component_navigate, nil})
        {:noreply, socket}
      end

      defp load_conversation(socket, conversation_id) do
        if #{actor_required?} && is_nil(socket.assigns.current_user) do
          socket
          |> put_flash(:error, "You must sign in to access conversations")
          |> clear_conversation()
        else
          conversation =
            #{inspect(chat)}.get_conversation!(conversation_id, actor: socket.assigns.current_user)

          messages = #{inspect(chat)}.message_history!(conversation.id, stream?: true)

          #{inspect(endpoint)}.subscribe("chat:messages:\#{conversation.id}")

          socket
          |> maybe_warn_tool_data(messages)
          |> assign(:conversation, conversation)
          |> assign(:agent_responding, agent_response_pending?(messages))
          |> stream(:messages, messages, reset: true)
          |> assign_message_form()
        end
      end

      defp clear_conversation(socket) do
        if socket.assigns[:conversation] do
          #{inspect(endpoint)}.unsubscribe("chat:messages:\#{socket.assigns.conversation.id}")
        end

        socket
        |> assign(:conversation, nil)
        |> assign(:agent_responding, false)
        |> stream(:messages, [], reset: true)
        |> assign_message_form()
      end

      defp get_current_conversation_id(socket) do
        if socket.assigns[:conversation], do: socket.assigns.conversation.id, else: nil
      end

      defp handle_broadcast(socket, %Phoenix.Socket.Broadcast{
        topic: "chat:messages:" <> conversation_id,
        payload: message
      }) do
        if socket.assigns.conversation && socket.assigns.conversation.id == conversation_id do
          socket
          |> maybe_warn_tool_data(message)
          |> stream_insert(:messages, message, at: 0)
          |> update_agent_responding(message)
        else
          socket
        end
      end

      defp handle_broadcast(socket, %Phoenix.Socket.Broadcast{
        topic: "chat:conversations:" <> _,
        payload: conversation
      }) do
        socket =
          if socket.assigns.conversation && socket.assigns.conversation.id == conversation.id do
            assign(socket, :conversation, conversation)
          else
            socket
          end

        stream_insert(socket, :conversations, conversation)
      end

      defp handle_broadcast(socket, _), do: socket

      def build_conversation_title_string(title) do
        cond do
          title == nil -> "Untitled conversation"
          is_binary(title) && String.length(title) > 25 -> String.slice(title, 0, 25) <> "..."
          is_binary(title) && String.length(title) <= 25 -> title
        end
      end

      defp assign_message_form(socket) do
        form =
          if socket.assigns.conversation do
            #{inspect(chat)}.form_to_create_message(
              actor: socket.assigns.current_user,
              private_arguments: %{conversation_id: socket.assigns.conversation.id}
            )
            |> to_form()
          else
            #{inspect(chat)}.form_to_create_message(actor: socket.assigns.current_user)
            |> to_form()
          end

        assign(
          socket,
          :message_form,
          form
        )
      end

      defp tool_calls(message), do: safe_extract(message).tool_calls

      defp tool_results(message), do: safe_extract(message).tool_results

      defp safe_extract(message) do
        case @chat_ui_tools.extract(message) do
          {:ok, extracted} ->
            extracted

          {:error, _} ->
            %{tool_calls: [], tool_results: []}
        end
      end

      defp maybe_warn_tool_data(socket, messages) when is_list(messages) do
        Enum.reduce(messages, socket, fn message, acc ->
          maybe_warn_tool_data(acc, message)
        end)
      end

      defp maybe_warn_tool_data(socket, message) do
        if agent_message?(message) do
          case @chat_ui_tools.extract(message) do
            {:ok, _} ->
              socket

            {:error, _} ->
              maybe_put_tool_data_warning(socket)
          end
        else
          socket
        end
      end

      defp maybe_put_tool_data_warning(socket) do
        if socket.assigns[:tool_data_warning_shown?] do
          socket
        else
          socket
          |> put_flash(:warning, "Some tool call data could not be displayed.")
          |> assign(:tool_data_warning_shown?, true)
        end
      end

      defp message_source(%{source: source}), do: source
      defp message_source(%{"source" => source}), do: source
      defp message_source(_), do: nil

      defp message_complete?(%{complete: complete}), do: complete in [true, "true"]
      defp message_complete?(%{"complete" => complete}), do: complete in [true, "true"]
      defp message_complete?(_), do: false

      defp user_message?(message), do: message_source(message) in [:user, "user"]
      defp agent_message?(message), do: message_source(message) in [:agent, "agent"]

      defp update_agent_responding(socket, message) do
        cond do
          user_message?(message) ->
            assign(socket, :agent_responding, true)

          agent_message?(message) ->
            assign(socket, :agent_responding, !message_complete?(message))

          true ->
            socket
        end
      end

      defp agent_response_pending?(messages) do
        case Enum.find(messages, fn message -> user_message?(message) or agent_message?(message) end) do
          nil -> false
          message -> user_message?(message) || !message_complete?(message)
        end
      end

      defp to_markdown(text) do
        MDEx.to_html(text,
          extension: [
            strikethrough: true,
            tagfilter: true,
            table: true,
            autolink: true,
            tasklist: true,
            footnotes: true,
            shortcodes: true
          ],
          parse: [
            smart: true,
            relaxed_tasklist_matching: true,
            relaxed_autolinks: true
          ],
          render: [
            github_pre_lang: true,
            unsafe: true
          ],
          sanitize: MDEx.Document.default_sanitize_options()
        )
        |> case do
          {:ok, html} ->
            html
            |> Phoenix.HTML.raw()
          {:error, _} -> text
        end
      end
      """
    end
  end
else
  defmodule Mix.Tasks.AshAi.Gen.Chat do
    @shortdoc "#{__MODULE__.Docs.short_doc()} | Install `igniter` to use"

    @moduledoc __MODULE__.Docs.long_doc()

    use Mix.Task

    def run(_argv) do
      Mix.shell().error("""
      The task 'ash_ai.gen.chat' requires igniter. Please install igniter and try again.

      For more information, see: https://hexdocs.pm/igniter/readme.html#installation
      """)

      exit({:shutdown, 1})
    end
  end
end
