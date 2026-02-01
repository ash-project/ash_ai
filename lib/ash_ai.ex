# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi do
  @moduledoc """
  Documentation for `AshAi`.
  """

  alias LangChain.Chains.LLMChain

  defstruct []

  require Logger

  use Spark.Dsl.Extension,
    sections: AshAi.Dsl.sections(),
    imports: [AshAi.Actions],
    transformers: [AshAi.Transformers.Vectorize],
    verifiers: [AshAi.Verifiers.McpResourceActionsReturnString]

  defmodule Tool do
    @moduledoc "An action exposed to LLM agents"
    defstruct [
      :name,
      :resource,
      :action,
      :load,
      :async,
      :domain,
      :identity,
      :description,
      :action_parameters,
      :arguments,
      :_meta,
      __spark_metadata__: nil
    ]

    defmodule Argument do
      @moduledoc """
      A struct representing an argument defined in the Tool DSL.
      """
      defstruct [
        :name,
        :type,
        :description,
        :default,
        constraints: [],
        allow_nil?: true,
        __spark_metadata__: nil
      ]
    end

    def has_meta?(%__MODULE__{_meta: meta})
        when not is_nil(meta) and meta != %{},
        do: true

    def has_meta?(_), do: false
  end

  defmodule McpResource do
    @moduledoc """
    An MCP resource to expose via the Model Context Protocol (MCP).

    MCP resources provide LLMs with access to static or dynamic content like UI components,
    data files, or images. Unlike tools which perform actions, resources return content that
    the LLM can read and reference.

    ## Example

    ```elixir
    defmodule MyApp.Blog do
      use Ash.Domain, extensions: [AshAi]

      mcp_resources do
        # Description inherited from :render_card action
        mcp_resource :post_card, "file://ui/post_card.html", Post, :render_card,
          mime_type: "text/html"

        # Custom description overrides action description
        mcp_resource :post_data, "file://data/post.json", Post, :to_json,
          description: "JSON metadata including author, tags, and timestamps",
          mime_type: "application/json"
      end
    end
    ```

    The action is called when an MCP client requests the resource, and its return value
    (which must be a string) is sent to the client with the specified MIME type.

    ## Description Behavior

    Resource descriptions default to the action's description. You can provide a custom
    `description` option in the DSL which takes precedence over the action description.
    This helps LLMs understand when to use each resource.
    """
    @type t :: %__MODULE__{
            name: atom(),
            resource: Ash.Resource.t(),
            action: atom() | Ash.Resource.Actions.Action.t(),
            domain: module() | nil,
            title: String.t(),
            description: String.t(),
            uri: String.t(),
            mime_type: String.t()
          }

    defstruct [
      :name,
      :resource,
      :action,
      :domain,
      :title,
      :description,
      :uri,
      :mime_type,
      __spark_metadata__: nil
    ]
  end

  defmodule FullText do
    @moduledoc "A section that defines how complex vectorized columns are defined"
    defstruct [
      :used_attributes,
      :text,
      :__identifier__,
      name: :full_text_vector,
      __spark_metadata__: nil
    ]
  end

  defmodule Options do
    @moduledoc false
    use Spark.Options.Validator,
      schema: [
        actions: [
          type:
            {:wrap_list,
             {:tuple, [{:spark, Ash.Resource}, {:or, [{:list, :atom}, {:literal, :*}]}]}},
          doc: """
          A set of {Resource, [:action]} pairs, or `{Resource, :*}` for all actions. Defaults to everything. If `tools` is also set, both are applied as filters.
          """
        ],
        tools: [
          type: {:wrap_list, :atom},
          doc: """
           A list of tool names. If not set. Defaults to everything. If `actions` is also set, both are applied as filters.
          """
        ],
        mcp_resources: [
          type: {:or, [{:wrap_list, :atom}, {:literal, :*}]},
          doc: """
          A list of MCP resource names to expose, or `:*` for all. If not set, defaults to everything.
          """
        ],
        exclude_actions: [
          type: {:wrap_list, {:tuple, [{:spark, Ash.Resource}, :atom]}},
          doc: """
          A set of {Resource, :action} pairs, or `{Resource, :*}` to be excluded from the added actions.
          """
        ],
        actor: [
          type: :any,
          doc: "The actor performing any actions."
        ],
        tenant: [
          type: {:protocol, Ash.ToTenant},
          doc: "The tenant to use for the action."
        ],
        messages: [
          type: {:list, :map},
          default: [],
          doc: """
          Used to provide conversation history.
          """
        ],
        context: [
          type: :map,
          default: %{},
          doc: """
          Context passed to each action invocation.
          """
        ],
        otp_app: [
          type: :atom,
          doc: "If present, allows discovering resource actions automatically."
        ],
        system_prompt: [
          type: {:or, [{:fun, 1}, {:literal, :none}]},
          doc: """
          A system prompt that takes the provided options and returns a system prompt.

          You will want to include something like the actor's id if you are chatting as an
          actor.
          """
        ],
        on_tool_start: [
          type: {:fun, 1},
          required: false,
          doc: """
          A callback function that is called when a tool execution starts.

          Receives an `AshAi.ToolStartEvent` struct with the following fields:
          - `:tool_name` - The name of the tool being called
          - `:action` - The action being performed
          - `:resource` - The resource the action is on
          - `:arguments` - The arguments passed to the tool
          - `:actor` - The actor performing the action
          - `:tenant` - The tenant context

          Example:
          ```
          on_tool_start: fn %AshAi.ToolStartEvent{} = event ->
            IO.puts("Starting tool: \#{event.tool_name}")
          end
          ```
          """
        ],
        on_tool_end: [
          type: {:fun, 1},
          required: false,
          doc: """
          A callback function that is called when a tool execution completes.

          Receives an `AshAi.ToolEndEvent` struct with the following fields:
          - `:tool_name` - The name of the tool
          - `:result` - The result of the tool execution (either {:ok, ...} or {:error, ...})

          Example:
          ```
          on_tool_end: fn %AshAi.ToolEndEvent{} = event ->
            IO.puts("Completed tool: \#{event.tool_name}")
          end
          ```
          """
        ]
      ]
  end

  def functions(opts) do
    opts
    |> exposed_tools()
    |> Enum.map(&AshAi.Tools.to_function/1)
  end

  def iex_chat(lang_chain, opts \\ []) do
    opts = Options.validate!(opts)

    messages =
      case opts.system_prompt do
        :none ->
          []

        nil ->
          [
            LangChain.Message.new_system!("""
            You are a helpful assistant.
            Your purpose is to operate the application on behalf of the user.
            """)
          ]

        system_prompt ->
          [LangChain.Message.new_system!(system_prompt.(opts))]
      end

    handler = %{
      on_llm_new_delta: fn _chain, deltas ->
        # we received a piece of data
        for delta <- deltas do
          IO.write(LangChain.MessageDelta.content_to_string(delta))
        end
      end,
      on_message_processed: fn _chain, _data ->
        # the message was assembled and is processed
        IO.write("\n--\n")
      end
    }

    lang_chain
    |> LLMChain.add_messages(messages)
    |> setup_ash_ai(opts)
    |> LLMChain.add_callback(handler)
    |> run_loop(true)
  end

  @doc """
  Adds the requisite context and tool calls to allow an agent to interact with your app.
  """
  def setup_ash_ai(lang_chain, opts \\ [])

  def setup_ash_ai(lang_chain, opts) when is_list(opts) do
    opts = Options.validate!(opts)
    setup_ash_ai(lang_chain, opts)
  end

  def setup_ash_ai(lang_chain, opts) do
    tools = functions(opts)

    lang_chain
    |> LLMChain.add_tools(tools)
    |> LLMChain.update_custom_context(%{
      actor: opts.actor,
      tenant: opts.tenant,
      context: opts.context,
      tool_callbacks: %{
        on_tool_start: opts.on_tool_start,
        on_tool_end: opts.on_tool_end
      }
    })
  end

  defp run_loop(chain, first? \\ false) do
    chain
    |> LLMChain.run(mode: :while_needs_response)
    |> case do
      {:ok,
       %LangChain.Chains.LLMChain{
         last_message: %{content: content}
       } = new_chain} ->
        if !first? && !Map.get(new_chain.llm, :stream) do
          IO.puts(content)
        end

        user_message = get_user_message()

        new_chain
        |> LLMChain.add_messages([LangChain.Message.new_user!(user_message)])
        |> run_loop()

      {:error, _new_chain, error} ->
        raise "Something went wrong:\n #{Exception.format(:error, error)}"
    end
  end

  defp get_user_message do
    case Mix.shell().prompt("> ") do
      nil -> get_user_message()
      "" -> get_user_message()
      "\n" -> get_user_message()
      message -> message
    end
  end

  def to_json_api_errors(domain, resource, errors, type) when is_list(errors) do
    Enum.flat_map(errors, &to_json_api_errors(domain, resource, &1, type))
  end

  def to_json_api_errors(domain, resource, %mod{errors: errors}, type)
      when mod in [Forbidden, Framework, Invalid, Unknown] do
    Enum.flat_map(errors, &to_json_api_errors(domain, resource, &1, type))
  end

  def to_json_api_errors(_domain, _resource, %AshJsonApi.Error{} = error, _type) do
    [error]
  end

  def to_json_api_errors(domain, _resource, %{class: :invalid} = error, _type) do
    if AshJsonApi.ToJsonApiError.impl_for(error) do
      error
      |> AshJsonApi.ToJsonApiError.to_json_api_error()
      |> List.wrap()
      |> Enum.flat_map(&with_source_pointer(&1, error))
    else
      uuid = Ash.UUID.generate()

      stacktrace =
        case error do
          %{stacktrace: %{stacktrace: v}} ->
            v

          _ ->
            nil
        end

      Logger.warning(
        "`#{uuid}`: AshJsonApi.Error not implemented for error:\n\n#{Exception.format(:error, error, stacktrace)}"
      )

      if AshJsonApi.Domain.Info.show_raised_errors?(domain) do
        [
          %AshJsonApi.Error{
            id: uuid,
            status_code: class_to_status(error.class),
            code: "something_went_wrong",
            title: "SomethingWentWrong",
            detail: """
            Raised error: #{uuid}

            #{Exception.format(:error, error, stacktrace)}"
            """
          }
        ]
      else
        [
          %AshJsonApi.Error{
            id: uuid,
            status_code: class_to_status(error.class),
            code: "something_went_wrong",
            title: "SomethingWentWrong",
            detail: "Something went wrong. Error id: #{uuid}"
          }
        ]
      end
    end
  end

  def to_json_api_errors(_domain, _resource, %{class: :forbidden} = error, _type) do
    [
      %AshJsonApi.Error{
        id: Ash.UUID.generate(),
        status_code: class_to_status(error.class),
        code: "forbidden",
        title: "Forbidden",
        detail: "forbidden"
      }
    ]
  end

  def to_json_api_errors(_domain, _resource, error, _type) do
    uuid = Ash.UUID.generate()

    stacktrace =
      case error do
        %{stacktrace: %{stacktrace: v}} ->
          v

        _ ->
          nil
      end

    Logger.warning(
      "`#{uuid}`: AshJsonApi.Error not implemented for error:\n\n#{Exception.format(:error, error, stacktrace)}"
    )

    [
      %AshJsonApi.Error{
        id: uuid,
        status_code: class_to_status(error.class),
        code: "something_went_wrong",
        title: "SomethingWentWrong",
        detail: "Something went wrong. Error id: #{uuid}"
      }
    ]
  end

  @doc "Turns an error class into an HTTP status code"
  def class_to_status(:forbidden), do: 403
  def class_to_status(:invalid), do: 400
  def class_to_status(_), do: 500

  def with_source_pointer(%{source_pointer: source_pointer} = built_error, _)
      when source_pointer not in [nil, :undefined] do
    [built_error]
  end

  def with_source_pointer(built_error, %{fields: fields, path: path})
      when is_list(fields) and fields != [] do
    Enum.map(fields, fn field ->
      %{built_error | source_pointer: source_pointer(field, path)}
    end)
  end

  def with_source_pointer(built_error, %{field: field, path: path})
      when not is_nil(field) do
    [
      %{built_error | source_pointer: source_pointer(field, path)}
    ]
  end

  def with_source_pointer(built_error, _) do
    [built_error]
  end

  defp source_pointer(field, path) do
    "/input/#{Enum.join(List.wrap(path) ++ [field], "/")}"
  end

  @doc false

  def exposed_mcp_resources(opts) when is_list(opts) do
    exposed_mcp_resources(Options.validate!(opts))
  end

  def exposed_mcp_resources(opts) do
    if !opts.otp_app and !opts.actions do
      raise "Must specify `otp_app` if you do not specify `actions`"
    end

    domains =
      if opts.actions do
        opts.actions
        |> Enum.map(fn {resource, _actions} ->
          domain = Ash.Resource.Info.domain(resource)

          if !domain do
            raise "Cannot use an ash resource that does not have a domain"
          end

          domain
        end)
        |> Enum.uniq()
      else
        Application.get_env(opts.otp_app, :ash_domains) || []
      end

    domains
    |> Enum.flat_map(fn domain ->
      domain
      |> AshAi.Info.mcp_resources()
      |> Enum.filter(fn mcp_resource ->
        valid_mcp_resource(mcp_resource, opts.mcp_resources, opts.actions, opts.exclude_actions)
      end)
      |> Enum.map(fn mcp_resource ->
        action = Ash.Resource.Info.action(mcp_resource.resource, mcp_resource.action)

        %{
          mcp_resource
          | domain: domain,
            action: action,
            description: mcp_resource.description || action.description
        }
      end)
    end)
  end

  defp valid_mcp_resource(mcp_resource, allowed_mcp_resources, allowed_actions, exclude_actions) do
    # If mcp_resources filter is specified (including empty list), check membership
    passes_mcp_resources_filter =
      case allowed_mcp_resources do
        [:*] -> true
        :* -> true
        nil -> true
        [] -> false
        list when is_list(list) -> Enum.member?(list, mcp_resource.name)
      end

    # Check if actions filter is specified
    passes_actions_filter =
      if allowed_actions && allowed_actions != [] do
        Enum.any?(allowed_actions, fn
          {resource, :*} ->
            mcp_resource.resource == resource

          {resource, actions} when is_list(actions) ->
            mcp_resource.resource == resource && mcp_resource.action in actions
        end)
      else
        true
      end

    # Check if this is in the exclude list
    is_excluded =
      if exclude_actions && exclude_actions != [] do
        Enum.any?(exclude_actions, fn {resource, action} ->
          mcp_resource.resource == resource && mcp_resource.action == action
        end)
      else
        false
      end

    passes_mcp_resources_filter && passes_actions_filter && !is_excluded
  end

  def exposed_tools(opts) when is_list(opts) do
    exposed_tools(Options.validate!(opts))
  end

  def exposed_tools(opts) do
    if opts.actions do
      Enum.flat_map(opts.actions, fn
        {resource, actions} ->
          domain = Ash.Resource.Info.domain(resource)

          if !domain do
            raise "Cannot use an ash resource that does not have a domain"
          end

          tools = AshAi.Info.tools(domain)

          if !Enum.any?(tools, fn tool ->
               tool.resource == resource && (actions == :* || tool.action in actions)
             end) do
            raise "Cannot use an action that is not exposed as a tool"
          end

          if actions == :* do
            tools
            |> Enum.filter(&(&1.resource == resource))
            |> Enum.map(fn tool ->
              %{tool | domain: domain, action: Ash.Resource.Info.action(resource, tool.action)}
            end)
          else
            tools
            |> Enum.filter(&(&1.resource == resource && &1.action in actions))
            |> Enum.map(fn tool ->
              %{tool | domain: domain, action: Ash.Resource.Info.action(resource, tool.action)}
            end)
          end
      end)
    else
      if !opts.otp_app do
        raise "Must specify `otp_app` if you do not specify `actions`"
      end

      for domain <- Application.get_env(opts.otp_app, :ash_domains) || [],
          tool <- AshAi.Info.tools(domain) do
        %{tool | domain: domain, action: Ash.Resource.Info.action(tool.resource, tool.action)}
      end
    end
    |> Enum.uniq()
    |> then(fn tools ->
      if is_list(opts.exclude_actions) do
        Enum.reject(tools, fn tool ->
          {tool.resource, tool.action.name} in opts.exclude_actions
        end)
      else
        tools
      end
    end)
    |> then(fn tools ->
      if allowed_tools = opts.tools do
        Enum.filter(tools, fn tool ->
          tool.name in List.wrap(allowed_tools)
        end)
      else
        tools
      end
    end)
    |> Enum.filter(
      &can?(
        opts.actor,
        &1.domain,
        &1.resource,
        &1.action,
        opts.tenant
      )
    )
  end

  def has_vectorize_change?(%Ash.Changeset{} = changeset) do
    full_text_attrs =
      AshAi.Info.vectorize(changeset.resource) |> Enum.flat_map(& &1.used_attributes)

    vectorized_attrs =
      AshAi.Info.vectorize_attributes!(changeset.resource)
      |> Enum.map(fn {attr, _} -> attr end)

    Enum.any?(vectorized_attrs ++ full_text_attrs, fn attr ->
      Ash.Changeset.changing_attribute?(changeset, attr)
    end)
  end

  defp can?(actor, domain, resource, action, tenant) do
    if Enum.empty?(Ash.Resource.Info.authorizers(resource)) do
      true
    else
      Ash.can?({resource, action}, actor,
        tenant: tenant,
        domain: domain,
        context: %{private: %{ash_ai_pre_check?: true}},
        maybe_is: true,
        run_queries?: false,
        pre_flight?: false
      )
    end
  rescue
    e ->
      Logger.error(
        """
        Error raised while checking permissions for #{inspect(resource)}.#{action.name}

        When checking permissions, we check the action using an empty input.
        Your action should be prepared for this.

        For create/update/destroy actions, you may need to add `only_when_valid?: true`
        to the changes, for other things, you may want to check validity of the changeset,
        query or action input.

        #{Exception.format(:error, e, __STACKTRACE__)}
        """,
        __STACKTRACE__
      )

      false
  end
end
