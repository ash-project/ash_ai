# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi do
  @moduledoc """
  Documentation for `AshAi`.
  """

  alias ReqLLM.Context

  defstruct []

  require Logger

  use Spark.Dsl.Extension,
    sections: AshAi.Dsl.sections(),
    imports: [AshAi.Actions],
    transformers: [
      AshAi.Transformers.Vectorize,
      AshAi.Transformers.ResourceTools,
      AshAi.Transformers.McpApps
    ],
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
      :ui,
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

  defmodule McpUiResource do
    @moduledoc """
    A UI resource for MCP Apps (Model Context Protocol Apps extension).

    UI resources serve static HTML files that are rendered in sandboxed iframes by MCP hosts
    (like Claude Desktop). They are linked to tools via `_meta.ui.resourceUri` and provide
    interactive interfaces for tool results.

    ## Example

        mcp_resources do
          mcp_ui_resource :estimates_list, "ui://estimates/list.html",
            html_path: "priv/mcp_apps/estimates.html"

          mcp_ui_resource :dashboard, "ui://dashboard.html",
            html_path: "priv/mcp_apps/dashboard.html",
            csp: [connect_domains: ["api.example.com"]],
            permissions: [camera: true]
        end

    The HTML file at `html_path` is read at request time and returned with MIME type
    `text/html;profile=mcp-app`.

    See [MCP Apps spec](https://modelcontextprotocol.io/specification/2025-11-25).
    """

    @mime_type "text/html;profile=mcp-app"

    @type t :: %__MODULE__{
            name: atom(),
            uri: String.t(),
            html_path: String.t(),
            title: String.t() | nil,
            description: String.t() | nil,
            csp: keyword() | nil,
            permissions: keyword() | nil,
            domain: :auto | String.t() | nil,
            prefers_border: boolean() | nil
          }

    defstruct [
      :name,
      :uri,
      :html_path,
      :title,
      :description,
      :csp,
      :permissions,
      :domain,
      :prefers_border,
      __spark_metadata__: nil
    ]

    @doc "Returns the fixed MIME type for MCP App UI resources."
    def mime_type, do: @mime_type
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
          type: {:or, [:boolean, {:wrap_list, :atom}]},
          default: true,
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
        ],
        strict: [
          type: :boolean,
          default: true,
          doc: """
          Whether to use strict schema mode when generating tool parameter schemas.

          When `true` (the default), applies OpenAI-compatible strict schema transformation: all objects get
          `additionalProperties: false`, all properties are included in `required`,
          and optional properties are wrapped in `anyOf: [null, type]`.

          Set to `false` when using providers that do not support this schema format.
          For example, Google Gemini rejects `additionalProperties` in function declarations.

          When `false`, `additionalProperties` is stripped from the schema and no
          `anyOf` null-wrapping is applied.
          """
        ],
        model: [
          type: :any,
          default: "openai:gpt-4o-mini",
          doc: """
          The LLM model specification used by ReqLLM.

          Can be:
          - a string (e.g. `"openai:gpt-4o-mini"`)
          - a tuple accepted by ReqLLM (e.g. `{:anthropic, [id: "claude-sonnet-4-5"]}`)
          - a function returning either format
          """
        ],
        req_llm: [
          type: :atom,
          default: ReqLLM,
          doc: """
          The ReqLLM module to use. Defaults to `ReqLLM`.
          Useful for tests with a mock ReqLLM module.
          """
        ],
        req_llm_opts: [
          type: :keyword_list,
          default: [],
          doc: """
          Additional options passed through to ReqLLM requests.

          AshAi still controls the final `:tools` value used for tool-calling.
          """
        ],
        extra_tools: [
          type: {:list, :any},
          default: [],
          doc: """
          Additional ReqLLM tools to expose alongside AshAi-discovered tools.

          Accepts either:
          - `%ReqLLM.Tool{}`
          - `{%ReqLLM.Tool{}, callback}` where `callback` is `fn args, context -> ... end`
          """
        ],
        max_iterations: [
          type: {:or, [:pos_integer, {:literal, :infinity}]},
          default: 10,
          doc: """
          Maximum number of tool-calling iterations before terminating.

          Set to `:infinity` to disable iteration limits.
          """
        ]
      ]
  end

  @doc """
  Returns ReqLLM tools for the given options.
  """
  def list_tools(opts) when is_list(opts), do: list_tools(Options.validate!(opts))
  def list_tools(opts), do: AshAi.Tools.list(opts)

  @doc """
  Returns `{tools, registry}` for ReqLLM tool-calling flows.
  """
  def build_tools_and_registry(opts) when is_list(opts) do
    opts
    |> Options.validate!()
    |> build_tools_and_registry()
  end

  def build_tools_and_registry(opts), do: AshAi.Tools.build_tools_and_registry(opts)

  @doc """
  Interactive IEx chat loop powered by ReqLLM.
  """
  def iex_chat(opts \\ []) do
    validated_opts = Options.validate!(opts)

    base_messages =
      case validated_opts.system_prompt do
        :none ->
          []

        nil ->
          [
            Context.system("""
            You are a helpful assistant.
            Your purpose is to operate the application on behalf of the user.
            """)
          ]

        system_prompt ->
          [Context.system(system_prompt.(validated_opts))]
      end

    run_iex_loop(base_messages, opts)
  end

  defp run_iex_loop(messages, opts) do
    case AshAi.ToolLoop.run(messages, opts) do
      {:ok, %AshAi.ToolLoop.Result{messages: updated_messages, final_text: final_text}} ->
        if final_text != "" do
          IO.puts(final_text)
        end

        case get_user_message() do
          :eof ->
            :ok

          user_message ->
            run_iex_loop(updated_messages ++ [Context.user(user_message)], opts)
        end

      {:error, error} ->
        raise "Something went wrong:\n #{inspect(error)}"
    end
  end

  defp get_user_message do
    case Mix.shell().prompt("> ") do
      nil -> :eof
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

  def exposed_mcp_action_resources(opts) when is_list(opts) do
    exposed_mcp_action_resources(Options.validate!(opts))
  end

  def exposed_mcp_action_resources(opts) do
    opts
    |> resolve_domains()
    |> Enum.flat_map(fn domain ->
      domain
      |> AshAi.Info.mcp_action_resources()
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

  @doc false
  def exposed_mcp_ui_resources(opts) when is_list(opts) do
    exposed_mcp_ui_resources(Options.validate!(opts))
  end

  def exposed_mcp_ui_resources(opts) do
    opts
    |> resolve_domains()
    |> Enum.flat_map(fn domain ->
      domain
      |> AshAi.Info.mcp_ui_resources()
      |> Enum.filter(fn ui_resource ->
        case opts.mcp_resources do
          nil -> true
          :* -> true
          [:*] -> true
          [] -> false
          list when is_list(list) -> ui_resource.name in list
        end
      end)
    end)
  end

  defp resolve_domains(opts) do
    if !opts.otp_app and !opts.actions do
      raise "Must specify `otp_app` if you do not specify `actions`"
    end

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
    if opts.tools in [false, []] do
      []
    else
      if opts.actions do
        Enum.flat_map(opts.actions, fn
          {resource, actions} ->
            tools = tools_for_resource(resource)

            if !Enum.any?(tools, fn tool ->
                 actions == :* || tool.action.name in actions
               end) do
              raise "Cannot use an action that is not exposed as a tool"
            end

            if actions == :* do
              tools
            else
              tools
              |> Enum.filter(&(&1.action.name in actions))
            end
        end)
      else
        if !opts.otp_app do
          raise "Must specify `otp_app` if you do not specify `actions`"
        end

        for domain <- Application.get_env(opts.otp_app, :ash_domains) || [],
            tool <- tools_for_domain(domain) do
          tool
        end
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
      case opts.tools do
        true -> tools
        false -> []
        allowed_tools -> Enum.filter(tools, &(&1.name in allowed_tools))
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

  defp tools_for_domain(domain) do
    domain_tools = attach_tool_runtime_details(AshAi.Info.tools(domain), domain)

    resource_tools =
      domain
      |> Ash.Domain.Info.resources()
      |> Enum.flat_map(fn resource ->
        resource
        |> AshAi.Info.tools()
        |> attach_tool_runtime_details(domain)
      end)

    ensure_unique_tool_names!(domain_tools ++ resource_tools, domain)
  end

  defp tools_for_resource(resource) do
    domain = Ash.Resource.Info.domain(resource)

    if !domain do
      raise "Cannot use an ash resource that does not have a domain"
    end

    domain
    |> tools_for_domain()
    |> Enum.filter(&(&1.resource == resource))
  end

  defp attach_tool_runtime_details(tools, domain) do
    Enum.map(tools, fn tool ->
      %{tool | domain: domain, action: Ash.Resource.Info.action(tool.resource, tool.action)}
    end)
  end

  defp ensure_unique_tool_names!(tools, domain) do
    duplicates =
      tools
      |> Enum.map(& &1.name)
      |> Enum.frequencies()
      |> Enum.filter(fn {_name, count} -> count > 1 end)
      |> Enum.map(fn {name, _count} -> name end)
      |> Enum.sort()

    case duplicates do
      [] ->
        tools

      names ->
        raise ArgumentError, """
        Duplicate tool names found in #{inspect(domain)}: #{Enum.join(names, ", ")}.

        Tool names must be unique per domain across both:
        - domain-level `tools do ... end`
        - resource-level `tools do ... end`
        """
    end
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
      Logger.error("""
      Error raised while checking permissions for #{inspect(resource)}.#{action.name}

      When checking permissions, we check the action using an empty input.
      Your action should be prepared for this.

      For create/update/destroy actions, you may need to add `only_when_valid?: true`
      to the changes, for other things, you may want to check validity of the changeset,
      query or action input.

      #{Exception.format(:error, e, __STACKTRACE__)}
      """)

      false
  end
end
