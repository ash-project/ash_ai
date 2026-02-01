# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Dsl do
  @moduledoc """
  Spark DSL schemas and configuration for AshAi.

  This module contains all the DSL entity and section definitions that define
  how AshAi resources are configured, including tools, vectorization, and MCP resources.
  """

  require Ash.Expr

  @tool_argument_schema [
    name: [
      type: :atom,
      required: true,
      doc: "The name of the argument."
    ],
    type: [
      type: :any,
      required: true,
      doc: "The Ash type of the argument (e.g., :string, :date, :integer)."
    ],
    constraints: [
      type: :keyword_list,
      default: [],
      doc: "Type constraints (e.g., [max_length: 10]). These are converted to JSON Schema rules."
    ],
    description: [
      type: :string,
      doc: "A description for the Agent."
    ],
    allow_nil?: [
      type: :boolean,
      default: true,
      doc: "If set to `false`, the argument is marked as required in the generated JSON Schema."
    ],
    default: [
      type: :any,
      doc: "The default value if not provided."
    ]
  ]

  @tool_schema [
    name: [type: :atom, required: true],
    resource: [type: {:spark, Ash.Resource}, required: true],
    action: [type: :atom, required: true],
    action_parameters: [
      type: {:list, :atom},
      required: false,
      doc:
        "A list of action specific parameters to allow for the underlying action. Only relevant for reads, and defaults to allowing `[:sort, :offset, :limit, :result_type, :filter]`"
    ],
    load: [
      type: :any,
      default: [],
      doc: """
      A list of relationships and calculations to load, or an anonymous function/1.

      Note that loaded fields can include private attributes, which will then be included in the tool's response. However, private attributes cannot be used for filtering, sorting, or aggregation.

      If a function is provided, it will be called with the tool input (a Map with **String keys**) and must return the final load list.

      ## Example
      load fn input ->
        [schedule: [date: input["date"]]] # Use string keys!
      end
      """
    ],
    async: [type: :boolean, default: true],
    description: [
      type: :string,
      doc: "A description for the tool. Defaults to the action's description."
    ],
    identity: [
      type: :atom,
      default: nil,
      doc:
        "The identity to use for update/destroy actions. Defaults to the primary key. Set to `false` to disable entirely."
    ],
    _meta: [
      type: :any,
      default: %{},
      doc:
        "Optional metadata map for tool integrations. Supports provider-specific extensions like OpenAI metadata. Keys and values should be strings to comply with JSON-RPC serialization."
    ]
  ]

  @mcp_resource_schema [
    name: [type: :atom, required: true],
    title: [
      type: :string,
      required: true,
      doc: "A short, human-readable title for the resource."
    ],
    description: [
      type: :string,
      doc:
        "A description of the resource. This is important for LLM to determine what the resource is and when to call it. Defaults to the Action's description if not provided."
    ],
    uri: [
      type: :string,
      required: true,
      doc: "The URI where the resource can be accessed."
    ],
    mime_type: [
      type: :string,
      default: "text/plain",
      doc: "The MIME type of the resource, e.g. 'application/json', 'image/png', etc."
    ],
    resource: [type: {:spark, Ash.Resource}, required: true],
    action: [type: :atom, required: true]
  ]

  @full_text_schema [
    name: [
      type: :atom,
      default: :full_text_vector,
      doc: "The name of the attribute to store the text vector in"
    ],
    used_attributes: [
      type: {:list, :atom},
      doc: "If set, a vector is only regenerated when these attributes are changed"
    ],
    text: [
      type: {:fun, 1},
      required: true,
      doc:
        "A function or expr that takes a list of records and computes a full text string that will be vectorized. If given an expr, use `atomic_ref` to refer to new values, as this is set as an atomic update."
    ]
  ]

  @full_text %Spark.Dsl.Entity{
    name: :full_text,
    imports: [Ash.Expr],
    target: AshAi.FullText,
    identifier: :name,
    schema: @full_text_schema
  }

  @vectorize %Spark.Dsl.Section{
    name: :vectorize,
    entities: [
      @full_text
    ],
    schema: [
      attributes: [
        type: :keyword_list,
        doc:
          "A keyword list of attributes to vectorize, and the name of the attribute to store the vector in",
        default: []
      ],
      strategy: [
        type: {:one_of, [:after_action, :manual, :ash_oban, :ash_oban_manual]},
        default: :after_action,
        doc:
          "How to compute the vector. Currently supported strategies are `:after_action`, `:manual`, and `:ash_oban`."
      ],
      define_update_action_for_manual_strategy?: [
        type: :boolean,
        default: true,
        doc:
          "If true, an `ash_ai_update_embeddings` update action will be defined, which will automatically update the embeddings when run."
      ],
      ash_oban_trigger_name: [
        type: :atom,
        default: :ash_ai_update_embeddings,
        doc:
          "The name of the AshOban-trigger that will be run in order to update the record's embeddings. Defaults to `:ash_ai_update_embeddings`."
      ],
      embedding_model: [
        type: {:spark_behaviour, AshAi.EmbeddingModel},
        required: true
      ]
    ]
  }

  @tool_argument %Spark.Dsl.Entity{
    name: :argument,
    schema: @tool_argument_schema,
    describe: "An argument to be passed to the tool.",
    target: AshAi.Tool.Argument,
    args: [:name, :type]
  }

  @tool %Spark.Dsl.Entity{
    name: :tool,
    describe: """
    Expose an Ash action as a tool that can be called by LLMs.

    Tools allow LLMs to interact with your application by calling specific actions on resources.
    Only public attributes can be used for filtering, sorting, and aggregation, but the `load`
    option allows including private attributes in the response data.
    """,
    examples: [
      ~s(tool :list_artists, Artist, :read),
      ~s(tool :create_artist, Artist, :create, description: "Create a new artist"),
      ~s(tool :update_artist, Artist, :update, identity: :id, load: [:albums]),
      ~s|tool :get_board, Board, :read, _meta: %{"openai/outputTemplate" => "ui://widget/kanban-board.html", "openai/toolInvocation/invoking" => "Preparing the board…", "openai/toolInvocation/invoked" => "Board ready."}|
    ],
    target: AshAi.Tool,
    schema: @tool_schema,
    args: [:name, :resource, :action],
    entities: [
      arguments: [@tool_argument]
    ]
  }

  @tools %Spark.Dsl.Section{
    name: :tools,
    entities: [
      @tool
    ]
  }

  @mcp_resource %Spark.Dsl.Entity{
    name: :mcp_resource,
    describe: """
    An MCP resource to expose via the Model Context Protocol (MCP).
    MCP Resources are different to Ash Resources. Here they are used to
    respond to LLM models with static or dynamic assets like files, images, or JSON.

    The resource description defaults to the action's description. You can override this
    by providing a `description` option which takes precedence.
    """,
    examples: [
      ~s(mcp_resource :artist_card, "file://info/artist_info.txt", Artist, :artist_info),
      ~s(mcp_resource :artist_card, "file://ui/artist_card.html", Artist, :artist_card, mime_type: "text/html"),
      ~s(mcp_resource :artist_data, "file://data/artist.json", Artist, :to_json, description: "Artist metadata as JSON", mime_type: "application/json")
    ],
    target: AshAi.McpResource,
    schema: @mcp_resource_schema,
    args: [:name, :uri, :resource, :action]
  }

  @mcp_resources %Spark.Dsl.Section{
    name: :mcp_resources,
    entities: [
      @mcp_resource
    ]
  }

  @doc false
  def sections do
    [@tools, @vectorize, @mcp_resources]
  end
end
