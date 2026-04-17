<!--
SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>

SPDX-License-Identifier: MIT
-->

# Ash AI
<img src="https://github.com/ash-project/ash_ai/blob/main/logos/ash_ai.png?raw=true" alt="Logo" width="300"/>

[![DeepWiki](https://img.shields.io/badge/DeepWiki-ash--project%2Fash__ai-blue.svg?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACwAAAAyCAYAAAAnWDnqAAAAAXNSR0IArs4c6QAAA05JREFUaEPtmUtyEzEQhtWTQyQLHNak2AB7ZnyXZMEjXMGeK/AIi+QuHrMnbChYY7MIh8g01fJoopFb0uhhEqqcbWTp06/uv1saEDv4O3n3dV60RfP947Mm9/SQc0ICFQgzfc4CYZoTPAswgSJCCUJUnAAoRHOAUOcATwbmVLWdGoH//PB8mnKqScAhsD0kYP3j/Yt5LPQe2KvcXmGvRHcDnpxfL2zOYJ1mFwrryWTz0advv1Ut4CJgf5uhDuDj5eUcAUoahrdY/56ebRWeraTjMt/00Sh3UDtjgHtQNHwcRGOC98BJEAEymycmYcWwOprTgcB6VZ5JK5TAJ+fXGLBm3FDAmn6oPPjR4rKCAoJCal2eAiQp2x0vxTPB3ALO2CRkwmDy5WohzBDwSEFKRwPbknEggCPB/imwrycgxX2NzoMCHhPkDwqYMr9tRcP5qNrMZHkVnOjRMWwLCcr8ohBVb1OMjxLwGCvjTikrsBOiA6fNyCrm8V1rP93iVPpwaE+gO0SsWmPiXB+jikdf6SizrT5qKasx5j8ABbHpFTx+vFXp9EnYQmLx02h1QTTrl6eDqxLnGjporxl3NL3agEvXdT0WmEost648sQOYAeJS9Q7bfUVoMGnjo4AZdUMQku50McDcMWcBPvr0SzbTAFDfvJqwLzgxwATnCgnp4wDl6Aa+Ax283gghmj+vj7feE2KBBRMW3FzOpLOADl0Isb5587h/U4gGvkt5v60Z1VLG8BhYjbzRwyQZemwAd6cCR5/XFWLYZRIMpX39AR0tjaGGiGzLVyhse5C9RKC6ai42ppWPKiBagOvaYk8lO7DajerabOZP46Lby5wKjw1HCRx7p9sVMOWGzb/vA1hwiWc6jm3MvQDTogQkiqIhJV0nBQBTU+3okKCFDy9WwferkHjtxib7t3xIUQtHxnIwtx4mpg26/HfwVNVDb4oI9RHmx5WGelRVlrtiw43zboCLaxv46AZeB3IlTkwouebTr1y2NjSpHz68WNFjHvupy3q8TFn3Hos2IAk4Ju5dCo8B3wP7VPr/FGaKiG+T+v+TQqIrOqMTL1VdWV1DdmcbO8KXBz6esmYWYKPwDL5b5FA1a0hwapHiom0r/cKaoqr+27/XcrS5UwSMbQAAAABJRU5ErkJggg==)](https://deepwiki.com/ash-project/ash_ai)
![Elixir CI](https://github.com/ash-project/ash_ai/workflows/CI/badge.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Hex version badge](https://img.shields.io/hexpm/v/ash_ai.svg)](https://hex.pm/packages/ash_ai)
[![Hexdocs badge](https://img.shields.io/badge/docs-hexdocs-purple)](https://hexdocs.pm/ash_ai)
[![REUSE status](https://api.reuse.software/badge/github.com/ash-project/ash_ai)](https://api.reuse.software/info/github.com/ash-project/ash_ai)


## Installation

<!-- tabs-open -->

### With Igniter

You can install `AshAi` using igniter. For example:
```sh
mix igniter.install ash_ai
```

### Manually

Add `AshAi` to your list of dependencies:

```elixir
def deps do
  [
    {:ash_ai, "~> 0.2"}
  ]
end
```

<!-- tabs-close -->


## MCP (Model Context Protocol) Server

Both the dev & production MCP servers can be installed with

`mix ash_ai.gen.mcp`

### Dev MCP Server

To install the dev MCP server, add the `AshAi.Mcp.Dev` plug to your
endpoint module, in the `code_reloading?` block. By default the
mcp server will be available under `http://localhost:4000/ash_ai/mcp`.



```elixir
  if code_reloading? do
    socket "/phoenix/live_reload/socket", Phoenix.LiveReloader.Socket

    plug AshAi.Mcp.Dev,
      # see the note below on protocol versions below
      protocol_version_statement: "2024-11-05",
      otp_app: :your_app
```

We are still experimenting to see what tools (if any) are useful while developing with agents.

### Production MCP Server

AshAi provides a pre-built MCP server that can be used to expose your tool definitions to an MCP client (typically some kind of IDE, or Claude Desktop for example).

The protocol version we implement is 2025-03-26. As of this writing, many tools have not yet been updated to support this version. You will generally need to use some kind of proxy until tools have been updated accordingly. We suggest this one, provided by tidewave. https://github.com/tidewave-ai/mcp_proxy_rust#installation

However, as of the writing of this guide, it requires setting a previous protocol version as noted above.

#### Roadmap

- Implement OAuth2 flow with AshAuthentication (long term)
- Implement sessions, and provide a session id context to tools (this code is just commented out, and can be uncommented, just needs timeout logic for inactive sesions)

#### Installation

##### Authentication

We don't currently support the OAuth2 flow out of the box with AshAi, but the goal is to eventually support this with AshAuthentication. You can always implement that yourself, but the quickest way to value is to use the new `api_key` strategy.

If you haven't installed `AshAuthentication` yet, install it like so: `mix igniter.install ash_authentication --auth-strategy api_key`.
If its already been installed, and you haven't set up API keys, use `mix ash_authentication.add_strategy api_key`.

Then, create a separate pipeline for `:mcp`, and add the api key plug to it:

```elixir
pipeline :mcp do
  plug AshAuthentication.Strategy.ApiKey.Plug,
    resource: YourApp.Accounts.User,
    # Use `required?: false` to allow unauthenticated
    # users to connect, for example if some tools
    # are publicly accessible.
    required?: false
end
```

##### Add the MCP server to your router

```elixir
scope "/mcp" do
  pipe_through :mcp

  forward "/", AshAi.Mcp.Router,
    tools: [
      :list,
      :of,
      :tools
    ],
    # For many tools, you will need to set the `protocol_version_statement` to the older version.
    protocol_version_statement: "2024-11-05",
    otp_app: :my_app
end
```

## `mix ash_ai.gen.chat`

This is a new and experimental tool to generate a chat feature for your Ash & Phoenix application. It is backed by `ash_oban` and `ash_postgres`, using `pub_sub` to stream messages to the client. Generated responders use `AshAi.ToolLoop.stream/2` (ReqLLM streaming) for incremental response updates. This is primarily a tool to get started with chat features and is by no means intended to handle every case you can come up with.

To get started:
```
mix ash_ai.gen.chat --live
```

The `--live` flag indicates that you wish to generate liveviews in addition to the chat resources.

It requires a `user` resource to exist. If your `user` resource is not called `<YourApp>.Accounts.User`, provide a custom user resource with the `--user`
flag.

To try it out from scratch:

```sh
mix igniter.new my_app \
  --with phx.new \
  --install ash,ash_postgres,ash_phoenix \
  --install ash_authentication_phoenix,ash_oban \
  --install ash_ai@github:ash-project/ash_ai \
  --auth-strategy password
```

and then run:

```sh
mix ash_ai.gen.chat --live
```

### Specify your LLM API key

By default, it uses OpenAI as the LLM provider, so set your API key as an environment variable (for example, `OPENAI_API_KEY=sk-...`).

### Ensure you have Tailwind and DaisyUI

The Chat UI liveview templates assume you have Tailwind and DaisyUI installed for styling purposes. DaisyUI is included in Phoenix 1.8 and later but if you generated your Phoenix app pre-1.8 then [install DaisyUI](https://daisyui.com/docs/install/).

### Access the chat route

You can then start your server and visit `http://localhost:4000/chat` to see the chat feature in action. You will be prompted to register first and sign in the first time.

### Tool call/result UI extraction

Generated `ChatLive` and `ChatComponent` modules call `AshAi.ChatUI.Tools.extract/1` to normalize tool call and tool result data.

If you need custom behavior, override the seam in the generated module:

```elixir
@chat_ui_tools MyApp.ChatUITools
```

### Register tools for the chatbot

Generated chat domains include two starter tools out of the box:
- `:chat_list_conversations`
- `:chat_message_history`

These are useful for validating tool calling quickly. For real app behavior, add domain-specific tools (see below).

## Expose actions as tool calls

```elixir
defmodule MyApp.Blog do
  use Ash.Domain, extensions: [AshAi]

  tools do
    tool :read_posts, MyApp.Blog.Post, :read
    tool :create_post, MyApp.Blog.Post, :create
    tool :publish_post, MyApp.Blog.Post, :publish
    tool :read_comments, MyApp.Blog.Comment, :read
  end
end
```

Expose these actions as tools. Use `AshAi.build_tools_and_registry/1` to get ReqLLM tools and callbacks,
or use `AshAi.ToolLoop.run/2` / `AshAi.ToolLoop.stream/2` to execute the full model + tool loop.

You can also define tools directly on a resource using the 2-argument shorthand:

```elixir
defmodule MyApp.Blog.Post do
  use Ash.Resource, extensions: [AshAi]

  tools do
    tool :read_posts, :read
    tool :create_post, :create
  end
end
```

This shorthand expands to the same tool definition as `tool :name, MyApp.Blog.Post, :action`.

When discovering tools with `AshAi.exposed_tools/1` and `actions: [{Resource, ...}]`, AshAi includes:
- tools defined on the domain for that resource
- tools defined directly on the resource

For migration guidance around `extra_tools`, `req_llm_opts`, and legacy adapter mapping, see [LangChain to ReqLLM Migration Guide](/documentation/topics/langchain-to-reqllm-migration.md).

## Expose content as MCP resources

MCP resources provide LLMs with access to static or dynamic content like UI components, data files, or images. Unlike tools which perform actions, resources return content that the LLM can read and reference.

```elixir
defmodule MyApp.Blog do
  use Ash.Domain, extensions: [AshAi]

  mcp_resources do
    # Return HTML UI for a post
    # Description is inherited from the :render_card action
    mcp_resource :post_card, "file://ui/post_card.html", Post, :render_card do
      mime_type "text/html"
    end

    # Return JSON data with custom description
    mcp_resource :post_metadata, "file://data/post.json", Post, :metadata do
      description "Metadata about the post including author and tags",
      mime_type "application/json"
    end
  end
end
```

Resources are exposed via the MCP server at `/mcp` and can be accessed by MCP-compatible clients. The action is called when the resource is read, and its return value is sent to the LLM.

**Description Behavior**: Resource descriptions default to the action's description. You can override this by providing a `description` option in the DSL, which takes precedence.

### Tool Data Access

**Important**: Tools have different access levels for different operations:
- **Filtering/Sorting/Aggregation**: Only public attributes (`public?: true`) can be used
- **Arguments**: Only public action arguments are exposed
- **Response data**: Public attributes are returned by default
- **Loading data**: Use the `load` option to include relationships, calculations, or additional attributes (including private ones) in responses

Example:
```elixir
tools do
  # Returns only public attributes
  tool :read_posts, MyApp.Blog.Post, :read
  
  # Returns public attributes AND loaded relationships/calculations
  # Note: loaded fields can include private attributes
  tool :read_posts_with_details, MyApp.Blog.Post, :read,
    load: [:author, :comment_count, :internal_notes]
end
```

Key distinction:
- Private attributes cannot be used for filtering, sorting, or aggregation
- Private attributes CAN be included in responses when using the `load` option
- The `load` option is primarily for loading relationships and calculations, but also makes any loaded attributes (including private ones) visible

### Tool Execution Callbacks

Monitor tool execution in real-time by providing callbacks to `AshAi.ToolLoop.run/2`:

```elixir
AshAi.ToolLoop.run(messages,
  actor: current_user,
  on_tool_start: fn %AshAi.ToolStartEvent{} = event ->
    # event includes: tool_name, action, resource, arguments, actor, tenant
    IO.puts("Starting #{event.tool_name}...")
  end,
  on_tool_end: fn %AshAi.ToolEndEvent{} = event ->
    # event includes: tool_name, result ({:ok, ...} or {:error, ...})
    IO.puts("Completed #{event.tool_name}")
  end
)
```

This is useful for showing progress indicators, logging, metrics collection, or debugging tool execution.

## Prompt-backed actions

This allows defining an action, including input and output types, and delegating the
implementation to an LLM. We use structured outputs to ensure that it always returns
the correct data type. We also derive a default prompt from the action description and
action inputs. See `AshAi.Actions.Prompt` for more information.

```elixir
action :analyze_sentiment, :atom do
  constraints one_of: [:positive, :negative]

  description """
  Analyzes the sentiment of a given piece of text to determine if it is overall positive or negative.
  """

  argument :text, :string do
    allow_nil? false
    description "The text for analysis"
  end

  run prompt("openai:gpt-4o",
    # setting `tools: true` allows it to use all exposed tools in your app
    tools: true,
    # alternatively you can restrict it to only a set of tools
    # tools: [:list, :of, :tool, :names]
    # provide an optional prompt, which is an EEx template
    # prompt: "Analyze the sentiment of the following text: <%= @input.arguments.description %>",
    # optional req_llm override for tests
    # req_llm: MyApp.MockReqLLM
  )
end
```

Prompt-backed action options to know:
- `tools:` can be `false`, `true`, or a list of tool names.
- `max_iterations:` defaults to `:infinity` for prompt actions (set an integer to bound tool loops).
- `verbose?: true` enables debug logging for tool loop lifecycle events.
- Tool loop failures are returned as action errors (with loop reason details) instead of raising runtime exceptions.

### Using Custom Types for Structured Outputs

The action's return type provides the JSON schema automatically. For complex structured outputs, you can use any Ash type:

```elixir
# Example using Ash.TypedStruct
defmodule JobListing do
  use Ash.TypedStruct

  typed_struct do
    field :title, :string, allow_nil?: false
    field :company, :string, allow_nil?: false
    field :location, :string
    field :requirements, {:array, :string}
  end
end

# Use it as the return type for your action
action :parse_job, JobListing do
  argument :raw_content, :string, allow_nil?: false

  run prompt("openai:gpt-4o-mini",
    prompt: "Parse this job listing: <%= @input.arguments.raw_content %>",
    tools: false
  )
end
```

For unconstrained `:map` returns, prompt actions use a permissive map schema (`type: object`) so arbitrary map keys are accepted.

### Setting up ReqLLM

Configure provider keys under `:req_llm` in `runtime.exs`, for example:

```elixir
config :req_llm, openai_api_key: System.fetch_env!("OPENAI_API_KEY")
config :req_llm, anthropic_api_key: System.fetch_env!("ANTHROPIC_API_KEY")
config :req_llm, google_api_key: System.fetch_env!("GOOGLE_API_KEY")
```

For AshAi-specific model notes:
- [Google Gemini 2.5](/documentation/models/gemini.md)
- [LangChain to ReqLLM Migration Guide](/documentation/topics/langchain-to-reqllm-migration.md)

## Vectorization

See `AshPostgres` vector setup for required steps: https://hexdocs.pm/ash_postgres/AshPostgres.Extensions.Vector.html

This extension creates a vector search action, and provides a few different strategies for how to
update the embeddings when needed.

You can have multiple `full_text`s in the case where you want to vectorize multiple groups of columns together, in the
case where you wish to do so, you should specify the `name` of the generated `full_text` column.

```elixir
# in a resource

vectorize do
  full_text do
    text(fn record ->
      """
      Name: #{record.name}
      Biography: #{record.biography}
      """
    end)

    # When used_attributes are defined, embeddings will only be rebuilt when
    # the listed attributes are changed in an update action.
    used_attributes [:name, :biography]
  end

  strategy :after_action
  attributes(name: :vectorized_name, biography: :vectorized_biography)

  # See the section below on defining an embedding model
  embedding_model MyApp.OpenAiEmbeddingModel
end
```

If you are using policies, add a bypass to allow us to update the vector embeddings:

```elixir
bypass action(:ash_ai_update_embeddings) do
  authorize_if AshAi.Checks.ActorIsAshAi
end
```

## Vectorization strategies

Currently there are three strategies to choose from:

- `:after_action` (default) - The embeddings will be updated synchronously on after every create & update action.
- `:ash_oban` - Embeddings will be updated asynchronously through an `ash_oban`-trigger when a record is created and updated.
- `:manual` - The embeddings will not be automatically updated in any way.

### `:after_action`

Will add a global change on the resource, that will run a generated action named `:ash_ai_update_embeddings`
on every update that requires the embeddings to be rebuilt. The `:ash_ai_update_embeddings`-action will be run in the `after_transaction`-phase of any create action and update action that requires the embeddings to be rebuilt.

This will make your app incredibly slow, and is not recommended for any real production usage.

### `:ash_oban`

Requires the `ash_oban`-dependency to be installed, and that the resource in question uses it as an extension, like this:

```elixir
defmodule MyApp.Artist do
  use Ash.Resource, extensions: [AshAi, AshOban]
end
```

Just like the `:after_action`-strategy, this strategy creates an `:ash_ai_update_embeddings` update-action, and adds a global change that will run an `ash_oban`-trigger (also in the `after_transaction`-phase) whenever embeddings need to be rebuilt.

You will have to define this trigger yourself, and then reference it in the `vectorize`-section like this:

```elixir
defmodule MyApp.Artist do
  use Ash.Resource, extensions: [AshAi, AshOban]

  vectorize do
    full_text do
      ...
    end

    strategy :ash_oban
    ash_oban_trigger_name :my_vectorize_trigger (default name is :ash_ai_update_embeddings)
    ...
  end

  oban do
    triggers do
      trigger :my_vectorize_trigger do
        action :ash_ai_update_embeddings
        queue :artist_vectorizer
        worker_read_action :read
        worker_module_name __MODULE__.AshOban.Worker.UpdateEmbeddings
        scheduler_module_name __MODULE__.AshOban.Scheduler.UpdateEmbeddings
        scheduler_cron false # change this to a cron expression if you want to rerun the embedding at specified intervals
        list_tenants MyApp.ListTenants
      end
    end
  end
end
```

You'll also need to create the queue in the Oban config by changing your `config.exs` file.
```elixir
config :my_app, Oban,
  engine: Oban.Engines.Basic,
  notifier: Oban.Notifiers.Postgres,
  queues: [
    default: 10,
    chat_responses: [limit: 10],
    conversations: [limit: 10],
    artist_vectorizer: [limit: 20], #set the limit of concurrent workers
  ],
  repo: MyApp.Repo,
  plugins: [{Oban.Plugins.Cron, []}]
```

The queue defaults to the resources short name plus the name of the trigger. (if you didn't set it through the queue option on the trigger).

### `:manual`

Will not automatically update the embeddings in any way, but will by default generated an update action
named `:ash_ai_update_embeddings` that can be run on demand. If needed, you can also disable the
generation of this action like this:

```elixir
vectorize do
  full_text do
    ...
  end

  strategy :manual
  define_update_action_for_manual_strategy? false
  ...
end
```

### Embedding Models

Embedding models are modules that are in charge of defining what the dimensions
are of a given vector and how to generate one. This example uses `Req` to
generate embeddings using `OpenAi`. To use it, you'd need to install `req`
(`mix igniter.install req`).

```elixir
defmodule Tunez.OpenAIEmbeddingModel do
  use AshAi.EmbeddingModel

  @impl true
  def dimensions(_opts), do: 3072

  @impl true
  def generate(texts, _opts) do
    api_key = System.fetch_env!("OPEN_AI_API_KEY")

    headers = [
      {"Authorization", "Bearer #{api_key}"},
      {"Content-Type", "application/json"}
    ]

    body = %{
      "input" => texts,
      "model" => "text-embedding-3-large"
    }

    response =
      Req.post!("https://api.openai.com/v1/embeddings",
        json: body,
        headers: headers
      )

    case response.status do
      200 ->
        response.body["data"]
        |> Enum.map(fn %{"embedding" => embedding} -> embedding end)
        |> then(&{:ok, &1})

      _status ->
        {:error, response.body}
    end
  end
end
```

Opts can be used to make embedding models that are dynamic depending on the resource, i.e

```elixir
embedding_model {MyApp.OpenAiEmbeddingModel, model: "a-specific-model"}
```

Those opts are available in the `_opts` argument to functions on your embedding model

## Using the vectors

You can use expressions in filters and sorts like `vector_cosine_distance(full_text_vector, ^search_vector)`. For example:

```elixir
read :search do
  argument :query, :string, allow_nil?: false

  prepare before_action(fn query, context ->
    case YourEmbeddingModel.generate([query.arguments.query], []) do
      {:ok, [search_vector]} ->
        Ash.Query.filter(
          query,
          vector_cosine_distance(full_text_vector, ^search_vector) < 0.5
        )
        |> Ash.Query.sort(
          {calc(vector_cosine_distance(full_text_vector, ^search_vector),
             type: :float
           ), :asc}
        )
        |> Ash.Query.limit(10)

      {:error, error} ->
        {:error, error}
    end
  end)
end
```

## Building a Vector Index

If your database stores more than ~10,000 vectors, you may see search performance degrade. You can ameliorate this by building an index on the vector column. Vector indices come at the expense of write speeds and higher resource usage. 

The below example uses an `hnsw` index, which trades higher memory usage and vector build times for faster query speeds. An `ivfflat` index will have different settings, faster build times, lower memory usage, but slower query speeds. Do research and consider the tradeoffs for your use case. 

```elixir
  postgres do
    table "embeddings"
    repo MyApp.Repo

    custom_statements do
      statement :vector_idx do
        up "CREATE INDEX vector_idx ON embeddings USING hnsw (vectorized_body vector_cosine_ops) WITH (m = 16, ef_construction = 64)"
        down "DROP INDEX vector_idx;"
      end
    end
  end
```


# Roadmap

- more action types, like:
  - bulk updates
  - bulk destroys
  - bulk creates.

# How to play with it

1. Setup `ReqLLM` keys (see above)
2. Use `AshAi.ToolLoop.run/2` or `AshAi.iex_chat/1`
3. Run `iex -S mix` and then run `AshAi.iex_chat(otp_app: :my_app)` to chat with your app
4. Build your own chat interface around `AshAi.ToolLoop`

## Contributing 

1. make sure to run `mix test.create && mix test.migrate` to set up locally
1. ensure that `mix check` passes

## Using AshAi.iex_chat

```elixir
defmodule MyApp.ChatBot do
  def iex_chat(actor \\ nil) do
    AshAi.iex_chat(
      actor: actor,
      otp_app: :my_app,
      model: "openai:gpt-4o"
    )
  end
end
```
