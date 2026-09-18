<!--
SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs.contributors>

SPDX-License-Identifier: MIT
-->

# Rules for working with Ash AI

## Understanding Ash AI

Ash AI is an extension for the Ash framework that integrates AI capabilities with Ash resources. It provides tools for vectorization, embedding generation, LLM interaction, and tooling for AI models.

## Core Concepts

- **Vectorization**: Convert text attributes into vector embeddings for semantic search
- **AI Tools**: Expose Ash actions as tools for LLMs
- **Prompt-backed Actions**: Create actions where the implementation is handled by an LLM
- **Evaluation Actions**: Ask typed questions of System One models such as TypeSafe's Jev
- **MCP Server**: Expose your tools to Machine Context Protocol clients

## Vectorization

Vectorization allows you to convert text data into embeddings that can be used for semantic search.

### Setting Up Vectorization

Add vectorization to a resource by including the `AshAi` extension and defining a vectorize block:

```elixir
defmodule MyApp.Artist do
  use Ash.Resource, extensions: [AshAi]

  vectorize do
    # For creating a single vector from multiple attributes
    full_text do
      text(fn record ->
        """
        Name: #{record.name}
        Biography: #{record.biography}
        """
      end)

      # Optional - only rebuild embeddings when these attributes change
      used_attributes [:name, :biography]
    end

    # Choose a strategy for updating embeddings
    strategy :ash_oban

    # Specify your embedding model implementation
    embedding_model MyApp.OpenAiEmbeddingModel
  end

  # Rest of resource definition...
end
```

### Embedding Models

Prefer the built-in ReqLLM embedding model, which works with any provider ReqLLM supports:

```elixir
vectorize do
  embedding_model {AshAi.EmbeddingModels.ReqLLM,
    model: "openai:text-embedding-3-small",
    dimensions: 1536}
end
```

`:model` and `:dimensions` are required; `:req_opts` passes provider options and
`:max_batch_size` (default 100) controls chunking. Provider keys come from the `:req_llm`
config, the same as for tools and prompt-backed actions.

To call a provider directly, implement the `AshAi.EmbeddingModel` behaviour yourself:

```elixir
defmodule MyApp.OpenAiEmbeddingModel do
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

### Vectorization Strategies

Choose the appropriate strategy based on your performance requirements:

1. **`:after_action`** (default): Updates embeddings synchronously after each create and update action
   - Simple but can make your app slow
   - Not recommended for production use with many records

2. **`:ash_oban`**: Updates embeddings asynchronously using Ash Oban
   - Requires `ash_oban` extension
   - Better for production use

3. **`:manual`**: No automatic updates; you control when embeddings are updated
   - Most flexible but requires you to manage when to update embeddings

### Using the Vectors for Search

Use vector expressions in filters and sorts:

```elixir
read :semantic_search do
  argument :query, :string, allow_nil?: false

  prepare before_action(fn query, context ->
    case MyApp.OpenAiEmbeddingModel.generate([query.arguments.query], []) do
      {:ok, [search_vector]} ->
        Ash.Query.filter(
          query,
          vector_cosine_distance(full_text_vector, ^search_vector) < 0.5
        )
        |> Ash.Query.sort([
          {
              calc(vector_cosine_distance(
                full_text_vector,
                ^search_vector
              )),
            :asc
          }
        ])

      {:error, error} ->
        {:error, error}
    end
  end)
end
```

### Authorization for Vectorization

If you're using policies, add a bypass to allow embedding updates:

```elixir
bypass action(:ash_ai_update_embeddings) do
  authorize_if AshAi.Checks.ActorIsAshAi
end
```

## AI Tools

Expose your Ash actions as tools for LLMs to use by configuring them in your domain:

```elixir
defmodule MyApp.Blog do
  use Ash.Domain, extensions: [AshAi]

  tools do
    tool :read_posts, MyApp.Blog.Post, :read do
      description "customize the tool description"
    end
    tool :create_post, MyApp.Blog.Post, :create
    tool :publish_post, MyApp.Blog.Post, :publish
    tool :read_comments, MyApp.Blog.Comment, :read
  end

  # Rest of domain definition...
end
```

### Tool Data Access Rules

Tools have different access levels for different operations:

1. **Filtering/Sorting/Aggregation**: Only attributes with `public?: true` can be used
2. **Arguments**: Only action arguments with `public?: true` are exposed to tools
3. **Response data**: Public attributes are returned by default
4. **Loading data**: The `load` option is used to include relationships, calculations, or additional attributes in responses (both public and private)

Example:

```elixir
# Resource definition
defmodule MyApp.Blog.Post do
  attributes do
    attribute :title, :string, public?: true
    attribute :content, :string, public?: true
    attribute :internal_notes, :string  # Default is public?: false
    attribute :view_count, :integer, public?: true
  end
  
  relationships do
    belongs_to :author, MyApp.Accounts.User, public?: true
  end
end

# Tool definition
tools do
  # Returns only public attributes (title, content, view_count)
  tool :read_posts, MyApp.Blog.Post, :read
  
  # Returns public attributes plus loaded fields (including private ones)
  tool :read_posts_with_all_details, MyApp.Blog.Post, :read do
    load [:author, :internal_notes]
  end
end
```

With this configuration:
- Tools can only filter/sort by `title`, `content`, and `view_count`
- `internal_notes` cannot be used for filtering, sorting, or aggregation
- `internal_notes` CAN be returned when explicitly loaded via the `load` option
- The `author` relationship can include both public and private attributes when loaded

This provides flexibility while maintaining control over data access:
- Private data is protected from queries and operations
- Private data can still be included in responses when explicitly loaded
- The `load` option serves dual purposes: loading relationships/calculations and making any loaded attributes visible (including private ones)

### Read Tool Results

List-style read tools (no `get_by`) mirror `Ash.read/2`:

- Action without pagination: returns a bare array of records, limited by `limit` (default 25) and `offset`. Note `defaults [:read]` creates a paginated action, so its tools return pages.
- Action with `pagination offset?: true`: returns `{"results": [...], "limit": n, "offset": n, "has_more": bool, "next_offset": n | null}`.
- Action with `pagination keyset?: true`: exposes `after`/`before` arguments instead of `offset` and returns `{"results": [...], "limit": n, "has_more": bool, "start_keyset": "...", "end_keyset": "..."}`. Pass `end_keyset` as `after` for the next page.
- `count` (total matching records) is only included when the action's pagination has `countable: :by_default`. Otherwise use `result_type: "count"`.
- To give an LLM pagination metadata, configure `pagination` on the read action. The raw result for paginated actions is an `Ash.Page.Offset` or `Ash.Page.Keyset` struct.
- Actions supporting both offset and keyset pagination (including `defaults [:read]`) use keyset by default; a positive `offset` switches to offset pagination for that call.
- `count`, `exists`, aggregate result types, and `get_by` tools return their value directly, never a page.

### Using Tools with an LLM (ReqLLM)

Ash AI is built on [ReqLLM](https://hexdocs.pm/req_llm). Models are referenced by
spec string, `"provider:model"`, for example `"openai:gpt-4o"` or
`"anthropic:claude-haiku-4-5"`. Provider keys are configured under `:req_llm`
in `runtime.exs`:

```elixir
config :req_llm, openai_api_key: System.fetch_env!("OPENAI_API_KEY")
config :req_llm, anthropic_api_key: System.fetch_env!("ANTHROPIC_API_KEY")
```

`AshAi.ToolLoop.run/2` runs the full model + tool loop and returns an
`AshAi.ToolLoop.Result` with `messages`, `final_text`, `iterations`, `tool_calls_made`,
and `usage`. `AshAi.ToolLoop.stream/2` does the same with streaming.

```elixir
messages = [ReqLLM.Context.user("List my recent posts")]

{:ok, %AshAi.ToolLoop.Result{final_text: text}} =
  AshAi.ToolLoop.run(messages,
    model: "openai:gpt-4o",
    otp_app: :my_app,          # discover tools from all domains in the app
    tools: [:read_posts],      # or `true` for every exposed tool
    actor: current_user,
    tenant: tenant,
    max_iterations: 10,
    on_tool_start: fn %AshAi.ToolStartEvent{} = event -> IO.inspect(event.tool_name) end,
    on_tool_end: fn %AshAi.ToolEndEvent{} = event -> IO.inspect(event.result) end
  )
```

Options to know:

- `otp_app:` or `actions: [{Resource, [:action]}]` decides where tools are discovered from.
- `tools:` is `true`, `false`, or a list of tool names.
- `extra_tools:` adds arbitrary `ReqLLM.Tool`s alongside Ash tools.
- `req_llm_opts:` passes provider options through (temperature, reasoning, and so on).
- `req_llm:` swaps in a module implementing the ReqLLM functions, for tests.
- `max_iterations:` defaults to 10 for the tool loop and `:infinity` for prompt actions.
- `strict:` (default `true`) emits OpenAI strict tool schemas; set `false` for providers that reject them.

To integrate with your own loop instead, `AshAi.build_tools_and_registry/1` returns
ReqLLM tools plus the execution callbacks. `AshAi.iex_chat/1` starts an interactive chat
in IEx for trying tools out.

## Structured Outputs (Prompt-Backed Actions)

Create actions whose implementation is an LLM call. The action's return type becomes the
JSON schema for structured output, and the default prompt is derived from the action
description and arguments. Requires the optional `req_llm` dependency.

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
    # Allow the model to use all exposed tools while answering
    tools: true,
    # Or restrict to specific tools
    # tools: [:list, :of, :tool, :names],
    # Optionally provide a custom prompt template
    # prompt: "Analyze the sentiment of the following text: <%= @input.arguments.text %>"
  )
end
```

### Structured Outputs with Custom Types

Any Ash type works as the return type, including `Ash.TypedStruct`, embedded resources,
and maps with `fields` constraints. Unconstrained `:map` returns use a permissive object
schema.

```elixir
defmodule JobListing do
  use Ash.TypedStruct

  typed_struct do
    field :title, :string, allow_nil?: false
    field :company, :string, allow_nil?: false
    field :location, :string
    field :requirements, {:array, :string}
  end
end

action :parse_raw, JobListing do
  argument :raw_content, :string, allow_nil?: false

  run prompt("openai:gpt-4o-mini",
    prompt: "Parse this job listing into structured data: <%= @input.arguments.raw_content %>",
    tools: false
  )
end
```

### Dynamic Model Configuration

The model can be a function of the input and context, for per-tenant or per-request models:

```elixir
run prompt(
  fn input, _context -> input.arguments.model || "openai:gpt-4o-mini" end,
  tools: false
)
```

Provider options such as temperature go through `req_llm_opts:`:

```elixir
run prompt("openai:gpt-4o", req_llm_opts: [temperature: 0.1], tools: false)
```

### Prompt Format Options

The `prompt` option accepts:

1. **String (EEx template)** with `@input` and `@context`:
   `prompt: "Analyze: <%= @input.arguments.text %>"`
2. **System/user tuple**, both templated:
   `prompt: {"You are a sentiment analyzer", "Analyze: <%= @input.arguments.text %>"}`
3. **`ReqLLM.Context`**, the canonical form:

   ```elixir
   import ReqLLM.Context

   prompt: fn input, _ctx ->
     ReqLLM.Context.new([
       system("You are an OCR expert"),
       user([
         ReqLLM.Message.ContentPart.text("Extract the text from this image"),
         ReqLLM.Message.ContentPart.image_url(input.arguments.image_url)
       ])
     ])
   end
   ```

4. **List of messages**: `ReqLLM.Message` structs or loose `%{role: "user", content: "..."}` maps.
   String content in statically configured lists is EEx-templated.
5. **Function** `fn input, context -> ... end` returning any of the above. Content returned
   from a function is used verbatim and is *not* EEx-evaluated, so user-supplied text is
   never compiled as a template.

Other prompt action options: `extra_tools:`, `max_iterations:`, `verbose?: true` for tool
loop debug logging, `req_llm:` to inject a fake module in tests, and `transform_flow:` to
customize the `AshAi.Actions.Prompt.FlowState` before the request.

Tool loop failures are returned as action errors rather than raised.

### Best Practices for Prompt-Backed Actions

- Write clear, detailed descriptions for the action and its arguments; they form the default prompt.
- Use constraints (`one_of`, `fields`, `min`/`max`) to narrow outputs.
- Keep prompts that include user input in a function, not a static EEx template.
- Set `max_iterations` when `tools:` is enabled so a looping model cannot run forever.

## Evaluation Actions (Jev and other System One models)

Evaluation models such as TypeSafe's Jev do not generate text. They take a `state` and a map
of typed questions and return one typed answer per question with probabilities and
confidence. Use `evaluate/2` instead of `prompt/2` for these models; `prompt/2` will fail
because the provider does not support object generation. Requires `req_llm >= 1.24` and
`TYPESAFE_API_KEY`.

The return type declares the questions and keeps the full answer:

- `AshAi.Evaluate.Choice` with `of: SomeEnum` (or `:atom` with `one_of`) asks one choice
  question and returns `value`, `probabilities`, and `confidence`. Enum value descriptions
  become the criteria.
- `AshAi.Evaluate.Noul` asks a yes/no question and returns only `probability`. Threshold in
  your code; the right threshold depends on the stakes.
- `AshAi.Evaluate.Score` with `levels: [...]` returns `value`, `level`, `probabilities`, and `confidence`.
- `AshAi.Evaluate.Judgments` asks several questions about the same state in one request. Fields
  typed as an enum or `:boolean` expand to Choice or Noul automatically.

The action arguments are sent as the state. The action description (single answer) or each
field's `description` (Judgments) is the question's instructions. Reference arguments with
backticked paths such as `` `ticket` ``.

```elixir
action :triage, AshAi.Evaluate.Judgments do
  argument :ticket, :string, allow_nil?: false

  constraints fields: [
    department: [type: MyApp.Department, description: "Which team should handle `ticket`?"],
    urgent: [type: :boolean, description: "Does `ticket` convey urgency?"],
    frustration: [
      type: AshAi.Evaluate.Score,
      constraints: [levels: ["Calm", "Frustrated but civil", "Very angry"]],
      description: "How frustrated is the customer in `ticket`?"
    ]
  ]

  run evaluate("typesafe:jev-latest")
end
```

Ask every question you might need in one Judgments action; extra questions are cheap and run
in parallel. Do not derive a Noul from a `:float` field; use `AshAi.Evaluate.Noul` explicitly.
Evaluation actions work as tools and MCP tools like any other generic action, and their
results serialize with probabilities and confidence intact.

### Dynamic questions

When the number of questions or their options depend on the input, return
`{:array, answer_type}` and supply the questions at runtime with the `questions:` option.
Each entry is instructions (a string, or a map/list for structured instructions) or a map
with `:instructions` and `:criteria`. Answers come back as a list in the same order.

```elixir
action :rerank, {:array, AshAi.Evaluate.Score} do
  argument :query, :string, allow_nil?: false
  argument :candidates, {:array, :string}, allow_nil?: false
  constraints items: [levels: ["Irrelevant", "Partially relevant", "Answers the query"]]

  run evaluate("typesafe:jev-latest",
    questions: fn input, _ctx ->
      input.arguments.candidates
      |> Enum.with_index()
      |> Enum.map(fn {_candidate, i} -> "How well does `candidates[#{i}]` answer `query`?" end)
    end
  )
end
```

Runtime `criteria` let options differ per question. A Choice with `of:` requires them to be a
subset of its options (hierarchical classification: offer only the children of the current
node). A Choice without `of:` returns string values. For `Judgments`, `questions:` returns a
map of field name to question and overrides only those fields' descriptions. For a single
answer type it overrides the action description.

## Model Context Protocol (MCP) Server

### Development MCP Server

For development environments, add the dev MCP server to your Phoenix endpoint:

```elixir
if code_reloading? do
  socket "/phoenix/live_reload/socket", Phoenix.LiveReloader.Socket

  plug AshAi.Mcp.Dev,
    protocol_version_statement: "2024-11-05",
    otp_app: :your_app

  plug Phoenix.LiveReloader
  plug Phoenix.CodeReloader
end
```

### Production MCP Server

For production environments, set up authentication and add the MCP router:

```elixir
# Add api_key strategy to your auth pipeline
pipeline :mcp do
  plug AshAuthentication.Strategy.ApiKey.Plug,
    resource: YourApp.Accounts.User,
    required?: false  # Set to true if all tools require authentication
end

# In your router
scope "/mcp" do
  pipe_through :mcp

  forward "/", AshAi.Mcp.Router,
    tools: [
      # List your tools here
      :read_posts,
      :create_post,
      :analyze_sentiment
    ],
    protocol_version_statement: "2024-11-05",
    otp_app: :my_app
end
```

## Testing

When testing AI components:
- Mock embedding model responses for consistent test results
- Test vector search with known embeddings
- For prompt-backed and evaluation actions, pass `req_llm: MyApp.FakeReqLLM` to inject a module that implements `generate_object/4`, `stream_text/3`, or `evaluate/4` and returns canned results
- Live LLM tests are tagged `:live_llm` and excluded by default
- Verify tool access and permissions work as expected
