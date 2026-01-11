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

Create a module that implements the `AshAi.EmbeddingModel` behaviour to generate embeddings:

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

### Using Tools in LangChain

Add your Ash AI tools to a LangChain chain:

```elixir
chain =
  %{
    llm: LangChain.ChatModels.ChatOpenAI.new!(%{model: "gpt-4o"}),
    verbose: true
  }
  |> LangChain.Chains.LLMChain.new!()
  |> AshAi.setup_ash_ai(otp_app: :my_app, tools: [:list, :of, :tools])
```

## Structured Outputs (Prompt-Backed Actions)

Create actions that use LLMs for their implementation:

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

  run prompt(
    LangChain.ChatModels.ChatOpenAI.new!(%{model: "gpt-4o"}),
    # Allow the model to use tools
    tools: true,
    # Or restrict to specific tools
    # tools: [:list, :of, :tool, :names],
    # Optionally provide a custom prompt template
    # prompt: "Analyze the sentiment of the following text: <%= @input.arguments.text %>"
  )
end
```

### Structured Outputs with Custom Types

The action's return type provides the JSON schema automatically. For complex structured outputs, you can use any Ash type, including `Ash.TypedStruct`:

```elixir
# Example using Ash.TypedStruct
defmodule JobListing do
  use Ash.TypedStruct

  typed_struct do
    field :title, :string, allow_nil?: false
    field :company, :string, allow_nil?: false
    field :location, :string
    field :salary_range, :string
    field :requirements, {:array, :string}
  end
end

# Use it as the return type for your action
action :parse_raw, JobListing do
  argument :raw_content, :string, allow_nil?: false

  run prompt(
    fn _input, _context ->
      LangChain.ChatModels.ChatOpenAI.new!(%{
        model: "gpt-4o-mini",
        api_key: System.get_env("OPENAI_API_KEY"),
        temperature: 0.1
      })
    end,
    prompt: """
    Parse this job listing into structured data following the exact schema.
    Extract all available information and return as JSON:

    <%= @input.arguments.raw_content %>
    """,
    tools: false
  )
end
```

### Dynamic LLM Configuration

For runtime configuration (like environment variables), use a function to define the LLM:

```elixir
action :analyze_sentiment, :atom do
  argument :text, :string, allow_nil?: false

  run prompt(
    fn _input, _context ->
      LangChain.ChatModels.ChatOpenAI.new!(%{
        model: "gpt-4o",
        # this can also be configured in application config, see langchain docs for more.
        api_key: System.get_env("OPENAI_API_KEY"),
        endpoint: System.get_env("OPENAI_ENDPOINT")
      })
    end,
    tools: false
  )
end
```

The function receives:
1. `input` - The action input
2. `context` - The execution context

### Prompt Format Options

The `prompt` option supports multiple formats for maximum flexibility:

#### 1. String (EEx Template)
Simple string templates with access to `@input` and `@context`:

```elixir
run prompt(
  ChatOpenAI.new!(%{model: "gpt-4o"}),
  prompt: "Analyze the sentiment of: <%= @input.arguments.text %>"
)
```

#### 2. System/User Tuple
Separate system and user messages (both support EEx templates):

```elixir
run prompt(
  ChatOpenAI.new!(%{model: "gpt-4o"}),
  prompt: {"You are a sentiment analyzer", "Analyze: <%= @input.arguments.text %>"}
)
```

#### 3. LangChain Messages List
For complex multi-turn conversations or image analysis:

```elixir
run prompt(
  ChatOpenAI.new!(%{model: "gpt-4o"}),
  prompt: [
    Message.new_system!("You are an expert assistant"),
    Message.new_user!("Hello, how can you help me?"),
    Message.new_assistant!("I can help with various tasks"),
    Message.new_user!("Great! Please analyze this data")
  ]
)
```

For image analysis with templates:

```elixir
run prompt(
  ChatOpenAI.new!(%{model: "gpt-4o"}),
  prompt: [
    Message.new_system!("You are an expert at image analysis"),
    Message.new_user!([
      PromptTemplate.from_template!("Extra context: <%= @input.arguments.context %>"),
      ContentPart.image!("<%= @input.arguments.image_data %>", media: :jpg, detail: "low")
    ])
  ]
)
```

#### 4. Dynamic Function
Return any of the above formats dynamically based on input:

```elixir
run prompt(
  ChatOpenAI.new!(%{model: "gpt-4o"}),
  prompt: fn input, context ->
    base = [Message.new_system!("You are helpful")]

    history = input.arguments.conversation_history
    |> Enum.map(fn %{"role" => role, "content" => content} ->
      case role do
        "user" -> Message.new_user!(content)
        "assistant" -> Message.new_assistant!(content)
      end
    end)

    base ++ history
  end
)
```

#### Template Processing

- **String prompts**: Processed as EEx templates with `@input` and `@context` variables
- **Messages with PromptTemplate**: Processed using LangChain's `apply_prompt_templates`
- **Functions**: Can return any supported format for dynamic generation

If no custom prompt is provided, a default template is used that includes the action name, description, and argument details.

### Adapters

Adapters control how the LLM is called to generate structured outputs. AshAi automatically selects the appropriate adapter based on your LLM, but you can override this with the `:adapter` option.

#### Default Adapter Selection

- **OpenAI API endpoints**: Uses `AshAi.Actions.Prompt.Adapter.StructuredOutput` (leverages OpenAI's structured output features)
- **Non-OpenAI endpoints**: Uses `AshAi.Actions.Prompt.Adapter.RequestJson` (requests JSON in the prompt)
- **Anthropic**: Uses `AshAi.Actions.Prompt.Adapter.CompletionTool` (uses tool calling for structured outputs)

#### Custom Adapter Configuration

You can specify a custom adapter or adapter options:

```elixir
# Use a specific adapter
run prompt(
  ChatOpenAI.new!(%{model: "gpt-4o"}),
  adapter: AshAi.Actions.Prompt.Adapter.RequestJson,
  tools: false
)

# Use an adapter with custom options
run prompt(
  ChatOpenAI.new!(%{model: "gpt-4o"}),
  adapter: {AshAi.Actions.Prompt.Adapter.StructuredOutput, [some_option: :value]},
  tools: false
)
```

#### Available Adapters

- **`StructuredOutput`**: Best for OpenAI models, uses native structured output capabilities
- **`RequestJson`**: Works with any model, requests JSON format in the prompt
- **`CompletionTool`**: Uses tool calling to generate structured outputs, good for models that support function calling

### Best Practices for Prompt-Backed Actions

- Write clear, detailed descriptions for the action and its arguments
- Use constraints when appropriate to restrict outputs
- Choose the appropriate prompt format for your use case:
  - Simple string templates for basic prompts
  - System/user tuples for role-based interactions
  - Message lists for complex conversations or multi-modal inputs
  - Functions for dynamic prompt generation
- Test thoroughly with different inputs to ensure reliable results

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
- For prompt-backed actions, consider using deterministic test models
- Verify tool access and permissions work as expected
