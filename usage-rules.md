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
        |> Ash.Query.sort(asc: vector_cosine_distance(full_text_vector, ^search_vector))

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

### Best Practices for Prompt-Backed Actions

- Write clear, detailed descriptions for the action and its arguments
- Use constraints when appropriate to restrict outputs
- Consider providing a custom prompt for more complex tasks
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
