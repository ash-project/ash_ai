# Google Gemini Configuration
Steps to configure The generated Chat Server to work with Gemini


## Configuration
In `config/runtime.ex` replace:

```elixir
config :langchain, openai_key: fn -> System.fetch_env!("OPENAI_API_KEY") end
```

With:

```elixir
config :langchain,
  google_ai_key: fn -> System.get_env("GEMINI_API_KEY") end
```



## Chat Component

In 
- `lib/your_app/chat/message/changes/respond.ex` 
- `lib/your_app/chat/conversation/changes/generate_name.ex`


Replace:

```elixir
 alias LangChain.ChatModels.ChatOpenAI

 ....

 llm: ChatOpenAI.new!(%{model: "gpt-4o", stream: true}),


```
With:

```elixir
 alias LangChain.ChatModels.ChatGoogleAI

 ...

 llm: ChatGoogleAI.new!(%{model: "gemini-2.5-pro", stream: true}),

```


## Embeddings

create `lib/your_app/google_ai_embedding_model.ex`

```elixir
defmodule YourApp.GoogleAiEmbeddingModel do
  use AshAi.EmbeddingModel

  @impl true
  def dimensions(_opts), do: 3072

  @impl true
  def generate(texts, _opts) do
    parts = Enum.map(texts, fn t -> %{text: t} end)
    api_key = System.fetch_env!("GEMINI_API_KEY")

    headers = [
      {"x-goog-api-key", "#{api_key}"},
      {"Content-Type", "application/json"}
    ]

    body = %{
      "content" => %{parts: parts},
      "model" => "models/gemini-embedding-001"
    }

    response =
      Req.post!(
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-embedding-001:embedContent",
        json: body,
        headers: headers
      )

    case response.status do
      200 ->
        {:ok, [response.body["embedding"]["values"]]}

      _status ->
        {:error, response.body}
    end
  end
end
```

and in your `vectorize` block change:

```elixir
embedding_model Roboadvisor.OpenAiEmbeddingModel
```

with:

```elixir
embedding_model Roboadvisor.GoogleAiEmbeddingModel
```
