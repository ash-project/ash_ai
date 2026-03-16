<!--
SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>

SPDX-License-Identifier: MIT
-->

# Live LLM Testing

AshAi includes a comprehensive suite of integration tests that make real API calls to LLM providers. These tests are excluded from the normal test run to avoid costs and API rate limits.

## Running Live LLM Tests

### Prerequisites

Set up your API keys as environment variables:

```bash
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."
```

Or create a `.env` file and source it before running tests.

### Test Commands

```bash
# Run all live LLM tests
mix test --only live_llm

# Run only OpenAI tests
mix test --only live_llm:openai

# Run only Anthropic tests
mix test --only live_llm:anthropic

# Run all tests including live LLM tests
mix test --include live_llm

# Run a specific live LLM test file
mix test test/live_llm/tool_calling_test.exs --include live_llm
```

## Test Coverage

### Tool Calling (`test/live_llm/tool_calling_test.exs`)

Tests the `AshAi.ToolLoop` module with real tool execution:

- Single tool calls (list items)
- Multi-turn conversations (create then list)
- Empty result handling
- `on_tool_start` and `on_tool_end` callbacks

### Structured Outputs (`test/live_llm/structured_output_test.exs`)

Tests the `prompt()` action implementation with typed returns:

- Enum return types (sentiment analysis)
- Integer extraction
- Embedded struct arrays (entity extraction)
- Constrained atoms (topic classification)
- String returns with function prompts

### Embeddings (`test/live_llm/embeddings_test.exs`)

Tests `AshAi.EmbeddingModels.ReqLLM`:

- Single text embedding
- Batch embedding
- Dimension verification
- Semantic similarity (similar texts have closer embeddings)
- Unicode and long text handling
- Batch chunking

### Streaming (`test/live_llm/streaming_test.exs`)

Tests `AshAi.ToolLoop.stream/2`:

- Content chunk streaming
- Tool call events
- Tool result events
- Iteration events for multi-turn
- Stream processing with `Enum.reduce`

## Models Used

| Provider | Chat Model | Embedding Model |
|----------|------------|-----------------|
| OpenAI | `gpt-4o-mini` | `text-embedding-3-small` |
| Anthropic | `claude-3-5-haiku-latest` | N/A |

These are chosen for their low cost and fast response times.

## Cost Estimates

Running the full live LLM test suite typically costs:

- **OpenAI**: ~$0.01-0.05 per full run
- **Anthropic**: ~$0.02-0.10 per full run

Costs vary based on response lengths and retry behavior.

## Writing New Live LLM Tests

Use the `AshAi.LiveLLMCase` test case module:

```elixir
defmodule AshAi.LiveLLM.MyFeatureTest do
  use AshAi.LiveLLMCase, async: true

  describe "OpenAI feature" do
    @tag :live_llm
    @tag live_llm: :openai
    test "my test" do
      require_provider!(:openai)
      
      # Test code using @openai_model
    end
  end

  describe "Anthropic feature" do
    @tag :live_llm
    @tag live_llm: :anthropic
    test "my test" do
      require_provider!(:anthropic)
      
      # Test code using @anthropic_model
    end
  end
end
```

### Available Module Attributes

- `@openai_model` - `"openai:gpt-4o-mini"`
- `@anthropic_model` - `"anthropic:claude-3-5-haiku-latest"`
- `@openai_embedding_model` - `"openai:text-embedding-3-small"`
- `@embedding_dimensions` - `1536`

### Helper Functions

- `require_provider!(:openai | :anthropic)` - Skips test if provider not configured
- `openai_configured?()` - Returns boolean
- `anthropic_configured?()` - Returns boolean

## CI/CD Considerations

Live LLM tests are excluded by default (`exclude: [:live_llm]` in `test_helper.exs`). For CI pipelines that need to run these tests:

1. Set the API key environment variables as secrets
2. Run with `--include live_llm` flag
3. Consider running only on specific branches or schedules to control costs

```yaml
# Example GitHub Actions step
- name: Run live LLM tests
  if: github.ref == 'refs/heads/main'
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
  run: mix test --only live_llm
```
