<!--
SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>

SPDX-License-Identifier: MIT
-->

# LangChain to ReqLLM Migration Guide

This guide covers migrating an `ash_ai` app from the old LangChain-based runtime to the ReqLLM-based runtime.

## What Changed

- LangChain runtime integration was removed.
- LLM access now goes through ReqLLM.
- Tool orchestration now goes through `AshAi.ToolLoop`.
- Prompt-backed actions (`prompt/2`) now use ReqLLM model specifications.
- Generated chat code (`mix ash_ai.gen.chat`) now uses ReqLLM.

## Migration Checklist

1. Update dependencies (`:langchain` out, `:req_llm` in).
2. Move provider keys to `config :req_llm`.
3. Replace LangChain model structs with ReqLLM model specs.
4. Replace removed AshAi APIs with ReqLLM-first APIs.
5. Re-run chat generator if you use generated chat code.
6. Run format/tests/checks.

## 1) Update Dependencies

In `mix.exs`:

- Remove LangChain dependency.
- Add ReqLLM dependency:

```elixir
{:req_llm, "~> 1.7"}
```

Then fetch and resolve:

```bash
mix deps.get
```

## 2) Update Runtime Configuration

Configure provider keys under `:req_llm` in `config/runtime.exs`.

```elixir
config :req_llm,
  openai_api_key: System.get_env("OPENAI_API_KEY"),
  anthropic_api_key: System.get_env("ANTHROPIC_API_KEY"),
  google_api_key: System.get_env("GOOGLE_API_KEY")
```

Use only the providers your app needs.

## 3) Update Model Specifications

`prompt/2` and tool loops now use ReqLLM model specs.

- Before (LangChain struct-based setup):

```elixir
LangChain.ChatModels.ChatOpenAI.new!(%{model: "gpt-4o"})
```

- After (ReqLLM model spec):

```elixir
"openai:gpt-4o"
```

Model strings follow `"provider:model-name"` and can be browsed at https://llmdb.xyz.

## 4) Replace Removed APIs

| Old | New |
| --- | --- |
| `AshAi.setup_ash_ai/2` | `AshAi.ToolLoop.run/2` or `AshAi.ToolLoop.stream/2` |
| `AshAi.functions/1` | `AshAi.list_tools/1` or `AshAi.build_tools_and_registry/1` |
| `AshAi.iex_chat/2` | `AshAi.iex_chat/1` |

## 5) Update Prompt-Backed Actions

The `prompt/2` macro remains, but model input uses ReqLLM model specs.

```elixir
run prompt("openai:gpt-4o",
  prompt: "Summarize: <%= @input.arguments.text %>",
  tools: true
)
```

Supported model forms:

- String model spec (`"provider:model"`)
- ReqLLM tuple model forms
- Function returning one of the above

### Customizing Prompt Actions

For prompt-backed actions, the new customization boundary is:

- `tools:` filters AshAi-exposed tools.
- `extra_tools:` adds arbitrary `ReqLLM.Tool`s.
- `req_llm_opts:` passes provider/request options through to ReqLLM.
- `transform_flow:` is the preferred ReqLLM-native customization hook.

Before, custom tools were often attached by mutating the LangChain chain:

```elixir
run prompt(llm,
  tools: true,
  modify_chain: fn chain, _context ->
    chain
    |> LangChain.Chains.LLMChain.add_tools([my_custom_tool])
    |> LangChain.Chains.LLMChain.update_custom_context(%{trace_id: "abc"})
  end
)
```

Now, keep AshAi tools and arbitrary ReqLLM tools separate:

```elixir
run prompt("openai:gpt-4o",
  tools: true,
  extra_tools: [
    ReqLLM.Tool.new!(
      name: "lookup_weather",
      description: "Look up weather by city",
      parameter_schema: [city: [type: :string, required: true]],
      callback: fn %{"city" => city} -> {:ok, %{city: city, forecast: "sunny"}} end
    )
  ],
  req_llm_opts: [trace_id: "abc"]
)
```

If you used `modify_chain` for prompt customization before, now express those changes directly against `transform_flow`:

```elixir
run prompt("openai:gpt-4o",
  tools: [],
  transform_flow: fn flow_state, _context ->
    %{
      flow_state
      | extra_tools: flow_state.extra_tools ++ [my_custom_tool],
        req_llm_opts: Keyword.put(flow_state.req_llm_opts, :trace_id, "abc")
    }
  end
)
```

## 6) Update Embeddings (If Used)

Use `AshAi.EmbeddingModels.ReqLLM` with explicit `model` and `dimensions`.

```elixir
vectorize do
  embedding_model {AshAi.EmbeddingModels.ReqLLM,
    model: "openai:text-embedding-3-small",
    dimensions: 1536
  }
end
```

## 7) Regenerate Chat Code (If Used)

If your app uses generated chat files, re-run:

```bash
mix ash_ai.gen.chat --live
```

or your existing generator flags. The generated code now uses ReqLLM and `AshAi.ToolLoop`.

## 8) Validate the Migration

Run:

```bash
mix format
mix test
mix check
```

Optional sanity check:

```bash
rg -n "LangChain|langchain" lib test config
```

## Legacy Compatibility Notes

- `verbose?` on prompt-backed actions is supported and logs tool-loop lifecycle events when set to `true`.
- Prompt-backed actions default to `max_iterations: :infinity` for tool loops; set an integer to enforce limits.
- Tool-loop failures in prompt-backed actions are returned as action errors (instead of runtime raises), including the loop reason.
- Unconstrained `:map` prompt return types use a permissive schema (`type: object`) to avoid over-constraining map keys.

### Legacy Adapter Mapping

The old LangChain-era adapter concepts map to ReqLLM-era behavior as follows:
- `StructuredOutput` -> `ReqLLM.generate_object/4` with schema-derived typed action returns.
- `CompletionTool` -> `AshAi.ToolLoop.run/2` or `AshAi.ToolLoop.stream/2` tool-calling orchestration.
- `RequestJson` -> prompt templates/messages + typed return schema casting in `prompt/2`.
- `Raw` -> use non-structured text generation directly via ReqLLM in custom code paths when typed action returns are not desired.

When migrating old `modify_chain` usage, move that customization into `transform_flow`, `tools:`, `extra_tools:`, and `req_llm_opts:` directly.

### Embedding Return Shape

`AshAi.EmbeddingModels.ReqLLM.generate/2` returns:
- `{:ok, embeddings}` on success
- `{:error, reason}` on failure

## Common Issues

- Missing API key errors:
  Add the matching `:req_llm` key or environment variable for your selected provider.
- Provider schema compatibility:
  If a provider rejects strict tool schemas, set `strict: false` in tool loop or prompt tool options.
