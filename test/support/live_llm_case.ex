# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.LiveLLMCase do
  @moduledoc """
  Shared test case for live LLM integration tests.

  These tests make real API calls to LLM providers and require valid API keys.

  ## Running Tests

      # Run all live LLM tests
      mix test --only live_llm

      # Run only OpenAI tests
      mix test --only live_llm:openai

      # Run only Anthropic tests
      mix test --only live_llm:anthropic

  ## Environment Variables

  Set these environment variables before running tests:

      export OPENAI_API_KEY="sk-..."
      export ANTHROPIC_API_KEY="sk-ant-..."

  Or create a `.env` file and source it.
  """

  use ExUnit.CaseTemplate

  @openai_model "openai:gpt-4o-mini"
  @anthropic_model "anthropic:claude-3-5-haiku-latest"
  @openai_embedding_model "openai:text-embedding-3-small"
  @embedding_dimensions 1536

  using do
    quote do
      import AshAi.LiveLLMCase

      @openai_model unquote(@openai_model)
      @anthropic_model unquote(@anthropic_model)
      @openai_embedding_model unquote(@openai_embedding_model)
      @embedding_dimensions unquote(@embedding_dimensions)
    end
  end

  @doc """
  Returns the OpenAI model identifier for tests.
  """
  def openai_model, do: @openai_model

  @doc """
  Returns the Anthropic model identifier for tests.
  """
  def anthropic_model, do: @anthropic_model

  @doc """
  Returns the OpenAI embedding model identifier for tests.
  """
  def openai_embedding_model, do: @openai_embedding_model

  @doc """
  Returns the expected embedding dimensions.
  """
  def embedding_dimensions, do: @embedding_dimensions

  @doc """
  Checks if the OpenAI API key is configured.
  """
  def openai_configured? do
    case System.get_env("OPENAI_API_KEY") do
      nil -> false
      "" -> false
      _ -> true
    end
  end

  @doc """
  Checks if the Anthropic API key is configured.
  """
  def anthropic_configured? do
    case System.get_env("ANTHROPIC_API_KEY") do
      nil -> false
      "" -> false
      _ -> true
    end
  end

  @doc """
  Asserts that the required provider is configured.

  Call at the beginning of each test that requires API access.
  Raises an assertion error with a clear message if the API key is not set.
  """
  defmacro require_provider!(provider) do
    quote do
      case unquote(provider) do
        :openai ->
          unless AshAi.LiveLLMCase.openai_configured?() do
            flunk("OPENAI_API_KEY environment variable not set - cannot run live LLM test")
          end

        :anthropic ->
          unless AshAi.LiveLLMCase.anthropic_configured?() do
            flunk("ANTHROPIC_API_KEY environment variable not set - cannot run live LLM test")
          end
      end
    end
  end
end
