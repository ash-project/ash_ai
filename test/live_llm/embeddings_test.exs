# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.LiveLLM.EmbeddingsTest do
  @moduledoc """
  Live integration tests for embedding generation with real LLM providers.

  These tests verify that AshAi.EmbeddingModels.ReqLLM correctly:
  - Generates embeddings for text
  - Returns vectors with correct dimensions
  - Handles batch embedding requests
  """
  use AshAi.LiveLLMCase, async: true

  alias AshAi.EmbeddingModels.ReqLLM, as: ReqLLMEmbedding

  @embedding_opts [
    model: "openai:text-embedding-3-small",
    dimensions: 1536
  ]

  describe "OpenAI embeddings" do
    @tag :live_llm
    @tag live_llm: :openai
    test "generates embedding for single text" do
      require_provider!(:openai)

      {:ok, [embedding]} = ReqLLMEmbedding.generate(["Hello, world!"], @embedding_opts)

      assert is_list(embedding)
      assert length(embedding) == @embedding_dimensions
      assert Enum.all?(embedding, &is_float/1)
    end

    @tag :live_llm
    @tag live_llm: :openai
    test "generates embeddings for batch of texts" do
      require_provider!(:openai)

      texts = [
        "The quick brown fox",
        "jumps over the lazy dog",
        "Hello, AI world!"
      ]

      {:ok, embeddings} = ReqLLMEmbedding.generate(texts, @embedding_opts)

      assert length(embeddings) == 3

      Enum.each(embeddings, fn embedding ->
        assert is_list(embedding)
        assert length(embedding) == @embedding_dimensions
        assert Enum.all?(embedding, &is_float/1)
      end)
    end

    @tag :live_llm
    @tag live_llm: :openai
    test "embeddings have correct dimensions from config" do
      require_provider!(:openai)

      dimensions = ReqLLMEmbedding.dimensions(@embedding_opts)
      assert dimensions == @embedding_dimensions

      {:ok, [embedding]} = ReqLLMEmbedding.generate(["Test text"], @embedding_opts)
      assert length(embedding) == dimensions
    end

    @tag :live_llm
    @tag live_llm: :openai
    test "similar texts have similar embeddings" do
      require_provider!(:openai)

      texts = [
        "I love programming in Elixir",
        "Elixir programming is great",
        "The weather is sunny today"
      ]

      {:ok, [emb1, emb2, emb3]} = ReqLLMEmbedding.generate(texts, @embedding_opts)

      similarity_1_2 = cosine_similarity(emb1, emb2)
      similarity_1_3 = cosine_similarity(emb1, emb3)

      assert similarity_1_2 > similarity_1_3,
             "Similar texts should have higher cosine similarity (#{similarity_1_2} vs #{similarity_1_3})"
    end

    @tag :live_llm
    @tag live_llm: :openai
    test "handles whitespace-only string" do
      require_provider!(:openai)

      {:ok, [embedding]} = ReqLLMEmbedding.generate([" "], @embedding_opts)

      assert is_list(embedding)
      assert length(embedding) == @embedding_dimensions
    end

    @tag :live_llm
    @tag live_llm: :openai
    test "handles unicode text" do
      require_provider!(:openai)

      texts = [
        "Hello 世界",
        "Привет мир",
        "مرحبا بالعالم"
      ]

      {:ok, embeddings} = ReqLLMEmbedding.generate(texts, @embedding_opts)

      assert length(embeddings) == 3

      Enum.each(embeddings, fn embedding ->
        assert length(embedding) == @embedding_dimensions
      end)
    end

    @tag :live_llm
    @tag live_llm: :openai
    test "handles long text" do
      require_provider!(:openai)

      long_text = String.duplicate("This is a test sentence. ", 100)

      {:ok, [embedding]} = ReqLLMEmbedding.generate([long_text], @embedding_opts)

      assert is_list(embedding)
      assert length(embedding) == @embedding_dimensions
    end

    @tag :live_llm
    @tag live_llm: :openai
    test "batching works for large number of texts" do
      require_provider!(:openai)

      texts = for i <- 1..10, do: "Text number #{i}"

      {:ok, embeddings} =
        ReqLLMEmbedding.generate(texts, Keyword.put(@embedding_opts, :max_batch_size, 3))

      assert length(embeddings) == 10

      Enum.each(embeddings, fn embedding ->
        assert length(embedding) == @embedding_dimensions
      end)
    end
  end

  defp cosine_similarity(vec1, vec2) do
    dot_product = Enum.zip(vec1, vec2) |> Enum.map(fn {a, b} -> a * b end) |> Enum.sum()
    magnitude1 = :math.sqrt(Enum.map(vec1, &(&1 * &1)) |> Enum.sum())
    magnitude2 = :math.sqrt(Enum.map(vec2, &(&1 * &1)) |> Enum.sum())
    dot_product / (magnitude1 * magnitude2)
  end
end
