# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.EmbeddingModels.ReqLLMTestHelper do
  @moduledoc false
  use AshAi.EmbeddingModel

  @default_max_batch_size 100

  @impl true
  def dimensions(opts) do
    Keyword.fetch!(opts, :dimensions)
  end

  @impl true
  def generate(texts, opts) do
    model = Keyword.fetch!(opts, :model)
    req_opts = Keyword.get(opts, :req_opts, [])
    max_batch_size = Keyword.get(opts, :max_batch_size, @default_max_batch_size)

    inputs = Enum.map(texts, &(&1 || ""))

    chunks = Enum.chunk_every(inputs, max_batch_size)

    chunks
    |> Enum.reduce_while({:ok, []}, fn chunk, {:ok, acc} ->
      case call_reqllm(model, chunk, req_opts) do
        {:ok, embeddings} -> {:cont, {:ok, acc ++ embeddings}}
        {:error, error} -> {:halt, {:error, error}}
      end
    end)
  end

  defp call_reqllm(model, inputs, req_opts) do
    mock_fn = Process.get(:reqllm_embed_mock)

    if mock_fn do
      case mock_fn.(model, inputs, req_opts) do
        {:ok, embeddings} when is_list(embeddings) ->
          {:ok, embeddings}

        {:error, error} ->
          {:error, error}

        other ->
          {:error, "Unexpected response from ReqLLM.embed/2: #{inspect(other)}"}
      end
    else
      {:error, "No mock configured for ReqLLM.embed/2"}
    end
  end
end

defmodule AshAi.EmbeddingModels.ReqLLMTest do
  use ExUnit.Case, async: true

  alias AshAi.EmbeddingModels.ReqLLM

  describe "dimensions/1" do
    test "returns configured dimensions" do
      assert 1536 = ReqLLM.dimensions(dimensions: 1536)
      assert 3072 = ReqLLM.dimensions(dimensions: 3072)
    end

    test "raises when dimensions not configured" do
      assert_raise KeyError, fn ->
        ReqLLM.dimensions([])
      end
    end
  end

  describe "generate/2" do
    test "raises when model not configured" do
      assert_raise KeyError, fn ->
        ReqLLM.generate(["hello"], dimensions: 1536)
      end
    end

    test "normalizes nil values to empty strings" do
      test_pid = self()

      opts = [
        model: "openai:text-embedding-3-small",
        dimensions: 3
      ]

      {:ok, _embeddings} =
        generate_with_mock(["hello", nil, "world"], opts, fn _model, inputs, _opts ->
          send(test_pid, {:inputs, inputs})
          {:ok, Enum.map(inputs, fn _ -> [0.1, 0.2, 0.3] end)}
        end)

      assert_received {:inputs, inputs}
      assert inputs == ["hello", "", "world"]
    end

    test "chunks large batches" do
      test_pid = self()
      call_count = :counters.new(1, [:atomics])

      opts = [
        model: "openai:text-embedding-3-small",
        dimensions: 3,
        max_batch_size: 2
      ]

      inputs = ["one", "two", "three", "four", "five"]

      {:ok, embeddings} =
        generate_with_mock(inputs, opts, fn _model, chunk, _opts ->
          :counters.add(call_count, 1, 1)
          send(test_pid, {:chunk, chunk})
          {:ok, Enum.map(chunk, fn _ -> [0.1, 0.2, 0.3] end)}
        end)

      assert :counters.get(call_count, 1) == 3
      assert length(embeddings) == 5

      assert_received {:chunk, ["one", "two"]}
      assert_received {:chunk, ["three", "four"]}
      assert_received {:chunk, ["five"]}
    end

    test "handles ReqLLM errors" do
      opts = [
        model: "openai:text-embedding-3-small",
        dimensions: 3
      ]

      {:error, error} =
        generate_with_mock(["hello"], opts, fn _model, _inputs, _opts ->
          {:error, "API rate limit exceeded"}
        end)

      assert error == "API rate limit exceeded"
    end

    test "handles unexpected responses" do
      opts = [
        model: "openai:text-embedding-3-small",
        dimensions: 3
      ]

      {:error, error} =
        generate_with_mock(["hello"], opts, fn _model, _inputs, _opts ->
          :unexpected
        end)

      assert error =~ "Unexpected response from ReqLLM.embed/2"
    end

    test "passes req_opts to ReqLLM" do
      test_pid = self()

      opts = [
        model: "openai:text-embedding-3-small",
        dimensions: 3,
        req_opts: [api_key: "test-key", base_url: "https://custom.api.com"]
      ]

      {:ok, _embeddings} =
        generate_with_mock(["hello"], opts, fn _model, _inputs, req_opts ->
          send(test_pid, {:req_opts, req_opts})
          {:ok, [[0.1, 0.2, 0.3]]}
        end)

      assert_received {:req_opts, req_opts}
      assert req_opts[:api_key] == "test-key"
      assert req_opts[:base_url] == "https://custom.api.com"
    end

    test "returns embeddings in correct order" do
      opts = [
        model: "openai:text-embedding-3-small",
        dimensions: 3,
        max_batch_size: 2
      ]

      {:ok, embeddings} =
        generate_with_mock(["a", "b", "c"], opts, fn _model, chunk, _opts ->
          embeddings =
            Enum.map(chunk, fn text ->
              case text do
                "a" -> [1.0, 1.0, 1.0]
                "b" -> [2.0, 2.0, 2.0]
                "c" -> [3.0, 3.0, 3.0]
              end
            end)

          {:ok, embeddings}
        end)

      assert embeddings == [[1.0, 1.0, 1.0], [2.0, 2.0, 2.0], [3.0, 3.0, 3.0]]
    end
  end

  defp generate_with_mock(texts, opts, mock_fn) do
    Process.put(:reqllm_embed_mock, mock_fn)

    try do
      AshAi.EmbeddingModels.ReqLLMTestHelper.generate(texts, opts)
    after
      Process.delete(:reqllm_embed_mock)
    end
  end
end
