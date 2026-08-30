# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Test.EmbeddingModel do
  @moduledoc false
  use AshAi.EmbeddingModel

  @impl true
  def dimensions(_opts), do: 1536

  @impl true
  def generate(texts, _opts) do
    if Enum.any?(texts, &(is_binary(&1) and String.contains?(&1, "FORCE_EMBED_ERROR"))) do
      # Mimics a provider HTTP client error whose inspected form carries the
      # outbound Authorization header, request URL, and provider response body.
      {:error,
       %{
         request: %{
           url: "https://provider.example/v1/embeddings",
           headers: [{"authorization", "Bearer sk-live-SECRET-2726"}]
         },
         response: %{status: 500, body: "provider internal detail req_int_7fa1"}
       }}
    else
      {:ok, Enum.map(texts, fn _ -> Enum.map(1..1536, fn _ -> 0.5 end) end)}
    end
  end
end
