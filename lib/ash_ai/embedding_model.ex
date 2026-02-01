# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.EmbeddingModel do
  @moduledoc """
  A behaviour that defines the dimensions of the vector, and how to generate the embedding
  """

  @type opts :: Keyword.t()

  @doc "The dimensions of generated embeddings"
  @callback dimensions(opts) :: pos_integer()
  @doc "Generate embeddings for the given list of strings"
  @callback generate([String.t()], opts) :: {:ok, [binary()]} | {:error, term()}

  defmacro __using__(_) do
    quote do
      @behaviour AshAi.EmbeddingModel
    end
  end
end
