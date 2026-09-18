# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Evaluate.Answer do
  @moduledoc """
  Behaviour for evaluation answer types.

  An answer type describes one question asked of an evaluation model (such as
  TypeSafe's Jev) and the typed answer that comes back, including the full
  probability distribution and confidence rather than only the collapsed value.

  Answer types are `Ash.Type.NewType`s over `Ash.Type.Struct`. Their custom
  constraints (for example `of:` or `levels:`) determine the struct's fields,
  which are derived in `init/1`.

  The built-in answer types are:

  - `AshAi.Evaluate.Choice` - one option from a defined set
  - `AshAi.Evaluate.Noul` - the probability that a yes/no question is true
  - `AshAi.Evaluate.Score` - a position along ordered, described levels

  Use `AshAi.Evaluate.Judgments` to ask several questions about the same state
  in one request.
  """

  @doc """
  Returns the struct fields for the answer, derived from the custom constraints.
  """
  @callback answer_fields(constraints :: Keyword.t()) :: {:ok, Keyword.t()} | {:error, term()}

  @doc """
  Builds the question sent to the evaluation model.
  """
  @callback to_question(instructions :: term(), constraints :: Keyword.t()) :: map()

  @doc """
  Converts the raw answer returned by the model into a map castable to the answer struct.
  """
  @callback from_answer(answer :: map(), constraints :: Keyword.t()) ::
              {:ok, map()} | {:error, term()}

  @doc "Returns true if the given type is an evaluation answer type."
  @spec answer_type?(Ash.Type.t()) :: boolean()
  def answer_type?({:array, _}), do: false

  def answer_type?(type) do
    type = Ash.Type.get_type(type)
    is_atom(type) and Spark.implements_behaviour?(type, __MODULE__)
  end

  @doc """
  Defines an answer type.

  `:constraints` is the `Spark.Options` schema of the type's custom constraints.
  The using module must implement the `AshAi.Evaluate.Answer` callbacks.
  """
  defmacro __using__(opts) do
    custom_schema = Keyword.fetch!(opts, :constraints)

    quote location: :keep do
      use Ash.Type.NewType, subtype_of: :struct

      @behaviour AshAi.Evaluate.Answer

      @custom_schema unquote(custom_schema)
      @custom_keys Keyword.keys(@custom_schema)

      @impl Ash.Type
      def constraints, do: super() ++ @custom_schema

      @impl Ash.Type
      def init(constraints) do
        with {:ok, custom} <-
               Spark.Options.validate(Keyword.take(constraints, @custom_keys), @custom_schema),
             {:ok, fields} <- answer_fields(custom) do
          super(Keyword.merge(constraints, fields: fields, instance_of: __MODULE__))
        end
      end
    end
  end
end
