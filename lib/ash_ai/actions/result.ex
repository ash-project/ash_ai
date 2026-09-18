# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Actions.Result do
  @moduledoc """
  Wraps the result of a prompt-backed or evaluation action with model metadata.

  By default those actions return only the value the model produced. Declare this
  type as the action's return type, with `of` naming the real return type, to also
  receive which model answered and what it cost. The action plans against the inner
  type exactly as it would without the wrapper.

  ## Fields

  - `result` - the value, cast to the `of` type
  - `model` - the model that answered, as reported by the provider (for example
    the versioned id behind a `jev-latest` alias)
  - `usage` - token usage as normalized by ReqLLM; for prompt actions this sums the
    tool loop iterations and the final generation
  - `provider_meta` - provider-specific response metadata

  ## Example

      action :triage, AshAi.Actions.Result do
        argument :ticket, :string, allow_nil?: false

        constraints of: AshAi.Evaluate.Judgments,
                    constraints: [
                      fields: [
                        urgent: [type: :boolean, description: "Does `ticket` convey urgency?"]
                      ]
                    ]

        run evaluate("typesafe:jev-latest")
      end

      %AshAi.Actions.Result{result: %{urgent: %AshAi.Evaluate.Noul{}}, model: "jev-1.13.0", usage: %{input_tokens: 312, ...}}

  For cross-cutting logging or cost accounting, prefer ReqLLM telemetry
  (`[:req_llm, :token_usage]` and `[:req_llm, :request, :stop]`) over changing
  return types.
  """

  defstruct [:result, :model, :usage, :provider_meta]

  @type t :: %__MODULE__{
          result: term(),
          model: String.t() | nil,
          usage: map() | nil,
          provider_meta: map() | nil
        }

  use Ash.Type.NewType, subtype_of: :struct

  @impl Ash.Type
  def constraints do
    super() ++
      [
        of: [type: :any, required: true, doc: "The return type being wrapped."],
        constraints: [type: :keyword_list, default: [], doc: "Constraints for the `of` type."]
      ]
  end

  @impl Ash.Type
  def init(constraints) do
    case Keyword.fetch(constraints, :of) do
      {:ok, of} when not is_nil(of) ->
        fields = [
          result: [type: of, constraints: constraints[:constraints] || []],
          model: [type: :string],
          usage: [type: :map],
          provider_meta: [type: :map]
        ]

        super(Keyword.merge(constraints, fields: fields, instance_of: __MODULE__))

      _ ->
        {:error, "#{inspect(__MODULE__)} requires the `of` constraint"}
    end
  end

  @doc """
  Returns the type an action actually produces: the `of` type when `returns` is
  this wrapper, otherwise `returns` itself.
  """
  @spec unwrap(Ash.Type.t() | nil, Keyword.t()) :: {Ash.Type.t() | nil, Keyword.t()}
  def unwrap(returns, constraints) do
    if wrapped?(returns) do
      result = constraints[:fields][:result] || []
      {result[:type], result[:constraints] || []}
    else
      {returns, constraints || []}
    end
  end

  @doc "Returns true if `returns` is this wrapper type."
  @spec wrapped?(Ash.Type.t() | nil) :: boolean()
  def wrapped?(nil), do: false
  def wrapped?({:array, _}), do: false
  def wrapped?(returns), do: Ash.Type.get_type(returns) == __MODULE__

  @doc """
  Builds the map to cast into this type from a result and a ReqLLM response (or
  any map with `model`, `usage`, and `provider_meta` keys). `usage` overrides the
  response's usage when given, for callers that sum several requests.
  """
  @spec wrap(term(), map() | nil, map() | nil) :: map()
  def wrap(result, response, usage \\ nil) do
    %{
      result: result,
      model: field(response, :model),
      usage: usage || field(response, :usage),
      provider_meta: field(response, :provider_meta)
    }
  end

  defp field(nil, _key), do: nil
  defp field(response, key) when is_map(response), do: Map.get(response, key)
  defp field(_response, _key), do: nil
end
