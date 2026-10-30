# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Tool.ResultMeta do
  @moduledoc """
  Computes per-call `_meta` for a tool's MCP `tools/call` result.

  Hosts hand a result's `_meta` to the tool's view (an MCP Apps `ui://`
  resource, or an OpenAI Apps SDK component) and keep it out of the model's
  context, so it is the place for data only the view needs: chart specs, row
  ids, pre-rendered labels. Set it with the `result_meta` tool option, as a
  module implementing this behaviour (or `{module, opts}`), or as a function
  taking the result and an `AshAi.Tool.ResultMeta.Context`:

      tools do
        tool :fund_development, MyApp.Reports.FundDevelopment, :development,
          ui: :charts,
          result_meta: &MyAppWeb.McpViews.fund_development/2
      end

      def fund_development(%Development{} = development, _context) do
        %{"com.example/charts" => [%{"title" => "Development", "spec" => vega_lite_spec(development)}]}
      end

  `result` is what the action returned, before serialization: a record or a
  list of records, an `Ash.Page.Offset` or `Ash.Page.Keyset` for a paginated
  read (a default `read` action is one), a count or aggregate value for a read
  called with a `result_type`, or a generic action's return value.

  Return a map, or `nil` to add nothing. Name its keys with a prefix you own,
  such as `"com.example/charts"`. The map is deep-merged over the tool's
  static `_meta`, winning on conflicts. `tools/list` is unaffected.

  The callback runs only after a successful call. If it raises, or returns
  anything other than `nil` or a JSON-encodable map, the error is logged and
  the result is sent without it: the action has already run, and an error
  result would invite the model to run it again.

  Only MCP `tools/call` results carry it; tool loops don't call it.
  """

  require Logger

  defmodule Context do
    @moduledoc """
    The context passed to an `AshAi.Tool.ResultMeta` callback.

      * `:tool` - the `%AshAi.Tool{}` that was called
      * `:arguments` - the call's arguments (string keys), after any
        `tool_argument_transformer`
      * `:actor`, `:tenant`, `:context` - what the action ran with
      * `:client_capabilities` - the capabilities the client declared on the
        request. Only the 2026-07-28 revision sends them with each request;
        `nil` on earlier revisions, where they are unknown here.
    """
    defstruct [:tool, :arguments, :actor, :tenant, :context, :client_capabilities]

    @type t :: %__MODULE__{
            tool: %AshAi.Tool{},
            arguments: map(),
            actor: term(),
            tenant: term(),
            context: map(),
            client_capabilities: map() | nil
          }
  end

  @doc "Returns the `_meta` entries for one call's result, or `nil` for none."
  @callback result_meta(result :: term(), opts :: Keyword.t(), context :: Context.t()) ::
              map() | nil

  defmacro __using__(_) do
    quote do
      @behaviour AshAi.Tool.ResultMeta
    end
  end

  @doc false
  # Returns the callback's map normalized to JSON (string keys, encoded
  # values) so it merges with the static `_meta` and can't break the
  # response, or `%{}` when the tool has none or the callback failed.
  def run(%AshAi.Tool{result_meta: nil}, _result, _context), do: %{}

  def run(%AshAi.Tool{result_meta: {module, opts}} = tool, result, %Context{} = context) do
    case module.result_meta(result, opts, context) do
      nil ->
        %{}

      meta when is_map(meta) and not is_struct(meta) ->
        normalize(tool, meta)

      other ->
        log_failure(tool, "must return a map or nil, got: #{inspect(other)}")
    end
  rescue
    error ->
      log_failure(tool, "raised:\n" <> Exception.format(:error, error, __STACKTRACE__))
  end

  defp normalize(tool, meta) do
    meta |> Jason.encode!() |> Jason.decode!()
  rescue
    error ->
      log_failure(tool, "returned a map that can't be JSON-encoded: " <> Exception.message(error))
  end

  defp log_failure(tool, message) do
    Logger.error(
      "result_meta for tool #{inspect(tool.name)} #{message}\nSending the result without it."
    )

    %{}
  end
end

defmodule AshAi.Tool.ResultMeta.Function do
  @moduledoc false
  use AshAi.Tool.ResultMeta

  @impl true
  def result_meta(result, [fun: {m, f, a}], context), do: apply(m, f, [result, context | a])
  def result_meta(result, [fun: fun], context), do: fun.(result, context)
end
