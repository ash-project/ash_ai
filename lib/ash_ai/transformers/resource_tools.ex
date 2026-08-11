# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Transformers.ResourceTools do
  @moduledoc false
  use Spark.Dsl.Transformer

  alias Spark.Dsl.Transformer

  def after?(_), do: true

  def transform(dsl_state) do
    module = Transformer.get_persisted(dsl_state, :module)
    resource_dsl? = resource_dsl?(module)

    dsl_state
    |> Transformer.get_entities([:tools])
    |> Enum.reduce(dsl_state, fn tool, dsl ->
      cond do
        resource_dsl? and is_nil(tool.resource) ->
          Transformer.replace_entity(
            dsl,
            [:tools],
            %{tool | resource: module},
            &(&1.name == tool.name)
          )

        resource_dsl? ->
          raise Spark.Error.DslError,
            module: module,
            path: [:tools, tool.name, :resource],
            message: """
            Resource-level tools cannot set `resource`.

            Inside an Ash.Resource, define tools as `tool :name, :action`.
            """

        is_nil(tool.resource) ->
          raise Spark.Error.DslError,
            module: module,
            path: [:tools, tool.name, :resource],
            message: """
            Tool `#{tool.name}` is missing a resource.

            On domains, define tools as `tool :name, Resource, :action`.
            """

        true ->
          dsl
      end
    end)
    |> validate_tools!(module, resource_dsl?)
    |> then(&{:ok, &1})
  end

  defp validate_tools!(dsl_state, module, resource_dsl?) do
    dsl_state
    |> Transformer.get_entities([:tools])
    |> Enum.each(&validate_get_by!(&1, dsl_state, module, resource_dsl?))

    dsl_state
  end

  defp validate_get_by!(%{get_by: nil}, _dsl_state, _module, _resource_dsl?), do: :ok

  defp validate_get_by!(tool, dsl_state, module, resource_dsl?) do
    case fetch_action(tool, dsl_state, resource_dsl?) do
      :deferred ->
        :ok

      nil ->
        raise Spark.Error.DslError,
          module: module,
          path: [:tools, tool.name, :action],
          message:
            "Tool `#{tool.name}` references action `#{tool.action}`, but no such action exists."

      %{type: :read} ->
        validate_get_by_fields!(tool, dsl_state, module, resource_dsl?)

      _action ->
        raise_get_by_error!(tool, module, "`get_by` can only be used with read tools.")
    end
  end

  # Domain-level tools reference other modules, which may not be compiled yet. Those are
  # skipped here; the same checks run again when the tool's schema is built.
  defp fetch_action(tool, dsl_state, true) do
    Ash.Resource.Info.action(dsl_state, tool.action)
  end

  defp fetch_action(tool, _dsl_state, false) do
    case Code.ensure_loaded(tool.resource) do
      {:module, resource} ->
        if Ash.Resource.Info.resource?(resource) do
          Ash.Resource.Info.action(resource, tool.action)
        end

      {:error, _reason} ->
        :deferred
    end
  end

  defp validate_get_by_fields!(tool, dsl_state, module, resource_dsl?) do
    source = if resource_dsl?, do: dsl_state, else: tool.resource

    tool.get_by
    |> List.wrap()
    |> Enum.each(fn field_name ->
      case AshAi.Tool.validate_get_by_field(source, field_name) do
        {:ok, _field} -> :ok
        {:error, message} -> raise_get_by_error!(tool, module, message)
      end
    end)
  end

  defp raise_get_by_error!(tool, module, message) do
    raise Spark.Error.DslError,
      module: module,
      path: [:tools, tool.name, :get_by],
      message: message
  end

  defp resource_dsl?(module) do
    Module.get_attribute(module, :spark_is) == Ash.Resource
  end
end
