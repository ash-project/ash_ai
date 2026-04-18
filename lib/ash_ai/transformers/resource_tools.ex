# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Transformers.ResourceTools do
  @moduledoc false
  use Spark.Dsl.Transformer

  alias Spark.Dsl.Transformer

  def transform(dsl_state) do
    module = Transformer.get_persisted(dsl_state, :module)
    resource_dsl? = not is_nil(Ash.Resource.Info.data_layer(dsl_state))

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
    |> then(&{:ok, &1})
  end
end
