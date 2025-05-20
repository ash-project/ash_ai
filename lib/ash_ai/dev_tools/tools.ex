defmodule AshAi.DevTools.Tools do
  @moduledoc false
  use Ash.Resource, domain: AshAi.DevTools

  defmodule Task do
    @moduledoc false
    use Ash.Type.NewType,
      subtype_of: :map,
      constraints: [
        fields: [
          command: [type: :string, allow_nil?: false, description: "The command to run"],
          docs: [type: :string, allow_nil?: false, description: "The documentation for the task"]
        ]
      ]
  end

  defmodule Resource do
    @moduledoc false
    use Ash.Type.NewType,
      subtype_of: :map,
      constraints: [
        fields: [
          name: [type: :string, allow_nil?: false, description: "The name of the resource module"],
          domain: [
            type: :string,
            allow_nil?: false,
            description: "The name of the resource's domain module"
          ]
        ]
      ]
  end

  actions do
    action :list_ash_resources, {:array, Resource} do
      description """
      Lists Ash resources and their domains.
      """

      run fn input, _ ->
        Ash.Info.domains_and_resources(input.context.otp_app)
        |> Enum.flat_map(fn {domain, resources} ->
          Enum.map(resources, fn resource ->
            %{domain: inspect(domain), name: inspect(resource)}
          end)
        end)
        |> then(&{:ok, &1})
      end
    end

    action :list_generators, {:array, Task} do
      description """
      Lists available igniter generators. Run with `mix <task_name>`. Pass `--dry-run` to see what the effects will be. Always pass `--yes` when running to accept changes automatically
      """

      run fn input, _ ->
        Mix.Task.all_modules()
        |> Enum.filter(fn module ->
          function_exported?(module, :igniter, 1)
        end)
        |> Enum.map(fn module ->
          %{docs: Mix.Task.moduledoc(module), command: Mix.Task.task_name(module)}
        end)
        |> then(&{:ok, &1})
      end
    end
  end
end
