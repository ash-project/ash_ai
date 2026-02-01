# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

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

  defmodule UsageRules do
    @moduledoc false
    use Ash.Type.NewType,
      subtype_of: :map,
      constraints: [
        fields: [
          package: [type: :string, allow_nil?: false, description: "The name of the package"],
          sub_rule: [
            type: :string,
            description: "The name of the sub-rule within the package"
          ],
          package_description: [
            type: :string,
            allow_nil?: false,
            description: "The description of the package"
          ],
          file_path: [
            type: :string,
            allow_nil?: false,
            description: "The path to the file containing the usage rules"
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

    action :get_usage_rules, {:array, UsageRules} do
      description """
      Lists the usage rules for the provided packages.
      Use this to discover how packages are intended to be used.
      Not all packages have rules, but when they do they are stored in a `usage-rules.md` file.
      """

      run fn input, _ ->
        Mix.Project.deps_paths()
        |> Enum.flat_map(fn {name, path} ->
          path = Path.relative_to_cwd(path)

          description =
            if name == :usage_rules do
              "general usage rules"
            else
              case Application.spec(name, :description) do
                nil -> ""
                desc -> to_string(desc)
              end
            end

          usage_rules =
            path
            |> Path.join("usage-rules.md")
            |> File.exists?()
            |> case do
              true ->
                [
                  %{
                    package: to_string(name),
                    package_description: description,
                    file_path: Path.join(path, "usage-rules.md")
                  }
                ]

              false ->
                []
            end

          path
          |> Path.join("usage-rules/*.md")
          |> Path.wildcard()
          |> Enum.map(fn path ->
            sub_rule =
              Path.basename(path, ".md")

            %{
              package: to_string(name),
              sub_rule: sub_rule,
              package_description: description,
              file_path: path
            }
          end)
          |> then(&Enum.concat(usage_rules, &1))
        end)
        |> then(&{:ok, &1})
      end
    end

    action :list_generators, {:array, Task} do
      description """
      Lists available igniter generators. Run with `mix <task_name>`. Pass `--dry-run` to see what the effects will be. Always pass `--yes` when running to accept changes automatically
      """

      run fn input, _ ->
        Mix.Task.load_all()
        |> Enum.filter(fn module ->
          Code.ensure_loaded?(module) && function_exported?(module, :igniter, 1)
        end)
        |> Enum.map(fn module ->
          %{docs: Mix.Task.moduledoc(module), command: Mix.Task.task_name(module)}
        end)
        |> then(&{:ok, &1})
      end
    end
  end
end
