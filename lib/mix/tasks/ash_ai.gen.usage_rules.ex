# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule Mix.Tasks.AshAi.Gen.UsageRules.Docs do
  @moduledoc false

  @spec example() :: String.t()
  def example do
    "mix ash_ai.gen.package_rules rules.md ash ash_postgres phoenix"
  end
end

if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.AshAi.Gen.UsageRules do
    @moduledoc false
    use Igniter.Mix.Task

    @impl Igniter.Mix.Task
    def info(_argv, _composing_task) do
      %Igniter.Mix.Task.Info{
        # Groups allow for overlapping arguments for tasks by the same author
        # See the generators guide for more.
        group: :ash_ai,
        example: __MODULE__.Docs.example(),
        positional: [
          :file,
          packages: [rest: true]
        ]
      }
    end

    @impl Igniter.Mix.Task
    def igniter(igniter) do
      packages =
        Mix.Project.deps_paths()
        |> Enum.filter(fn {name, _path} ->
          to_string(name) in igniter.args.positional.packages
        end)
        |> Enum.flat_map(fn {name, path} ->
          path
          |> Path.join("usage-rules.md")
          |> File.exists?()
          |> case do
            true ->
              [
                {name,
                 "<-- #{name}-start -->\n" <>
                   "## #{name} usage\n" <>
                   File.read!(Path.join(path, "usage-rules.md")) <>
                   "\n<-- #{name}-end -->"}
              ]

            false ->
              []
          end
        end)

      contents =
        "<-- package-rules-start -->\n" <>
          Enum.map_join(packages, "\n", &elem(&1, 1)) <> "\n<-- package-rules-end -->"

      Igniter.create_or_update_file(
        igniter,
        igniter.args.positional.file,
        contents,
        fn source ->
          current_contents = Rewrite.Source.get(source, :content)

          new_content =
            case String.split(current_contents, [
                   "<-- package-rules-start -->\n",
                   "\n<-- package-rules-end -->"
                 ]) do
              [prelude, current_packages_contents, postlude] ->
                Enum.reduce(packages, current_packages_contents, fn {name, package_contents},
                                                                    acc ->
                  case String.split(acc, [
                         "<-- #{name}-start -->\n",
                         "\n<-- #{name}-end -->"
                       ]) do
                    [prelude, _, postlude] ->
                      prelude <> package_contents <> postlude

                    _ ->
                      acc <> "\n" <> package_contents
                  end
                end)
                |> then(fn content ->
                  prelude <>
                    "<-- package-rules-start -->\n" <>
                    content <>
                    "\n<-- package-rules-end -->\n" <>
                    postlude
                end)

              _ ->
                current_contents <>
                  "\n<-- package-rules-start -->\n" <>
                  contents <>
                  "\n<-- package-rules-end -->\n"
            end

          Rewrite.Source.update(source, :content, new_content)
        end
      )
      |> Igniter.add_warning(
        "Deprecated: use `mix usage_rules.sync` instead of `ash_ai.gen.usage_rules`"
      )
    end
  end
else
  defmodule Mix.Tasks.AshAi.Gen.UsageRules do
    @moduledoc false
    use Mix.Task

    @impl Mix.Task
    def run(_argv) do
      Mix.shell().error("""
      The task 'ash_ai.gen.package_rules' requires igniter. Please install igniter and try again.

      For more information, see: https://hexdocs.pm/igniter/readme.html#installation
      """)

      exit({:shutdown, 1})
    end
  end
end
