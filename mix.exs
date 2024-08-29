defmodule AshAi.MixProject do
  use Mix.Project

  def project do
    [
      app: :ash_ai,
      version: "0.1.0",
      elixir: "~> 1.17",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:openai_ex, "~> 0.8"},
      {:ash, "~> 3.0"},
      {:ash_json_api, github: "ash-project/ash_json_api"},
      {:open_api_spex, "~> 3.0"},
      {:igniter, "~> 0.3"}
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"}
    ]
  end
end
