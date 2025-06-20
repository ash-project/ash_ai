defmodule AshMcp.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/your-org/ash_mcp"

  def project do
    [
      app: :ash_mcp,
      version: @version,
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      docs: docs(),
      aliases: aliases()
    ]
  end

  def application do
    [
      extra_applications: [:logger],
      mod: {AshMcp.Application, []}
    ]
  end

  defp deps do
    [
      # HTTP and JSON handling
      {:plug, "~> 1.15"},
      {:jason, "~> 1.4"},

      # Optional Phoenix integration
      {:phoenix, "~> 1.7", optional: true},

      # UUID generation
      {:ash, "~> 3.0", optional: true},

      # HTTP client for OAuth
      {:req, "~> 0.4", optional: true},

      # Development dependencies
      {:ex_doc, "~> 0.27", only: :dev, runtime: false},
      {:credo, "~> 1.6", only: [:dev, :test], runtime: false}
    ]
  end

  defp description do
    """
    A Model Context Protocol (MCP) server implementation for Elixir applications.
    Provides a framework for building MCP servers with support for tools, resources,
    prompts, and sampling capabilities.
    """
  end

  defp package do
    [
      name: "ash_mcp",
      files: ~w(lib .formatter.exs mix.exs README* LICENSE* CHANGELOG*),
      licenses: ["MIT"],
      links: %{"GitHub" => @source_url}
    ]
  end

  defp docs do
    [
      main: "readme",
      source_url: @source_url,
      source_ref: "v#{@version}",
      formatters: ["html"]
    ]
  end

  defp aliases do
    [
      setup: ["deps.get"],
      test: ["test"]
    ]
  end
end
