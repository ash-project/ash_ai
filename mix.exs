defmodule AshAi.MixProject do
  use Mix.Project

  @description """
  Integrated LLM features for your Ash application.
  """

  @version "0.1.0"

  @source_url "https://github.com/ash-project/ash_ai"

  def project do
    [
      app: :ash_ai,
      version: @version,
      elixir: "~> 1.17",
      elixirc_paths: elixirc_paths(Mix.env()),
      package: package(),
      consolidate_protocols: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      aliases: aliases(),
      deps: deps(),
      docs: &docs/0,
      dialyzer: [plt_add_apps: [:ash, :mix]],
      description: @description,
      source_url: @source_url,
      homepage_url: @source_url,
      preferred_cli_env: [
        "test.create": :test,
        "test.migrate": :test,
        "test.rollback": :test,
        "test.migrate_tenants": :test,
        "test.check_migrations": :test,
        "test.drop": :test,
        "test.generate_migrations": :test,
        "test.reset": :test,
        "test.full_reset": :test
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger],
      mod: {AshAi.Application, []}
    ]
  end

  defp docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      logo: "logos/small-logo.png",
      extra_section: "GUIDES",
      before_closing_head_tag: fn type ->
        if type == :html do
          """
          <script>
            if (location.hostname === "hexdocs.pm") {
              var script = document.createElement("script");
              script.src = "https://plausible.io/js/script.js";
              script.setAttribute("defer", "defer")
              script.setAttribute("data-domain", "ashhexdocs")
              document.head.appendChild(script);
            }
          </script>
          """
        end
      end,
      extras: [
        {"README.md", title: "Home"},
        {"documentation/dsls/DSL-AshAi.md", search_data: Spark.Docs.search_data_for(AshAi)},
        "documentation/topics/mcp.md"
        # "CHANGELOG.md"
      ],
      groups_for_extras: [
        Tutorials: ~r'documentation/tutorials',
        "How To": ~r'documentation/how_to',
        Topics: ~r'documentation/topics',
        DSLs: ~r'documentation/dsls',
        "About AshGraphql": [
          "CHANGELOG.md"
        ]
      ],
      groups_for_modules: [
        AshGraphql: [
          AshGraphql
        ],
        Introspection: [
          AshGraphql.Resource.Info,
          AshGraphql.Domain.Info,
          AshGraphql.Resource,
          AshGraphql.Domain,
          AshGraphql.Resource.Action,
          AshGraphql.Resource.ManagedRelationship,
          AshGraphql.Resource.Mutation,
          AshGraphql.Resource.Query
        ],
        Errors: [
          AshGraphql.Error,
          AshGraphql.Errors
        ],
        Miscellaneous: [
          AshGraphql.Resource.Helpers
        ],
        Utilities: [
          AshGraphql.ContextHelpers,
          AshGraphql.DefaultErrorHandler,
          AshGraphql.Plug,
          AshGraphql.Subscription,
          AshGraphql.Type,
          AshGraphql.Types.JSON,
          AshGraphql.Types.JSONString
        ]
      ]
    ]
  end

  defp elixirc_paths(:test) do
    ["test/support/", "lib/"]
  end

  defp elixirc_paths(_env) do
    ["lib/"]
  end

  defp package do
    [
      name: :ash_ai,
      licenses: ["MIT"],
      maintainers: "Zach Daniel",
      files: ~w(lib .formatter.exs mix.exs README* LICENSE*
      CHANGELOG* documentation),
      links: %{
        "GitHub" => @source_url,
        "Discord" => "https://discord.gg/HTHRaaVPUc",
        "Website" => "https://ash-hq.org",
        "Forum" => "https://elixirforum.com/c/ash-framework-forum/",
        "Changelog" => "#{@source_url}/blob/main/CHANGELOG.md"
      }
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:ash, ash_version("~> 3.5 and >= 3.5.5")},
      {:ash_json_api, "~> 1.4 and >= 1.4.27"},
      {:open_api_spex, "~> 3.0"},
      {:langchain, "~> 0.3"},
      {:ash_postgres, "~> 2.5", optional: true},
      {:ash_oban, "~> 0.4.3", optional: true},
      {:ash_phoenix, "~> 2.0", optional: true},
      {:igniter, "~> 0.5", optional: true},
      {:plug, "~> 1.17", optional: true},
      # dev/test deps
      {:phx_new, "~> 1.7", optional: true},
      {:ex_doc, "~> 0.37-rc", only: [:dev, :test], runtime: false},
      {:ex_check, "~> 0.12", only: [:dev, :test]},
      {:credo, ">= 0.0.0", only: [:dev, :test], runtime: false},
      {:dialyxir, ">= 0.0.0", only: [:dev, :test], runtime: false},
      {:sobelow, ">= 0.0.0", only: [:dev, :test], runtime: false},
      {:git_ops, "~> 2.5", only: [:dev, :test]},
      {:mix_test_watch, "~> 1.0", only: :dev, runtime: false},
      {:simple_sat, ">= 0.0.0", only: :test},
      {:mix_audit, ">= 0.0.0", only: [:dev, :test], runtime: false}
    ]
  end

  defp aliases do
    [
      "spark.formatter": "spark.formatter --extensions AshAi",
      sobelow: "sobelow --skip",
      credo: "credo --strict",
      docs: [
        "spark.cheat_sheets",
        "docs",
        "spark.replace_doc_links"
      ],
      "spark.cheat_sheets": "spark.cheat_sheets --extensions AshAi",
      "test.generate_migrations": "ash_postgres.generate_migrations",
      "test.check_migrations": "ash_postgres.generate_migrations --check",
      "test.migrate_tenants": "ash_postgres.migrate --tenants",
      "test.migrate": "ash_postgres.migrate",
      "test.rollback": "ash_postgres.rollback",
      "test.create": "ash_postgres.create",
      "test.full_reset": ["test.generate_migrations", "test.reset"],
      "test.reset": ["test.drop", "test.create", "test.migrate", "ash_postgres.migrate --tenants"],
      "test.drop": "ash_postgres.drop"
    ]
  end

  defp ash_version(default_version) do
    case System.get_env("ASH_VERSION") do
      nil -> default_version
      "local" -> [path: "../ash", override: true]
      "main" -> [git: "https://github.com/ash-project/ash.git", override: true]
      version -> "~> #{version}"
    end
  end
end
