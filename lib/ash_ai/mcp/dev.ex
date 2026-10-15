# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.Dev do
  @moduledoc """
  Place in your endpoint's code_reloading section to expose Ash dev MCP"

  Default path is `/ash_ai/mcp`

  ## Options

    * `:otp_app` - your application.
    * `:path` - where the server is mounted. Defaults to `/ash_ai/mcp`.
    * `:dev_tool_domains` - a list of Ash domains that use the `AshAi` extension. The tools
      declared in their `tools do` sections are served alongside AshAi's own dev tools.
      Defaults to `[]`.
  """
  @behaviour Plug

  @impl true
  def init(opts) do
    path =
      opts
      |> Keyword.get(:path, "/ash_ai/mcp")
      |> String.split("/")
      |> Enum.reject(&(&1 == ""))

    dev_tool_domains =
      opts
      |> Keyword.get(:dev_tool_domains, [])
      |> validate_dev_tool_domains!()

    opts =
      opts
      |> Keyword.put(:tools, :ash_dev_tools)
      |> Keyword.put(:dev_tool_domains, dev_tool_domains)
      |> Keyword.put(:path, path)

    AshAi.Mcp.Router.init(opts)
  end

  @impl true
  def call(%Plug.Conn{path_info: path_info} = conn, opts) do
    expected_path = Keyword.get(opts, :path)

    case Enum.split(path_info, length(expected_path)) do
      {^expected_path, rest} ->
        conn
        |> Plug.forward(rest, AshAi.Mcp.Router, opts)
        |> Plug.Conn.halt()

      _ ->
        conn
    end
  end

  @doc false
  # The tool entries the dev server exposes: AshAi's own dev tools, then those
  # declared by each of the given domains and their resources.
  def dev_tools(dev_tool_domains) do
    Enum.flat_map([AshAi.DevTools | dev_tool_domains], fn domain ->
      AshAi.Info.tools(domain) ++
        Enum.flat_map(Ash.Domain.Info.resources(domain), &AshAi.Info.tools/1)
    end)
  end

  defp validate_dev_tool_domains!(domains) when is_list(domains) do
    domains =
      domains
      |> Enum.uniq()
      |> Enum.reject(&(&1 == AshAi.DevTools))

    Enum.each(domains, &validate_dev_tool_domain!/1)

    duplicates =
      domains
      |> dev_tools()
      |> Enum.frequencies_by(& &1.name)
      |> Enum.filter(fn {_name, count} -> count > 1 end)
      |> Enum.map(fn {name, _count} -> name end)
      |> Enum.sort()

    if duplicates != [] do
      raise ArgumentError,
            "`dev_tool_domains` declare tool names that are already in use on the dev MCP server: " <>
              Enum.map_join(duplicates, ", ", &inspect/1)
    end

    domains
  end

  defp validate_dev_tool_domains!(other) do
    raise ArgumentError,
          "`dev_tool_domains` must be a list of Ash domains, got: #{inspect(other)}"
  end

  defp validate_dev_tool_domain!(domain) do
    cond do
      !is_atom(domain) or !match?({:module, _}, Code.ensure_compiled(domain)) ->
        raise ArgumentError,
              "`dev_tool_domains` entry #{inspect(domain)} is not a loaded module"

      !Spark.Dsl.is?(domain, Ash.Domain) ->
        raise ArgumentError,
              "`dev_tool_domains` entry #{inspect(domain)} is not an Ash domain"

      AshAi not in Spark.extensions(domain) ->
        raise ArgumentError,
              "`dev_tool_domains` entry #{inspect(domain)} does not use the AshAi extension. " <>
                "Add `extensions: [AshAi]` to its `use Ash.Domain` and declare its tools in `tools do`."

      true ->
        :ok
    end
  end
end
