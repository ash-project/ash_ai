defmodule AshAi.Mcp.Resources do
  @moduledoc """
  MCP Resources capability for AshAi.

  This capability integrates Ash resources with the MCP protocol,
  delegating to the AshMcp framework for core functionality.
  """

  if Code.ensure_loaded?(AshMcp) do
    @behaviour AshMcp.Capability

    require Logger

    @impl AshMcp.Capability
    def capability_name, do: "resources"

    @impl AshMcp.Capability
    def capability_config do
      %{
        "listChanged" => false
      }
    end

    @impl AshMcp.Capability
    def list_items(_session_id, opts) do
      resources = get_ash_resources(opts)

      resource_list =
        Enum.map(resources, fn {domain, resource} ->
          %{
            "uri" => "ash://#{inspect(domain)}/#{inspect(resource)}",
            "name" => inspect(resource),
            "description" => get_resource_description(resource),
            "mimeType" => "application/json"
          }
        end)

      {:ok, resource_list}
    end

    @impl AshMcp.Capability
    def handle_method("resources/list", _params, session_id, opts) do
      {:ok, resources} = list_items(session_id, opts)
      {:ok, %{"resources" => resources}}
    end

    def handle_method("resources/read", params, _session_id, opts) do
      uri = params["uri"]

      case parse_ash_uri(uri) do
        {:ok, {domain, resource}} ->
          case read_ash_resource(domain, resource, opts) do
            {:ok, data} ->
              {:ok, %{
                "contents" => [%{
                  "uri" => uri,
                  "mimeType" => "application/json",
                  "text" => Jason.encode!(data, pretty: true)
                }]
              }}

            {:error, error} ->
              {:error, {:resource_read_failed, error}}
          end

        {:error, error} ->
          {:error, {:invalid_uri, error}}
      end
    end

    def handle_method(_method, _params, _session_id, _opts) do
      :not_handled
    end

    # Private functions

    defp get_ash_resources(opts) do
      if opts[:otp_app] do
        case Application.get_env(opts[:otp_app], :ash_domains) do
          nil -> []
          domains ->
            Enum.flat_map(domains, fn domain ->
              case Ash.Domain.Info.resources(domain) do
                [] -> []
                resources -> Enum.map(resources, &{domain, &1})
              end
            end)
        end
      else
        []
      end
    end

    defp get_resource_description(resource) do
      case Ash.Resource.Info.description(resource) do
        nil -> "Ash resource: #{inspect(resource)}"
        description -> description
      end
    end

    defp parse_ash_uri("ash://" <> rest) do
      case String.split(rest, "/", parts: 2) do
        [domain_str, resource_str] ->
          try do
            domain = String.to_existing_atom(domain_str)
            resource = String.to_existing_atom(resource_str)
            {:ok, {domain, resource}}
          rescue
            ArgumentError ->
              {:error, :invalid_module_name}
          end

        _ ->
          {:error, :invalid_format}
      end
    end

    defp parse_ash_uri(_), do: {:error, :invalid_scheme}

    defp read_ash_resource(domain, resource, opts) do
      try do
        query = resource |> Ash.Query.new() |> Ash.Query.limit(100)

        context = build_ash_context(opts)

        case Ash.read(query, [domain: domain, authorize?: false] ++ context) do
          {:ok, records} ->
            {:ok, %{
              "resource" => inspect(resource),
              "domain" => inspect(domain),
              "count" => length(records),
              "records" => Enum.map(records, &serialize_ash_record/1)
            }}

          {:error, error} ->
            {:error, error}
        end
      rescue
        error ->
          {:error, error}
      end
    end

    defp build_ash_context(opts) do
      []
      |> maybe_add(:actor, opts[:actor])
      |> maybe_add(:tenant, opts[:tenant])
    end

    defp maybe_add(list, _key, nil), do: list
    defp maybe_add(list, key, value), do: [{key, value} | list]

    defp serialize_ash_record(record) when is_struct(record) do
      record
      |> Map.from_struct()
      |> Enum.reduce(%{}, fn {key, value}, acc ->
        Map.put(acc, to_string(key), serialize_value(value))
      end)
    end

    defp serialize_value(value) when is_struct(value, DateTime), do: DateTime.to_iso8601(value)
    defp serialize_value(value) when is_struct(value, Date), do: Date.to_iso8601(value)
    defp serialize_value(value) when is_struct(value, Time), do: Time.to_iso8601(value)
    defp serialize_value(value) when is_struct(value), do: inspect(value)
    defp serialize_value(value), do: value
  else
    def capability_name, do: "resources"
    def capability_config, do: %{}
    def list_items(_session_id, _opts), do: {:ok, []}
    def handle_method(_method, _params, _session_id, _opts), do: :not_handled
  end
end
