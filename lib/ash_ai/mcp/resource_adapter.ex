defmodule AshAi.Mcp.ResourceAdapter do
  @moduledoc """
  Adapter for converting Ash resources to MCP resource format.

  This module provides functions to introspect Ash resources and domains,
  converting them to the format expected by the MCP Resources capability.
  """

  @doc """
  Discovers all Ash resources in the application.
  """
  def discover_resources(opts \\ []) do
    otp_app = opts[:otp_app]

    case get_domains_and_resources(otp_app) do
      {:ok, domains_and_resources} ->
        resources =
          domains_and_resources
          |> Enum.flat_map(fn {domain, resources} ->
            Enum.map(resources, fn resource ->
              %{
                domain: domain,
                resource: resource,
                uri: build_resource_uri(domain, resource)
              }
            end)
          end)

        {:ok, resources}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Converts an Ash resource to MCP resource format.
  """
  def to_mcp_resource(domain, resource) do
    %{
      "uri" => build_resource_uri(domain, resource),
      "name" => resource_name(resource),
      "description" => resource_description(resource),
      "mimeType" => "application/json"
    }
  end

  @doc """
  Gets detailed information about a resource for MCP resource reading.
  """
  def get_resource_content(uri, _opts \\ []) do
    case parse_resource_uri(uri) do
      {:ok, {domain_name, resource_name}} ->
        # For now, return a simplified schema since we can't resolve the actual modules
        # from just the names without additional context
        content = %{
          "uri" => uri,
          "domain_name" => domain_name,
          "resource_name" => resource_name,
          "note" =>
            "Full resource schema requires access to the actual domain and resource modules"
        }

        {:ok,
         %{
           "contents" => [
             %{
               "uri" => uri,
               "mimeType" => "application/json",
               "text" => Jason.encode!(content, pretty: true)
             }
           ]
         }}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Lists resources with optional filtering.
  """
  def list_resources(opts \\ []) do
    case discover_resources(opts) do
      {:ok, discovered_resources} ->
        resources =
          discovered_resources
          |> Enum.map(fn %{domain: domain, resource: resource} ->
            to_mcp_resource(domain, resource)
          end)

        {:ok, resources}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Private functions

  defp get_domains_and_resources(nil) do
    {:error, :otp_app_required}
  end

  defp get_domains_and_resources(otp_app) do
    try do
      domains_and_resources = Ash.Info.domains_and_resources(otp_app)
      {:ok, domains_and_resources}
    rescue
      error ->
        {:error, {:discovery_failed, error}}
    end
  end

  defp build_resource_uri(domain, resource) do
    domain_name = domain |> Module.split() |> List.last()
    resource_name = resource |> Module.split() |> List.last()
    "ash://#{domain_name}/#{resource_name}"
  end

  defp parse_resource_uri("ash://" <> rest) do
    case String.split(rest, "/", parts: 2) do
      [domain_name, resource_name] ->
        # This is a simplified approach that just returns the string names
        # In a real implementation, you'd resolve these to actual modules
        {:ok, {domain_name, resource_name}}

      _ ->
        {:error, :invalid_uri_format}
    end
  end

  defp parse_resource_uri(_uri) do
    {:error, :invalid_uri_scheme}
  end

  defp resource_name(resource) do
    resource |> Module.split() |> List.last()
  end

  defp resource_description(resource) do
    try do
      case Ash.Resource.Info.description(resource) do
        description when is_binary(description) -> description
        _ -> "Ash resource: #{resource_name(resource)}"
      end
    rescue
      _ -> "Ash resource: #{resource_name(resource)}"
    end
  end
end
