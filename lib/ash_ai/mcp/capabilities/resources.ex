defmodule AshAi.Mcp.Capabilities.Resources do
  @moduledoc """
  MCP Resources capability implementation.

  This module handles the resources capability for the MCP server,
  allowing clients to discover and read Ash resources as structured data.
  """

  @behaviour AshAi.Mcp.Capability

  require Logger
  alias AshAi.Mcp.ResourceAdapter

  @impl AshAi.Mcp.Capability
  def capability_name, do: "resources"

  @impl AshAi.Mcp.Capability
  def capability_config do
    %{
      "subscribe" => false,
      "listChanged" => false
    }
  end

  @impl AshAi.Mcp.Capability
  def list_items(_session_id, opts) do
    ResourceAdapter.list_resources(opts)
  end

  @impl AshAi.Mcp.Capability
  def handle_method("resources/list", _params, session_id, opts) do
    case list_items(session_id, opts) do
      {:ok, resources} ->
        {:ok, %{"resources" => resources}}

      {:error, :otp_app_required} ->
        {:error, {:missing_configuration, "otp_app is required for resource discovery"}}

      {:error, {:discovery_failed, error}} ->
        Logger.warning("Resource discovery failed: #{inspect(error)}")
        {:error, {:discovery_failed, "Failed to discover Ash resources"}}
    end
  end

  def handle_method("resources/read", params, _session_id, opts) do
    uri = params["uri"]

    if is_nil(uri) do
      {:error, {:missing_parameter, "uri parameter is required"}}
    else
      case ResourceAdapter.get_resource_content(uri, opts) do
        {:ok, content} ->
          {:ok, content}

        {:error, :invalid_uri_scheme} ->
          {:error, {:invalid_uri, "URI must use ash:// scheme"}}

        {:error, :invalid_uri_format} ->
          {:error, {:invalid_uri, "URI format should be ash://Domain/Resource"}}
      end
    end
  end

  def handle_method(_method, _params, _session_id, _opts) do
    :not_handled
  end
end
