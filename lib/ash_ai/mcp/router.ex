if Code.ensure_loaded?(Plug) do
  defmodule AshAi.Mcp.Router do
    @moduledoc """
    MCP Router for AshAi applications.

    This router provides a simplified interface to AshMcp.Router with
    Ash-specific defaults and capabilities.

    ## Usage

    ```elixir
    # Basic usage without authentication
    forward "/mcp", AshAi.Mcp.Router, tools: [:tool1, :tool2], otp_app: :my_app

    # With OAuth authentication (requires AshAuthentication)
    forward "/mcp", AshAi.Mcp.Router,
      tools: [:tool1, :tool2],
      otp_app: :my_app,
      auth_enabled?: true,
      auth_strategies: [:github, :google],
      require_auth?: false
    ```
    """

    use Plug.Router, copy_opts_to_assign: :router_opts

    plug(:match)
    plug(:dispatch)

    match _ do
      # Use AshMcp.Router with Ash-specific options
      opts = build_ash_mcp_opts(conn.assigns.router_opts)

      if Code.ensure_loaded?(AshMcp.Router) do
        AshMcp.Router.call(conn, AshMcp.Router.init(opts))
      else
        send_resp(conn, 503, "MCP functionality requires ash_mcp dependency")
      end
    end

    # Build options with Ash-specific defaults
    defp build_ash_mcp_opts(opts) do
      base_capabilities = [
        AshAi.Mcp.Tools,
        AshAi.Mcp.Resources
      ]

      additional_capabilities = opts[:capabilities] || []

      opts
      |> Keyword.put(:capabilities, base_capabilities ++ additional_capabilities)
      |> Keyword.put_new(:server_name, "AshAi MCP Server")
      |> Keyword.put_new(:server_version, get_ash_ai_version())
      |> Keyword.put_new(:protocol_version, "2025-03-26")
    end

    defp get_ash_ai_version do
      case Application.spec(:ash_ai, :vsn) do
        nil -> "0.1.0"
        version -> List.to_string(version)
      end
    end
  end
end
