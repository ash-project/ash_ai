# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

if Code.ensure_loaded?(Plug) and Code.ensure_loaded?(Req) do
  defmodule AshAi.Mcp.OAuth.ClientMetadataPlug do
    @moduledoc """
    Serves the Client ID Metadata Document from
    `AshAi.Mcp.OAuth.client_metadata_document/1`.

    Mount it at the URL you pass as `:client_metadata_url`. It takes the same
    options as `AshAi.Mcp.OAuth`, given directly, as `{module, function, args}`,
    or as a zero-arity function, so they can be read at runtime:

        forward "/oauth/client-metadata.json", AshAi.Mcp.OAuth.ClientMetadataPlug,
          {MyApp.Mcp, :oauth_options, []}
    """

    @behaviour Plug

    @impl Plug
    def init(opts), do: opts

    @impl Plug
    def call(conn, opts) do
      opts = resolve(opts)

      # Without a `:client_metadata_url` (for example in development, when the
      # application isn't served over HTTPS) there is no document to serve
      if opts[:client_metadata_url] do
        body = opts |> AshAi.Mcp.OAuth.client_metadata_document() |> Jason.encode!()

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.put_resp_header("cache-control", "public, max-age=3600")
        |> Plug.Conn.send_resp(200, body)
        |> Plug.Conn.halt()
      else
        conn
        |> Plug.Conn.send_resp(404, "")
        |> Plug.Conn.halt()
      end
    end

    defp resolve({module, function, args}), do: apply(module, function, args)
    defp resolve(fun) when is_function(fun, 0), do: fun.()
    defp resolve(opts) when is_list(opts), do: opts
  end
end
