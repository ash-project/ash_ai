# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.Client.Connection do
  @moduledoc """
  A server and the protocol details `AshAi.Mcp.Client.connect/1` settled on.

  * `era` is `:modern` for revisions that carry their version on every request
    (2026-07-28 on) and `:legacy` for the `initialize`-based revisions.
  * `session_id` is the legacy `Mcp-Session-Id`, or `nil`.
  * `server_info`, `capabilities`, and `instructions` come from `server/discover`
    or `initialize`, when the client made one of those requests.

  Holds no process or socket; Req pools the HTTP connections underneath.
  """

  # A session id lets whoever holds it act in the session
  @derive {Inspect, except: [:session_id]}
  defstruct [
    :server,
    :protocol_version,
    :era,
    :session_id,
    :server_info,
    :instructions,
    capabilities: %{},
    supported_versions: []
  ]

  @type t :: %__MODULE__{
          server: AshAi.Mcp.Client.Server.t(),
          protocol_version: String.t(),
          era: :modern | :legacy,
          session_id: String.t() | nil,
          server_info: map() | nil,
          instructions: String.t() | nil,
          capabilities: map(),
          supported_versions: [String.t()]
        }
end
