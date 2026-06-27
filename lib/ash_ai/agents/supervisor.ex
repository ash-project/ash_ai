# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Agents.Supervisor do
  @moduledoc """
  Top-level supervisor for the agent runtime. Add this to your app's
  supervision tree:

      children = [
        # ...
        {AshAi.Agents.Supervisor, data_dir: "data/ekv/agents"}
      ]

  Wires up:

    * `:ekv` — BEAM-native cluster-replicated KV store, locally durable via
      SQLite at `data_dir`. Used by DurableServer for cluster registry +
      heartbeats.
    * `DurableServer.Supervisor` — registered as
      `AshAi.Agents.DurableSup` (the underlying registry/supervisor that
      `AshAi.Agents` operates against).

  ## Options

    * `:data_dir` — local filesystem path for the SQLite-backed ekv store.
      Required. Each node should have its own (cluster replication is over the
      BEAM, not via shared filesystem).
    * `:cluster_size` — number of voting EKV members in the cluster. Defaults
      to `1` (single-node). Set to your cluster's voting-member count for
      multi-node deployments. Required for CAS quorum which DurableServer uses.
    * `:prefix` — DurableServer storage prefix, defaults to `"ash_ai_agents/"`.
  """
  use Supervisor

  @ekv_name :ash_ai_agents_ekv
  @default_prefix "ash_ai_agents/"

  def start_link(opts) do
    Supervisor.start_link(__MODULE__, opts)
  end

  @impl true
  def init(opts) do
    data_dir = Keyword.fetch!(opts, :data_dir)
    prefix = Keyword.get(opts, :prefix, @default_prefix)
    cluster_size = Keyword.get(opts, :cluster_size, 1)

    children = [
      {EKV, name: @ekv_name, data_dir: data_dir, cluster_size: cluster_size},
      {DurableServer.Supervisor,
       name: AshAi.Agents.DurableSup,
       prefix: prefix,
       backend: {DurableServer.Backends.EKVStore, name: @ekv_name}}
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end
end
