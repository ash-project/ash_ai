# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Test.OAuthClient do
  @moduledoc false
  use Ash.Resource,
    domain: AshAi.Test.OauthDomain,
    data_layer: Ash.DataLayer.Ets

  attributes do
    uuid_v7_primary_key :id
    attribute :client_name, :string, public?: true, allow_nil?: false
    attribute :redirect_uris, {:array, :string}, public?: true, allow_nil?: false, default: []
    attribute :grant_types, {:array, :string}, public?: true, default: ["authorization_code"]
    attribute :response_types, {:array, :string}, public?: true, default: ["code"]
    attribute :token_endpoint_auth_method, :string, public?: true, default: "none"
    attribute :client_secret_hash, :string, public?: false
    attribute :scope, :string, public?: true, default: "mcp"
    attribute :last_used_at, :utc_datetime_usec, public?: true
    create_timestamp :created_at
    update_timestamp :updated_at
  end

  actions do
    defaults [:read, :destroy]

    create :register do
      accept [:client_name, :redirect_uris, :grant_types, :response_types, :token_endpoint_auth_method, :scope]
    end

    update :touch do
      accept []
      change set_attribute(:last_used_at, &DateTime.utc_now/0)
    end
  end
end
