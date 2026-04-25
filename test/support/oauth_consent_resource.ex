# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Test.OAuthConsent do
  @moduledoc false
  use Ash.Resource,
    domain: AshAi.Test.OauthDomain,
    data_layer: Ash.DataLayer.Ets

  attributes do
    uuid_v7_primary_key :id
    attribute :user_id, :uuid_v7, allow_nil?: false, public?: true
    attribute :client_id, :uuid_v7, allow_nil?: false, public?: true
    attribute :scope, :string, allow_nil?: false, public?: true
    attribute :granted_at, :utc_datetime_usec, allow_nil?: false, public?: true, default: &DateTime.utc_now/0
  end

  actions do
    defaults [:read, :destroy]

    create :grant do
      upsert? true
      upsert_identity :by_user_client
      accept [:user_id, :client_id, :scope]
    end
  end

  identities do
    identity :by_user_client, [:user_id, :client_id], pre_check_with: AshAi.Test.OauthDomain
  end
end
