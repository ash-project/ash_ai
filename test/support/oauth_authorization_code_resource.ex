# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Test.OAuthAuthorizationCode do
  @moduledoc false
  use Ash.Resource,
    domain: AshAi.Test.OauthDomain,
    data_layer: Ash.DataLayer.Ets

  attributes do
    uuid_v7_primary_key :id
    attribute :client_id, :uuid_v7, allow_nil?: false, public?: true
    attribute :user_id, :uuid_v7, allow_nil?: false, public?: true
    attribute :redirect_uri, :string, allow_nil?: false, public?: true
    attribute :code_challenge, :string, allow_nil?: false, public?: true
    attribute :scope, :string, allow_nil?: false, public?: true
    attribute :resource_uri, :string, allow_nil?: false, public?: true
    attribute :expires_at, :utc_datetime_usec, allow_nil?: false, public?: true
    attribute :consumed_at, :utc_datetime_usec, public?: true
  end

  actions do
    defaults [:read, :destroy]

    create :create do
      accept [:client_id, :user_id, :redirect_uri, :code_challenge, :scope, :resource_uri, :expires_at]
    end

    update :consume do
      accept []
      require_atomic? false

      change fn changeset, _ ->
        if Ash.Changeset.get_data(changeset, :consumed_at) do
          Ash.Changeset.add_error(changeset, field: :consumed_at, message: "code already used")
        else
          Ash.Changeset.change_attribute(changeset, :consumed_at, DateTime.utc_now())
        end
      end
    end
  end
end
