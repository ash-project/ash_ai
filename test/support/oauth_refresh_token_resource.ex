# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Test.OAuthRefreshToken do
  @moduledoc false
  use Ash.Resource,
    domain: AshAi.Test.OauthDomain,
    data_layer: Ash.DataLayer.Ets

  attributes do
    uuid_v7_primary_key :id
    attribute :token_hash, :string, allow_nil?: false, public?: true
    attribute :client_id, :uuid_v7, allow_nil?: false, public?: true
    attribute :user_id, :uuid_v7, allow_nil?: false, public?: true
    attribute :scope, :string, allow_nil?: false, public?: true
    attribute :resource_uri, :string, allow_nil?: false, public?: true
    attribute :expires_at, :utc_datetime_usec, allow_nil?: false, public?: true
    attribute :rotated_to_id, :uuid_v7, public?: true
    attribute :revoked_at, :utc_datetime_usec, public?: true
  end

  actions do
    defaults [:read, :destroy]

    create :issue do
      accept [:token_hash, :client_id, :user_id, :scope, :resource_uri, :expires_at]
    end

    update :rotate do
      argument :new_id, :uuid_v7, allow_nil?: false
      accept []
      require_atomic? false

      change fn changeset, _ ->
        cond do
          Ash.Changeset.get_data(changeset, :revoked_at) ->
            Ash.Changeset.add_error(changeset, message: "refresh token revoked")

          Ash.Changeset.get_data(changeset, :rotated_to_id) ->
            Ash.Changeset.add_error(changeset, message: "refresh token already rotated")

          true ->
            new_id = Ash.Changeset.get_argument(changeset, :new_id)
            Ash.Changeset.change_attribute(changeset, :rotated_to_id, new_id)
        end
      end
    end

    update :revoke do
      accept []
      change set_attribute(:revoked_at, &DateTime.utc_now/0)
    end

    # Bulk destroy of expired/revoked rows. Wire into a periodic job:
    #
    #     OAuthRefreshToken
    #     |> Ash.Query.filter(expires_at < ^DateTime.utc_now() or not is_nil(revoked_at))
    #     |> Ash.bulk_destroy!(:destroy_expired, %{})
    destroy :destroy_expired do
      require_atomic? false
    end
  end

  identities do
    identity :by_token_hash, [:token_hash]
  end
end
