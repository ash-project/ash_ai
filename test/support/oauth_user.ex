# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Test.OauthUser do
  @moduledoc false
  use Ash.Resource,
    domain: AshAi.Test.OauthDomain,
    data_layer: Ash.DataLayer.Ets

  attributes do
    uuid_v7_primary_key :id
    attribute :email, :ci_string, public?: true, allow_nil?: false
  end

  actions do
    defaults [:read]
    create :create, accept: [:email]
  end
end

defmodule AshAi.Test.OauthDomain do
  @moduledoc false
  use Ash.Domain

  resources do
    resource AshAi.Test.OauthUser
  end
end
