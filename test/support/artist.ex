# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Test.Music.ArtistAfterAction do
  @moduledoc false
  use Ash.Resource,
    domain: AshAi.Test.Music,
    extensions: [AshAi],
    data_layer: AshPostgres.DataLayer

  postgres do
    table("artists")
    repo(AshAi.TestRepo)
  end

  vectorize do
    strategy :after_action

    full_text do
      text fn record ->
        """
        Artist details
        Name: #{record.name}
        Bio: #{record.bio}
        """
      end

      used_attributes [:name, :bio]
    end

    full_text do
      name :name_full_text_vector

      text fn record ->
        """
        Artist Name: #{record.name}
        """
      end

      used_attributes [:name]
    end

    embedding_model(AshAi.Test.EmbeddingModel)
  end

  attributes do
    uuid_v7_primary_key :id, writable?: true
    attribute :name, :string, public?: true
    attribute :bio, :string, public?: true
  end

  actions do
    default_accept [:*]
    defaults [:create, :read, :update, :destroy]
  end
end

defmodule AshAi.Test.Music.ArtistManual do
  @moduledoc false
  use Ash.Resource,
    domain: AshAi.Test.Music,
    extensions: [AshAi],
    data_layer: AshPostgres.DataLayer

  postgres do
    table("artists")
    repo(AshAi.TestRepo)
  end

  vectorize do
    strategy :manual

    full_text do
      text fn record ->
        """
        Artist details
        Name: #{record.name}
        Bio: #{record.bio}
        """
      end

      used_attributes [:name, :bio]
    end

    full_text do
      name :name_full_text_vector

      text fn record ->
        """
        Artist Name: #{record.name}
        """
      end

      used_attributes [:name]
    end

    embedding_model(AshAi.Test.EmbeddingModel)
  end

  attributes do
    uuid_v7_primary_key :id, writable?: true
    attribute :name, :string, public?: true
    attribute :bio, :string, public?: true
  end

  actions do
    default_accept [:*]
    defaults [:create, :read, :update, :destroy]
  end
end

defmodule AshAi.Test.Music.ArtistOban do
  @moduledoc false
  use Ash.Resource,
    domain: AshAi.Test.Music,
    extensions: [AshAi, AshOban],
    data_layer: AshPostgres.DataLayer

  postgres do
    table("artists")
    repo(AshAi.TestRepo)
  end

  vectorize do
    strategy :ash_oban

    full_text do
      text fn record ->
        """
        Artist details
        Name: #{record.name}
        Bio: #{record.bio}
        """
      end

      used_attributes [:name, :bio]
    end

    full_text do
      name :name_full_text_vector

      text fn record ->
        """
        Artist Name: #{record.name}
        """
      end

      used_attributes [:name]
    end

    embedding_model(AshAi.Test.EmbeddingModel)
  end

  oban do
    triggers do
      trigger :ash_ai_update_embeddings do
        action :ash_ai_update_embeddings
        worker_module_name(AshAi.Test.Music.ArtistOban.AshOban.Worker.AshAiUpdateEmbeddings)
        scheduler_module_name(AshAi.Test.Music.ArtistOban.AshOban.Scheduler.AshAiUpdateEmbeddings)
      end
    end
  end

  attributes do
    uuid_v7_primary_key :id, writable?: true
    create_timestamp :created_at, public?: true
    update_timestamp :updated_at, public?: true
    attribute :name, :string, public?: true
    attribute :bio, :string, public?: true
  end

  actions do
    default_accept [:*]
    defaults [:create, :read, :update, :destroy]
  end
end

defmodule AshAi.Test.Music.ArtistUi do
  @moduledoc false
  use Ash.Resource,
    domain: AshAi.Test.Music,
    extensions: [AshAi]

  attributes do
    uuid_v7_primary_key :id, writable?: true
    attribute :name, :string, public?: true
    attribute :bio, :string, public?: true
  end

  actions do
    action :artist_card, :string do
      description "Get an artist card UI representation."

      run fn _, _ ->
        {:ok, "<div>Artist Card</div>"}
      end
    end

    action :artist_card_with_params, :string do
      description "Get an artist card with custom template."
      argument :template, :string, allow_nil?: false

      run fn input, _ ->
        {:ok, "<div>#{input.arguments.template}</div>"}
      end
    end

    action :failing_action, :string do
      description "Action that always fails for testing."

      run fn _, _ ->
        {:error, "Intentional test failure"}
      end
    end

    action :artist_json, :string do
      description "Get artist data as JSON string."

      run fn _, _ ->
        {:ok, Jason.encode!(%{artist: "Test Artist", genre: "Rock"})}
      end
    end

    action :actor_test, :string do
      description "Returns the actor ID if present."

      run fn _, context ->
        case context.actor do
          nil -> {:ok, "no_actor"}
          actor -> {:ok, "actor:#{inspect(actor)}"}
        end
      end
    end
  end
end
