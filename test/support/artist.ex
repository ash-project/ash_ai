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
