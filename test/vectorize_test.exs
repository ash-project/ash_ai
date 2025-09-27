defmodule AshAiVectorizeTest do
  use AshAi.RepoCase, async: false

  use Oban.Testing, repo: AshAi.TestRepo, prefix: "private"

  alias AshAi.Test.Music

  test "after_action strategy works as expected" do
    artist =
      Music.create_artist_after_action!(%{
        name: "John Doe",
        bio: "John Doe is a musician"
      })
      |> Ash.load!([:full_text_vector, :name_full_text_vector])

    assert is_list(Ash.Vector.to_list(artist.full_text_vector))
    assert is_list(Ash.Vector.to_list(artist.name_full_text_vector))
  end

  test "manual strategy works as expected" do
    artist =
      Music.create_artist_manual!(%{
        name: "John Doe",
        bio: "John Doe is a musician"
      })
      |> Ash.load!([:full_text_vector, :name_full_text_vector])

    assert {nil, nil} = {artist.full_text_vector, artist.name_full_text_vector}

    artist =
      Music.update_embeddings_artist_manual!(artist)
      |> Ash.load!([:full_text_vector, :name_full_text_vector])

    assert is_list(Ash.Vector.to_list(artist.full_text_vector))
    assert is_list(Ash.Vector.to_list(artist.name_full_text_vector))
  end

  test "ash_oban strategy works as expected" do
    Oban.start_link(AshOban.config([AshAi.Test.Music], Application.get_env(:ash_ai, :oban)))

    artist =
      Music.create_artist_oban!(%{
        name: "John Doe",
        bio: "John Doe is a musician"
      })
      |> Ash.load!([:full_text_vector, :name_full_text_vector])

    assert {nil, nil} = {artist.full_text_vector, artist.name_full_text_vector}

    assert [_job] =
             all_enqueued(
               worker: AshAi.Test.Music.ArtistOban.AshOban.Worker.AshAiUpdateEmbeddings
             )

    assert %{success: 1, failure: 0} =
             Oban.drain_queue(queue: :artist_oban_ash_ai_update_embeddings)

    artist = Ash.load!(artist, [:full_text_vector, :name_full_text_vector])
    assert is_list(Ash.Vector.to_list(artist.full_text_vector))
    assert is_list(Ash.Vector.to_list(artist.name_full_text_vector))

    updated_artist =
      Music.update_artist_oban!(artist, %{name: "Jane Doe", bio: "Jane Doe is a musician"})

    assert %{success: 1, failure: 0} =
             Oban.drain_queue(queue: :artist_oban_ash_ai_update_embeddings)

    updated_vector_artist = Ash.load!(updated_artist, [:full_text_vector, :name_full_text_vector])
    assert DateTime.after?(updated_vector_artist.updated_at, updated_artist.updated_at)
    assert is_list(Ash.Vector.to_list(artist.full_text_vector))
    assert is_list(Ash.Vector.to_list(artist.name_full_text_vector))
  end
end
