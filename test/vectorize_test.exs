# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

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

  test "embedding generation errors do not leak provider internals into the error message" do
    artist =
      Music.create_artist_manual!(%{
        name: "John Doe",
        bio: "John Doe FORCE_EMBED_ERROR"
      })

    assert {:error, error} = Music.update_embeddings_artist_manual(artist)

    message =
      error
      |> Ash.Error.to_error_class()
      |> Map.get(:errors, [])
      |> Enum.map_join(" ", &(Map.get(&1, :message) || Exception.message(&1)))

    # The raw provider error (API key, URL, response body) must not be echoed
    # into the user-facing validation error.
    refute message =~ "sk-live-SECRET-2726"
    refute message =~ "req_int_7fa1"
    refute message =~ "authorization"
    assert message =~ "An error occurred while generating embeddings"
  end

  test "ash_oban strategy works as expected" do
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
