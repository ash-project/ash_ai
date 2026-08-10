# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.ToolLoadSelectTest do
  use ExUnit.Case, async: true

  alias __MODULE__.{Album, Artist, Domain}

  defmodule Album do
    @moduledoc false
    use Ash.Resource, domain: Domain, data_layer: Ash.DataLayer.Ets

    ets do
      private? true
    end

    attributes do
      uuid_v7_primary_key :id, writable?: true
      attribute :title, :string, public?: true
      attribute :year, :integer, public?: true
      attribute :notes, :string, public?: true
    end

    relationships do
      belongs_to :artist, Artist, public?: true, attribute_writable?: true
    end

    actions do
      defaults [:read, :create, :update, :destroy]
      default_accept [:id, :title, :year, :notes, :artist_id]
    end
  end

  defmodule Artist do
    @moduledoc false
    use Ash.Resource, domain: Domain, data_layer: Ash.DataLayer.Ets

    ets do
      private? true
    end

    attributes do
      uuid_v7_primary_key :id, writable?: true
      attribute :name, :string, public?: true
      attribute :bio, :string, public?: true
      attribute :secret, :string
    end

    relationships do
      has_many :albums, Album, public?: true
    end

    actions do
      defaults [:read, :create, :update, :destroy]
      default_accept [:id, :name, :bio, :secret]
    end
  end

  defmodule Domain do
    @moduledoc false
    use Ash.Domain, extensions: [AshAi]

    resources do
      resource Artist
      resource Album
    end

    tools do
      # Baseline: non-strict load of a relationship with a nested field list
      tool :read_artists, Artist, :read, load: [albums: [:title]]

      # Same load statement, but strict: only :title is selected on albums
      tool :read_artists_strict, Artist, :read,
        load: [albums: [:title]],
        load_strict?: true

      # Restrict the serialized top-level fields
      tool :read_artists_select, Artist, :read, select: [:name]

      # select combined with load
      tool :read_artists_select_and_load, Artist, :read,
        select: [:name],
        load: [albums: [:title]]

      # select including a private attribute
      tool :read_artists_select_private, Artist, :read, select: [:name, :secret]

      # Non-read actions honour select as well
      tool :create_artist, Artist, :create, select: [:name]
      tool :update_artist, Artist, :update, select: [:name]
    end
  end

  setup do
    artist =
      Artist
      |> Ash.Changeset.for_create(:create, %{
        name: "Miles Davis",
        bio: "Trumpeter",
        secret: "classified"
      })
      |> Ash.create!(domain: Domain)

    album =
      Album
      |> Ash.Changeset.for_create(:create, %{
        title: "Kind of Blue",
        year: 1959,
        notes: "Modal jazz",
        artist_id: artist.id
      })
      |> Ash.create!(domain: Domain)

    %{artist: artist, album: album, registry: registry()}
  end

  describe "load_strict?" do
    test "defaults to false, loading all public fields of the relationship", %{registry: registry} do
      {:ok, json, [artist]} = registry["read_artists"].(%{}, context())

      [album] = artist.albums

      assert album.title == "Kind of Blue"
      assert album.year == 1959
      assert album.notes == "Modal jazz"

      [serialized_album] = Jason.decode!(json) |> hd() |> Map.fetch!("albums")

      assert serialized_album["title"] == "Kind of Blue"
      assert serialized_album["year"] == 1959
      assert serialized_album["notes"] == "Modal jazz"
    end

    test "true selects only the listed fields on the relationship", %{registry: registry} do
      {:ok, json, [artist]} = registry["read_artists_strict"].(%{}, context())

      [album] = artist.albums

      assert album.title == "Kind of Blue"
      assert match?(%Ash.NotLoaded{}, album.year)
      assert match?(%Ash.NotLoaded{}, album.notes)

      [serialized_album] = Jason.decode!(json) |> hd() |> Map.fetch!("albums")

      assert serialized_album["title"] == "Kind of Blue"
      refute Map.has_key?(serialized_album, "year")
      refute Map.has_key?(serialized_album, "notes")
    end
  end

  describe "select" do
    test "restricts both the query and the serialized output", %{registry: registry} do
      {:ok, json, [artist]} = registry["read_artists_select"].(%{}, context())

      assert artist.name == "Miles Davis"
      assert match?(%Ash.NotLoaded{}, artist.bio)

      assert Jason.decode!(json) == [%{"name" => "Miles Davis"}]
    end

    test "combines with load", %{registry: registry} do
      {:ok, json, [artist]} = registry["read_artists_select_and_load"].(%{}, context())

      assert artist.name == "Miles Davis"
      assert match?(%Ash.NotLoaded{}, artist.bio)

      assert [%{"name" => "Miles Davis", "albums" => [album]}] = Jason.decode!(json)
      assert album["title"] == "Kind of Blue"
    end

    test "can select private attributes", %{registry: registry} do
      {:ok, json, [artist]} = registry["read_artists_select_private"].(%{}, context())

      assert artist.secret == "classified"

      assert Jason.decode!(json) == [%{"name" => "Miles Davis", "secret" => "classified"}]
    end

    test "defaults to all public attributes when unset", %{registry: registry} do
      {:ok, json, [artist]} = registry["read_artists"].(%{}, context())

      assert artist.name == "Miles Davis"
      assert artist.bio == "Trumpeter"

      serialized = Jason.decode!(json) |> hd()

      assert serialized["name"] == "Miles Davis"
      assert serialized["bio"] == "Trumpeter"
    end

    test "applies to create actions", %{registry: registry} do
      {:ok, json, record} =
        registry["create_artist"].(
          %{"input" => %{"name" => "John Coltrane", "bio" => "Saxophonist"}},
          context()
        )

      assert record.name == "John Coltrane"
      assert Jason.decode!(json) == %{"name" => "John Coltrane"}
    end

    test "applies to update actions", %{artist: artist, registry: registry} do
      {:ok, json, record} =
        registry["update_artist"].(
          %{"id" => artist.id, "input" => %{"name" => "Miles Dewey Davis"}},
          context()
        )

      assert record.name == "Miles Dewey Davis"
      assert Jason.decode!(json) == %{"name" => "Miles Dewey Davis"}
    end
  end

  defp registry do
    {_tools, registry} =
      AshAi.build_tools_and_registry(
        actions: [{Artist, [:read, :create, :update]}],
        strict: false
      )

    registry
  end

  defp context do
    %{actor: nil, tenant: nil, context: %{}, tool_callbacks: %{}}
  end
end
