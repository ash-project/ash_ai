defmodule AshAi.Changes.VectorizeAfterAction do
  @moduledoc "Vectorizes attributes inline immediately after they are changed"
  use Ash.Resource.Change

  # TODO add bulk action callbacks here?
  def change(changeset, opts, context) do
    Ash.Changeset.after_transaction(changeset, fn
      _changeset, {:error, error} ->
        {:error, error}

      changeset, {:ok, result} ->
        if changeset.action.name == :ash_ai_update_embeddings do
          {:ok, result}
        else
          {embedding_model, vector_opts} =
            AshAi.Info.vectorize_embedding_model!(changeset.resource)

          changes =
            opts[:vectors]
            |> Enum.flat_map(fn
              {source, dest} ->
                if Ash.Changeset.changing_attribute?(changeset, source) do
                  text = Map.get(result, source)

                  [{dest, text}]
                else
                  []
                end

              {:full_text, name, used_attrs, fun} ->
                if is_nil(used_attrs) ||
                     Enum.any?(used_attrs, &Ash.Changeset.changing_attribute?(changeset, &1)) do
                  text = fun.(result)

                  [{name, text}]
                else
                  []
                end
            end)

          strings = Enum.map(changes, &elem(&1, 1))

          case embedding_model.generate(strings, vector_opts) do
            {:ok, vectors} ->
              changes =
                Enum.zip_with(changes, vectors, fn {k, _}, r ->
                  {k, r}
                end)

              result
              |> Ash.Changeset.for_update(
                :ash_ai_update_embeddings,
                changes,
                Ash.Context.to_opts(context, actor: %AshAi{})
              )
              |> Ash.update()

            {:error, error} ->
              {:error, error}
          end
        end
    end)
  end

  def atomic(changeset, opts, context) do
    {:ok, change(changeset, opts, context)}
  end
end
