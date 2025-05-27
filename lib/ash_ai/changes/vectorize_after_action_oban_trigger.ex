if Code.ensure_loaded?(AshOban) do
  defmodule AshAi.Changes.VectorizeAfterActionObanTrigger do
    @moduledoc "Run an ash_oban trigger when embeddings need to be regenerated."
    use Ash.Resource.Change

    # TODO add bulk action callbacks here?
    def change(changeset, module_opts, _context) do
      Ash.Changeset.after_action(changeset, fn
        changeset, record ->
          if changeset.action.name == :ash_ai_update_embeddings do
            {:ok, record}
          else
            if AshAi.has_vectorize_change?(changeset) do
              %Oban.Job{} = AshOban.run_trigger(record, module_opts[:trigger_name])
            end

            {:ok, record}
          end
      end)
    end

    def atomic(changeset, opts, context) do
      {:ok, change(changeset, opts, context)}
    end
  end
end
