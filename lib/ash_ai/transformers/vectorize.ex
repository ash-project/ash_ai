defmodule AshAi.Transformers.Vectorize do
  @moduledoc false
  use Spark.Dsl.Transformer

  import Spark.Dsl.Builder
  import Ash.Resource.Builder

  def after?(_), do: true

  def transform(dsl) do
    attrs =
      dsl
      |> AshAi.Info.vectorize_attributes!()

    full_text_entities =
      AshAi.Info.vectorize(dsl)
      |> Enum.reject(&is_nil(&1.text))

    if Enum.empty?(attrs) && Enum.empty?(full_text_entities) do
      {:ok, dsl}
    else
      if Ash.Resource.Info.data_layer(dsl) != AshPostgres.DataLayer do
        raise "AshAi vectorization only currently supports AshPostgres"
      end

      full_text_entities =
        full_text_entities
        |> Enum.map(&{:full_text, &1.name, &1.used_attributes, &1.text})

      names =
        full_text_entities
        |> Enum.reject(&is_nil(Ash.Resource.Info.field(dsl, elem(&1, 1))))

      if !Enum.empty?(names) do
        raise "AshAi vectorization won't work if the field names are already taken: `#{names |> Enum.join("`, `")}`"
      end

      full_text_entities
      |> Enum.map(&{:full_text, &1 |> elem(1)})
      |> Enum.concat(attrs)
      |> Enum.reduce({:ok, dsl}, &vectorize_attribute(&2, &1))
      |> update_vectors_action(full_text_entities)
    end
  end

  defbuilder update_vectors_action(dsl_state, full_text_entities) do
    attrs =
      AshAi.Info.vectorize_attributes!(dsl_state)

    full_text_entities
    |> Enum.concat(attrs)
    |> case do
      [] ->
        {:ok, dsl_state}

      vectors ->
        strategy = AshAi.Info.vectorize_strategy!(dsl_state)

        case strategy do
          :after_action ->
            dsl_state
            |> add_change({AshAi.Changes.VectorizeAfterAction, [vectors: vectors]})
            |> add_new_action(:update, :ash_ai_update_embeddings,
              accept: Enum.map(vectors, &elem(&1, 1)),
              require_atomic?: false
            )

          :manual ->
            if AshAi.Info.vectorize_define_update_action_for_manual_strategy?(dsl_state) do
              dsl_state
              |> add_new_action(:update, :ash_ai_update_embeddings,
                accept: [],
                changes: [
                  %Ash.Resource.Change{
                    change: {AshAi.Changes.Vectorize, [vectors: vectors]},
                    on: nil,
                    only_when_valid?: true,
                    description: nil,
                    always_atomic?: false,
                    where: []
                  }
                ],
                require_atomic?: false
              )
            else
              {:ok, dsl_state}
            end

          :ash_oban ->
            if Code.ensure_loaded?(AshOban) do
              trigger_name = AshAi.Info.vectorize_ash_oban_trigger_name!(dsl_state)

              triggers =
                Spark.Dsl.Transformer.get_entities(dsl_state, [:oban, :triggers])

              trigger_defined? = Enum.any?(triggers, &(&1.name == trigger_name))

              if trigger_defined? do
                dsl_state
                |> add_change(
                  {AshAi.Changes.VectorizeAfterActionObanTrigger, [trigger_name: trigger_name]}
                )
                |> add_new_action(:update, :ash_ai_update_embeddings,
                  accept: [],
                  changes: [
                    %Ash.Resource.Change{
                      change: {AshAi.Changes.Vectorize, [vectors: vectors]},
                      on: nil,
                      only_when_valid?: true,
                      description: nil,
                      always_atomic?: false,
                      where: []
                    }
                  ],
                  require_atomic?: false
                )
              else
                raise "ash_oban-trigger :#{trigger_name} is not defined."
              end
            else
              raise "AshOban must be loaded in order to use the :ash_oban strategy, see README.md in ash_ai for instructions."
            end
        end
    end
  end

  defbuilder vectorize_attribute(dsl_state, {_, dest}) do
    {embedding_model, opts} = AshAi.Info.vectorize_embedding_model!(dsl_state)

    dsl_state
    |> add_new_attribute(dest, :vector,
      constraints: [dimensions: embedding_model.dimensions(opts)],
      select_by_default?: false
    )
  end
end
