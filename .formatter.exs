spark_locals_without_parens = [
  action_parameters: 1,
  ash_oban_trigger_name: 1,
  async: 1,
  attributes: 1,
  define_update_action_for_manual_strategy?: 1,
  description: 1,
  embedding_model: 1,
  full_text: 0,
  full_text: 1,
  identity: 1,
  load: 1,
  name: 1,
  strategy: 1,
  text: 1,
  tool: 3,
  tool: 4,
  used_attributes: 1
]

[
  locals_without_parens: spark_locals_without_parens,
  import_deps: [:ash],
  export: [
    locals_without_parens: spark_locals_without_parens
  ],
  inputs: ["{mix,.formatter}.exs", "{config,lib,test}/**/*.{ex,exs}"]
]
