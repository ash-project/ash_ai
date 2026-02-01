# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

spark_locals_without_parens = [
  _meta: 1,
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
  mcp_resource: 4,
  mcp_resource: 5,
  mime_type: 1,
  name: 1,
  strategy: 1,
  text: 1,
  title: 1,
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
