# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.DevTools do
  @moduledoc false
  use Ash.Domain,
    extensions: [AshAi],
    validate_config_inclusion?: false

  tools do
    tool :list_ash_resources, AshAi.DevTools.Tools, :list_ash_resources do
      description "List all Ash resources in the app along with their domains"
    end

    tool :get_usage_rules, AshAi.DevTools.Tools, :get_usage_rules do
      description """
      Gets name, description and usage rules file path for all packages that have usage rules.

      Read the usage rules file to understand how to use any given package.
      """
    end

    tool :list_generators, AshAi.DevTools.Tools, :list_generators do
      description "List available generators and their documentation"
    end
  end

  resources do
    resource AshAi.DevTools.Tools
  end
end
