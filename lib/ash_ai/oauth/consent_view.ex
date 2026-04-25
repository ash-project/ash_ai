# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Oauth.ConsentView do
  @moduledoc """
  Default consent screen renderer.

  Override via `consent_template:` config to customize. The replacement
  module must export `render(:consent, assigns)` returning a binary or
  `Phoenix.HTML.Safe`.
  """

  require EEx

  @template ~S"""
  <!DOCTYPE html>
  <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Authorize <%= @client_name %></title>
      <style>
        body { font-family: system-ui, sans-serif; max-width: 480px; margin: 4rem auto; padding: 0 1rem; }
        h1 { font-size: 1.5rem; }
        .scopes { background: #f4f4f5; padding: 1rem; border-radius: 0.5rem; margin: 1rem 0; }
        button { padding: 0.75rem 1.25rem; margin-right: 0.5rem; cursor: pointer; }
        button.approve { background: #2563eb; color: white; border: none; border-radius: 0.25rem; }
        button.deny { background: white; color: #1f2937; border: 1px solid #d1d5db; border-radius: 0.25rem; }
        code { background: #f4f4f5; padding: 0.1rem 0.25rem; border-radius: 0.25rem; }
      </style>
    </head>
    <body>
      <h1>Authorize access</h1>
      <p><strong><%= @client_name %></strong> wants to access your account at <strong><%= @resource_uri %></strong>.</p>
      <p>Redirect target: <code><%= @redirect_uri %></code></p>
      <div class="scopes">
        <strong>Requested scope:</strong> <code><%= @scope %></code>
      </div>
      <form method="POST" action="<%= @action_path %>">
        <input type="hidden" name="_csrf_token" value="<%= @csrf_token %>" />
        <input type="hidden" name="response_type" value="code" />
        <input type="hidden" name="client_id" value="<%= @client_id %>" />
        <input type="hidden" name="redirect_uri" value="<%= @redirect_uri %>" />
        <input type="hidden" name="code_challenge" value="<%= @code_challenge %>" />
        <input type="hidden" name="code_challenge_method" value="S256" />
        <input type="hidden" name="scope" value="<%= @scope %>" />
        <input type="hidden" name="state" value="<%= @state %>" />
        <input type="hidden" name="resource" value="<%= @resource %>" />
        <button type="submit" class="approve" name="action" value="approve">Approve</button>
        <button type="submit" class="deny" name="action" value="deny">Deny</button>
      </form>
    </body>
  </html>
  """

  EEx.function_from_string(:def, :render_consent, @template, [:assigns])

  def render(:consent, assigns) when is_map(assigns) do
    render_consent(assigns)
  end
end
