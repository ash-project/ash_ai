defmodule AshAi.Mcp.PromptTemplate do
  @moduledoc """
  Template management system for MCP prompts.

  This module provides functionality to discover, manage, and expose
  prompt templates through the MCP protocol.
  """

  @doc """
  Discovers prompt templates from Ash actions and domains.
  """
  def discover_prompts(opts \\ []) do
    otp_app = opts[:otp_app]

    case get_domains_and_resources(otp_app) do
      {:ok, domains_and_resources} ->
        prompts =
          domains_and_resources
          |> Enum.flat_map(fn {domain, resources} ->
            Enum.flat_map(resources, fn resource ->
              get_resource_prompts(domain, resource)
            end)
          end)

        # Add default system prompts
        system_prompts = get_system_prompts()

        {:ok, prompts ++ system_prompts}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Converts a prompt template to MCP prompt format.
  """
  def to_mcp_prompt(prompt_info) do
    %{
      "name" => prompt_info.name,
      "description" => prompt_info.description,
      "arguments" =>
        Enum.map(prompt_info.arguments, fn arg ->
          %{
            "name" => arg.name,
            "description" => arg.description,
            "required" => arg.required
          }
        end)
    }
  end

  @doc """
  Gets a prompt template by name and renders it with arguments.
  """
  def get_prompt(name, arguments \\ %{}, opts \\ []) do
    case find_prompt_by_name(name, opts) do
      {:ok, prompt_info} ->
        case render_prompt(prompt_info, arguments) do
          {:ok, rendered} ->
            {:ok,
             %{
               "description" => prompt_info.description,
               "messages" => rendered.messages
             }}

          {:error, reason} ->
            {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Private functions

  defp get_domains_and_resources(nil) do
    {:error, :otp_app_required}
  end

  defp get_domains_and_resources(otp_app) do
    domains_and_resources = Ash.Info.domains_and_resources(otp_app)
    {:ok, domains_and_resources}
  rescue
    error ->
      {:error, {:discovery_failed, error}}
  end

  defp get_resource_prompts(domain, resource) do
    # Get all prompt-backed actions from the resource
    resource
    |> Ash.Resource.Info.actions()
    |> Enum.filter(&prompt_action?/1)
    |> Enum.map(fn action ->
      %{
        name: "#{domain_name(domain)}.#{resource_name(resource)}.#{action.name}",
        description: action.description || "Prompt-backed action: #{action.name}",
        type: :action_prompt,
        domain: domain,
        resource: resource,
        action: action,
        arguments: get_action_arguments(action)
      }
    end)
  rescue
    _ -> []
  end

  defp get_system_prompts do
    [
      %{
        name: "ash_ai.default_action_prompt",
        description: "Default prompt template for Ash AI actions",
        type: :system_prompt,
        template: get_default_action_template(),
        arguments: [
          %{name: "action_name", description: "The name of the action", required: true},
          %{
            name: "action_description",
            description: "Description of the action",
            required: false
          },
          %{name: "arguments", description: "Action arguments", required: false}
        ]
      },
      %{
        name: "ash_ai.simple_task",
        description: "Simple task completion prompt",
        type: :system_prompt,
        template: {"You are a helpful assistant. Complete the following task.", "<%= @task %>"},
        arguments: [
          %{name: "task", description: "The task to complete", required: true}
        ]
      }
    ]
  end

  defp prompt_action?(action) do
    # Check if the action uses the prompt implementation
    case action.run do
      {AshAi.Actions.Prompt, _opts} -> true
      _ -> false
    end
  end

  defp get_action_arguments(action) do
    action.arguments
    |> Enum.map(fn argument ->
      %{
        name: to_string(argument.name),
        description: argument.description || "",
        required: !argument.allow_nil?
      }
    end)
  end

  defp domain_name(domain) do
    domain |> Module.split() |> List.last()
  end

  defp resource_name(resource) do
    resource |> Module.split() |> List.last()
  end

  defp find_prompt_by_name(name, opts) do
    case discover_prompts(opts) do
      {:ok, prompts} ->
        case Enum.find(prompts, &(&1.name == name)) do
          nil -> {:error, :prompt_not_found}
          prompt -> {:ok, prompt}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp render_prompt(prompt_info, arguments) do
    case prompt_info.type do
      :action_prompt ->
        render_action_prompt(prompt_info, arguments)

      :system_prompt ->
        render_system_prompt(prompt_info, arguments)
    end
  end

  defp render_action_prompt(prompt_info, arguments) do
    # This would need access to actual action input and context
    # For now, return a simplified template
    {:ok,
     %{
       messages: [
         %{
           "role" => "system",
           "content" =>
             "You are responsible for performing the #{prompt_info.action.name} action."
         },
         %{
           "role" => "user",
           "content" => "Perform the action with arguments: #{Jason.encode!(arguments)}"
         }
       ]
     }}
  rescue
    error ->
      {:error, {:render_failed, error}}
  end

  defp render_system_prompt(prompt_info, arguments) do
    case prompt_info.template do
      {system_prompt, user_message} ->
        system_content = EEx.eval_string(system_prompt, assigns: arguments)
        user_content = EEx.eval_string(user_message, assigns: arguments)

        {:ok,
         %{
           messages: [
             %{"role" => "system", "content" => system_content},
             %{"role" => "user", "content" => user_content}
           ]
         }}

      single_prompt ->
        content = EEx.eval_string(single_prompt, assigns: arguments)

        {:ok,
         %{
           messages: [
             %{"role" => "user", "content" => content}
           ]
         }}
    end
  rescue
    error ->
      {:error, {:render_failed, error}}
  end

  defp get_default_action_template do
    {"""
     You are responsible for performing the `<%= @action_name %>` action.

     <%= if @action_description do %>
     # Description
     <%= @action_description %>
     <% end %>
     """,
     """
     # Action Inputs

     <%= for {name, value} <- @arguments do %>
       - <%= name %>: <%= Jason.encode!(value) %>
     <% end %>
     """}
  end
end
