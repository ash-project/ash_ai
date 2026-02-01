# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.ChatFaker do
  @moduledoc false
  @behaviour LangChain.ChatModels.ChatModel

  alias LangChain.Message

  defstruct [
    # required for chat models
    callbacks: [],
    expect_fun: nil
  ]

  def new!(attrs) do
    struct(__MODULE__, attrs)
  end

  @impl LangChain.ChatModels.ChatModel
  def call(%__MODULE__{expect_fun: expect_fun} = chat_model, messages, tools)
      when is_list(messages) and is_list(tools) do
    case expect_fun do
      expect_fun when is_function(expect_fun) ->
        expect_fun.(chat_model, messages, tools)

      nil ->
        Message.new_assistant(%{content: "Good!"})
    end
  end

  @impl LangChain.ChatModels.ChatModel
  def restore_from_map(_data) do
    raise "Not implemented"
  end

  @impl LangChain.ChatModels.ChatModel
  def serialize_config(_model) do
    raise "Not implemented"
  end

  @impl LangChain.ChatModels.ChatModel
  def retry_on_fallback?(_), do: false
end
