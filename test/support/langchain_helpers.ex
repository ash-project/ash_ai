defmodule AshAi.Test.LangChainHelpers do
  @moduledoc """
  Helper function for handling LangChain version compatibility in tests.

  In LangChain 0.4+, message content became a list of ContentPart structs,
  while in earlier versions it was a plain string. This helper provides
  a backward-compatible way to extract text content.
  """

  alias LangChain.Message.ContentPart

  def extract_content_text([%ContentPart{type: :text, content: text} | _]) when is_binary(text) do
    {:ok, text}
  end

  def extract_content_text(content) when is_binary(content) do
    {:ok, content}
  end

  def extract_content_text(_content) do
    :error
  end
end
