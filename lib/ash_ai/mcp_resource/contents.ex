# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.McpResource.Contents do
  @moduledoc """
  Builds the `contents` of an `mcp_resource`'s `resources/read` result from
  what its action returned.

  Without the `contents` option, an action that returns `:string` is sent as
  text, and one that returns `:binary` as a base64 `blob`, each with the
  resource's `mime_type`. Set `contents` when that isn't enough: a MIME type
  that differs per read, such as a photo's, or several items for one URI. It
  takes a module implementing this behaviour (or `{module, opts}`), or a
  function taking the action's result and an
  `AshAi.McpResource.Contents.Context`:

      mcp_resources do
        mcp_resource :photo, "photos://{id}", MyApp.Photos.Photo, :get do
          title "Photo"
          contents &MyAppWeb.McpViews.photo/2
        end
      end

      def photo(%Photo{} = photo, _context) do
        AshAi.McpResource.Contents.blob(MyApp.Storage.read!(photo.key),
          mime_type: photo.mime_type
        )
      end

  With `contents`, the action may return any type. Return one item built with
  `text/2` or `blob/2`, or a list of them. An item's `uri` defaults to the URI
  that was read, and its `mime_type` to the resource's `mime_type`, if it has
  one.

  The callback isn't called when the action returns `nil` or fails with
  `Ash.Error.Query.NotFound`: both are sent as resource not found. If it
  raises, or returns anything else, the error is logged and the client gets a
  read error.
  """

  require Logger

  defmodule Context do
    @moduledoc """
    The context passed to an `AshAi.McpResource.Contents` callback.

      * `:mcp_resource` - the `%AshAi.McpResource{}` that was read
      * `:uri` - the URI that was read
      * `:arguments` - the arguments the action ran with (string keys),
        including those taken from a URI template
      * `:actor`, `:tenant`, `:context` - what the action ran with
    """
    defstruct [:mcp_resource, :uri, :arguments, :actor, :tenant, :context]

    @type t :: %__MODULE__{
            mcp_resource: AshAi.McpResource.t(),
            uri: String.t(),
            arguments: map(),
            actor: term(),
            tenant: term(),
            context: map()
          }
  end

  defmodule Text do
    @moduledoc "A text item in a `resources/read` result. Build one with `AshAi.McpResource.Contents.text/2`."
    defstruct [:text, :uri, :mime_type, :meta]

    @type t :: %__MODULE__{
            text: String.t(),
            uri: String.t() | nil,
            mime_type: String.t() | nil,
            meta: map() | nil
          }
  end

  defmodule Blob do
    @moduledoc "A binary item in a `resources/read` result. Build one with `AshAi.McpResource.Contents.blob/2`."
    defstruct [:data, :uri, :mime_type, :meta]

    @type t :: %__MODULE__{
            data: binary(),
            uri: String.t() | nil,
            mime_type: String.t() | nil,
            meta: map() | nil
          }
  end

  @type item :: Text.t() | Blob.t()

  @doc "Returns the contents for one read: an item or a list of items."
  @callback contents(result :: term(), opts :: Keyword.t(), context :: Context.t()) ::
              item() | [item()]

  defmacro __using__(_) do
    quote do
      @behaviour AshAi.McpResource.Contents
    end
  end

  @item_opts [:uri, :mime_type, :meta]

  @doc """
  A text item. `text` must be valid UTF-8.

  ## Options

    * `:mime_type` - defaults to the resource's `mime_type`
    * `:uri` - defaults to the URI that was read
    * `:meta` - a map sent as the item's `_meta`
  """
  @spec text(String.t(), Keyword.t()) :: Text.t()
  def text(text, opts \\ []) when is_binary(text) do
    struct!(Text, [text: text] ++ Keyword.validate!(opts, @item_opts))
  end

  @doc """
  A binary item. Pass the raw bytes; they are base64-encoded for you.

  Takes the same options as `text/2`.
  """
  @spec blob(binary(), Keyword.t()) :: Blob.t()
  def blob(data, opts \\ []) when is_binary(data) do
    struct!(Blob, [data: data] ++ Keyword.validate!(opts, @item_opts))
  end

  @doc false
  # The JSON `contents` list for a read, from the action's (non-nil) result
  @spec run(AshAi.McpResource.t(), term(), Context.t()) :: {:ok, [map()]} | {:error, String.t()}
  def run(%AshAi.McpResource{contents: nil} = resource, result, context) do
    item =
      case resource.action do
        %{returns: Ash.Type.Binary} when is_binary(result) -> %Blob{data: result}
        _action when is_binary(result) -> %Text{text: result}
        _action -> result
      end

    to_json([item], resource, context, "its action returned")
  end

  def run(%AshAi.McpResource{contents: {module, opts}} = resource, result, context) do
    result
    |> module.contents(opts, context)
    |> List.wrap()
    |> to_json(resource, context, "its `contents` callback returned")
  rescue
    error ->
      failure(
        resource,
        "contents callback failed",
        Exception.format(:error, error, __STACKTRACE__)
      )
  end

  defp to_json(items, resource, context, source) do
    case Enum.reject(items, &valid_item?/1) do
      [] ->
        {:ok, Enum.map(items, &item_to_json(&1, resource, context))}

      [invalid | _] ->
        failure(
          resource,
          "invalid contents",
          "#{source} #{inspect(invalid)}, which isn't text (valid UTF-8), a binary, " <>
            "or an item built with AshAi.McpResource.Contents.text/2 or blob/2"
        )
    end
  end

  defp valid_item?(%Text{text: text} = item) when is_binary(text),
    do: String.valid?(text) and valid_item_opts?(item)

  defp valid_item?(%Blob{data: data} = item) when is_binary(data), do: valid_item_opts?(item)
  defp valid_item?(_item), do: false

  defp valid_item_opts?(%{uri: uri, mime_type: mime_type, meta: meta}) do
    (is_nil(uri) or is_binary(uri)) and (is_nil(mime_type) or is_binary(mime_type)) and
      (is_nil(meta) or (is_map(meta) and not is_struct(meta)))
  end

  defp item_to_json(item, resource, context) do
    %{"uri" => item.uri || context.uri}
    |> put_present("mimeType", item.mime_type || resource.mime_type)
    |> put_present("_meta", item.meta && item.meta |> Jason.encode!() |> Jason.decode!())
    |> put_data(item)
  end

  defp put_data(json, %Text{text: text}), do: Map.put(json, "text", text)
  defp put_data(json, %Blob{data: data}), do: Map.put(json, "blob", Base.encode64(data))

  defp put_present(map, _key, nil), do: map
  defp put_present(map, key, value), do: Map.put(map, key, value)

  # The client gets a short reason; the log gets the details
  defp failure(resource, reason, details) do
    Logger.error("Reading mcp_resource #{inspect(resource.name)} failed: #{details}")
    {:error, "Failed to build the resource's contents: #{reason}"}
  end
end

defmodule AshAi.McpResource.Contents.Function do
  @moduledoc false
  use AshAi.McpResource.Contents

  @impl true
  def contents(result, [fun: {m, f, a}], context), do: apply(m, f, [result, context | a])
  def contents(result, [fun: fun], context), do: fun.(result, context)
end
