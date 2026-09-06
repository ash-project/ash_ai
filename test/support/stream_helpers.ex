# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Test.StreamHelpers do
  @moduledoc false

  def metadata_handle(metadata \\ %{}) do
    {:ok, handle} = ReqLLM.StreamResponse.MetadataHandle.start_link(fn -> metadata end)
    handle
  end
end
