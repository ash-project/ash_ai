# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

if Code.ensure_loaded?(Plug) do
  defmodule AshAi.Oauth.Revoke do
    @moduledoc """
    Plug implementing RFC 7009 token revocation.

    Mount at `POST /oauth/revoke`. Always returns 200 per the RFC, regardless
    of whether the token was found.
    """

    @behaviour Plug
    import Plug.Conn
    require Ash.Query

    alias AshAi.Oauth.Config

    @impl Plug
    def init(opts), do: Keyword.fetch!(opts, :otp_app)

    @impl Plug
    def call(%{method: "POST"} = conn, otp_app) do
      params = conn.params || %{}
      token = params["token"]
      client_id = params["client_id"]

      if is_binary(token) and is_binary(client_id) do
        revoke(otp_app, token, client_id)
      end

      # RFC 7009 §2.2: respond 200 regardless of whether the token was
      # found, to avoid leaking which tokens are valid.
      conn
      |> put_resp_header("cache-control", "no-store")
      |> send_resp(200, "")
      |> halt()
    end

    def call(conn, _), do: send_resp(conn, 405, "") |> halt()

    # Only revoke if the presented client_id matches the row's client_id.
    # Public clients have no other auth credential; pairing the token with
    # its issuing client is the minimum check RFC 7009 §2.1 requires.
    defp revoke(otp_app, token, client_id) do
      hash = :crypto.hash(:sha256, token) |> Base.encode16(case: :lower)

      Config.refresh_token_resource(otp_app)
      |> Ash.Query.filter(token_hash == ^hash and client_id == ^client_id)
      |> Ash.read_one(authorize?: false)
      |> case do
        {:ok, %{} = row} ->
          row
          |> Ash.Changeset.for_update(:revoke, %{})
          |> Ash.update(authorize?: false)

        _ ->
          :noop
      end
    end
  end
end
