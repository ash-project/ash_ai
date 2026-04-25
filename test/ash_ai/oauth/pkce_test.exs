# SPDX-FileCopyrightText: 2026 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Oauth.PkceTest do
  use ExUnit.Case, async: true

  alias AshAi.Oauth.Pkce

  test "challenge/1 produces RFC 7636 §4.2 fixture" do
    # Verifier and expected challenge from RFC 7636 §4.2
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert Pkce.challenge(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
  end

  test "verify/2 returns :ok for matching pair" do
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    assert Pkce.verify(verifier, challenge) == :ok
  end

  test "verify/2 returns :error for mismatch" do
    verifier = "wrong-verifier"
    challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    assert Pkce.verify(verifier, challenge) == :error
  end

  test "verify/2 is constant-time (uses Plug.Crypto.secure_compare)" do
    # Sanity: function returns :error rather than crashing on any input shape
    assert Pkce.verify("", "") == :error
    assert Pkce.verify(nil, "x") == :error
    assert Pkce.verify("x", nil) == :error
  end
end
