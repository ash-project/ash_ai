defmodule AshAiTest do
  use ExUnit.Case
  doctest AshAi

  test "greets the world" do
    assert AshAi.hello() == :world
  end
end
