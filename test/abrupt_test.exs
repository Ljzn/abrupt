defmodule AbruptTest do
  use ExUnit.Case
  doctest Abrupt

  test "greets the world" do
    assert Abrupt.hello() == :world
  end
end
