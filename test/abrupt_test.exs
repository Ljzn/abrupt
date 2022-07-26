defmodule AbruptTest do
  use ExUnit.Case
  import Abrupt

  test "greets the world" do
    filter = fn x ->
      x == Base.decode16!("76a914349f97087dbac1a574756d2eadff9d7df07ee93988ac", case: :lower)
    end

    File.stream!("./data/blk.dat", [], 1024)
    |> Stream.map(fn chunk -> chunk end)
    |> Enum.into([])
    |> Enum.reduce(decode_init(), fn bin, state ->
      case decode_update(state, bin) do
        {:abrupt, rest, stack, alt} ->
          alt = filter_alt(alt, filter)
          {:abrupt, rest, stack, alt}

        {:done, [[header, txs]]} ->
          [header, filter_alt(txs, filter)]
      end
    end)
    |> IO.inspect()
  end

  def filter_alt(alt, filter) do
    Enum.map(alt, fn
      %{data: [_, _, outputs, _]} = x ->
        if Enum.any?(outputs, fn [_, script] ->
             filter.(script)
           end) do
          x
        else
          nil
        end

      x ->
        x
    end)
  end
end
