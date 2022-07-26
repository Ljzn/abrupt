defmodule Abrupt do
  @moduledoc """
  Documentation for `Abrupt`.
  """

  def read_part(n) do
    File.stream!("./data/blk.dat", [], 1024)
    |> Stream.map(fn chunk -> chunk end)
    |> Stream.take(n)
    |> Enum.into(<<>>)
    |> decode([type: :block], [])
  end

  @defs [
    %{
      name: :block,
      type: [
        :block_header,
        {:vec, :tx}
      ]
    },
    %{
      name: :block_header,
      type: [
        :version,
        :hash_prev,
        :hash_merkle,
        :time,
        :bits,
        :nonce
      ]
    },
    %{
      name: :version,
      type: :int32
    },
    %{
      name: :hash_prev,
      type: :hash
    },
    %{
      name: :hash_merkle,
      type: :hash
    },
    %{
      name: :time,
      type: :uint32
    },
    %{
      name: :bits,
      type: :uint32
    },
    %{
      name: :nonce,
      type: :uint32
    },
    %{
      name: :tx,
      type: [
        :version,
        {:vec, :tx_in},
        {:vec, :tx_out},
        :lock_time
      ]
    },
    %{
      name: :tx_in,
      type: [
        :out_point,
        :script_sig,
        :sequence
      ]
    },
    %{
      name: :script_sig,
      type: {:vec, :byte}
    },
    %{
      name: :sequence,
      type: :uint32
    },
    %{
      name: :out_point,
      type: [
        :txid,
        :n
      ]
    },
    %{
      name: :txid,
      type: :hash
    },
    %{
      name: :n,
      type: :uint32
    },
    %{
      name: :lock_time,
      type: :uint32
    },
    %{
      name: :tx_out,
      type: [
        :value,
        :script_pub_key
      ]
    },
    %{
      name: :script_pub_key,
      type: {:vec, :byte}
    },
    %{
      name: :value,
      type: :int64
    }
  ]

  def decode(bin, [{:type, type} | t] = stack, alt) do
    case parse(bin, type) do
      :abrupt ->
        {:abrupt, bin, stack, alt}

      {:op, ops} when is_list(ops) ->
        decode(bin, ops ++ t, alt)

      {:op, op} ->
        decode(bin, [op | t], alt)

      {a, rest} ->
        decode(rest, t, [a | alt])
    end
  end

  def decode(bin, [{:collect, n} | t], alt) when is_integer(n) do
    {collect, alt} = Enum.split(alt, n)
    decode(bin, t, [collect | alt])
  end

  def decode(bin, [{:alt, type} | t] = _stack, [ah | at] = _alt) when is_integer(ah) do
    decode(bin, [{ah, type}, {:collect, ah} | t], at)
  end

  def decode(bin, [{0, _type} | t], alt) do
    decode(bin, t, alt)
  end

  # FIXME: optimize the bytes
  def decode(bin, [{n, type} | t], alt) when is_integer(n) do
    decode(bin, [{:type, type}, {n - 1, type} | t], alt)
  end

  def parse(<<a, rest::bytes>>, :byte) do
    {a, rest}
  end

  def parse(<<a::32-signed, rest::bytes>>, :int32) do
    {a, rest}
  end

  def parse(<<a::64-signed, rest::bytes>>, :int64) do
    {a, rest}
  end

  def parse(<<a::32, rest::bytes>>, :uint32) do
    {a, rest}
  end

  def parse(<<a::256-little, rest::bytes>>, :hash) do
    a = <<a::256-big>>
    {Base.encode16(a, case: :lower), rest}
  end

  def parse(<<a::8, rest::bytes>>, :varint) when a < 0xFD do
    {a, rest}
  end

  def parse(<<0xFD, a::16-little, rest::bytes>>, :varint) do
    {a, rest}
  end

  def parse(<<0xFE, a::32-little, rest::bytes>>, :varint) do
    {a, rest}
  end

  def parse(<<0xFF, a::64-little, rest::bytes>>, :varint) do
    {a, rest}
  end

  for %{type: type, name: name} <- @defs do
    cond do
      is_list(type) ->
        def parse(_bin, unquote(name)) do
          {
            :op,
            Enum.map(unquote(type), fn x -> {:type, x} end)
          }
        end

      true ->
        def parse(_bin, unquote(name)) do
          {
            :op,
            {:type, unquote(type)}
          }
        end
    end
  end

  def parse(_bin, {:vec, type}) do
    {
      :op,
      [{:type, :varint}, {:alt, type}]
    }
  end

  def parse(_, _) do
    :abrupt
  end
end
