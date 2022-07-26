defmodule Abrupt do
  @moduledoc """
  Documentation for `Abrupt`.
  """

  def read_part() do
    File.stream!("./data/blk.dat", [], 1024)
    |> Stream.map(fn chunk -> chunk end)
    |> Enum.into([])
    |> Enum.reduce(decode_init(), fn bin, state ->
      decode_update(state, bin)
    end)
  end

  def decode_init(data \\ "") do
    {:abrupt, data, [type: :block], []}
  end

  def decode_update({:abrupt, rest, stack, alt}, bin) do
    decode(rest <> bin, stack, alt)
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
      ],
      hash: true
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
      ],
      hash: true
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

  def decode(bin, [:hash_start | t], alt) do
    decode(bin, t, [{:hash, :crypto.hash_init(:sha256)} | alt])
  end

  def decode(bin, [:hash_stop, {:collect, _} = c | t], [{:hash, hash} | alt]) do
    decode(bin, [c, {:tag, :hash, final_hash(hash)} | t], alt)
  end

  def decode(bin, [{:tag, k, v} | t], [ah | at]) do
    ah =
      if is_map(ah) do
        Map.put(ah, k, v)
      else
        %{:data => ah, k => v}
      end

    decode(bin, t, [ah | at])
  end

  def decode(bin, [{:type, type} | t] = stack, alt) do
    case parse(bin, type) do
      :abrupt ->
        {:abrupt, bin, stack, alt}

      {:op, ops} when is_list(ops) ->
        decode(bin, ops ++ t, alt)

      {:op, op} ->
        decode(bin, [op | t], alt)

      {a, rest} ->
        case alt do
          [{:hash, hash} | alt] ->
            consumed =
              case rest do
                <<>> -> bin
                _ -> String.trim_trailing(bin, rest)
              end

            decode(rest, t, [{:hash, hash(hash, consumed)}, a | alt])

          _ ->
            decode(rest, t, [a | alt])
        end
    end
  end

  def decode(bin, [{:collect, n} | t], alt) when is_integer(n) do
    case alt do
      [{:hash, hash} | alt] ->
        {collect, alt} = Enum.split(alt, n)
        decode(bin, t, [{:hash, hash}, Enum.reverse(collect) | alt])

      alt ->
        {collect, alt} = Enum.split(alt, n)
        decode(bin, t, [Enum.reverse(collect) | alt])
    end
  end

  def decode(bin, [{:alt, type} | t] = _stack, [ah | at] = _alt) when is_integer(ah) do
    decode(bin, [{ah, type}, {:collect, ah} | t], at)
  end

  def decode(bin, [{:alt, type} | t] = _stack, [{:hash, _} = ah1, ah2 | at] = _alt) do
    decode(bin, [{:alt, type} | t], [ah2, ah1 | at])
  end

  def decode(bin, [{0, _type} | t], alt) do
    decode(bin, t, alt)
  end

  # FIXME: optimize the bytes
  def decode(bin, [{n, type} | t], alt) when is_integer(n) do
    decode(bin, [{:type, type}, {n - 1, type} | t], alt)
  end

  def decode(<<>>, [], alt) do
    {:done, Enum.reverse(alt)}
  end

  ##############################################################

  # basic types

  def parse(<<a, rest::bytes>>, :byte) do
    {a, rest}
  end

  def parse(<<a::32-signed-little, rest::bytes>>, :int32) do
    {a, rest}
  end

  def parse(<<a::64-signed-little, rest::bytes>>, :int64) do
    {a, rest}
  end

  def parse(<<a::32-little, rest::bytes>>, :uint32) do
    {a, rest}
  end

  def parse(<<a::256-little, rest::bytes>>, :hash) do
    a = <<a::256-big>>
    {Base.encode16(a, case: :lower), rest}
  end

  # varint

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

  # complex types

  for %{type: type, name: name} = d <- @defs do
    hash = d[:hash]

    cond do
      is_list(type) ->
        def parse(_bin, unquote(name)) do
          content = Enum.map(unquote(type), fn x -> {:type, x} end)

          content =
            if unquote(hash) do
              [:hash_start] ++ content ++ [:hash_stop]
            else
              content
            end

          {
            :op,
            content ++ [{:collect, length(unquote(type))}]
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

  # vec

  def parse(_bin, {:vec, type}) do
    {
      :op,
      [{:type, :varint}, {:alt, type}]
    }
  end

  # not match

  def parse(_, _) do
    :abrupt
  end

  ## hashing

  def hash(a, b) do
    :crypto.hash_update(a, b)
  end

  def final_hash(hash) do
    <<a::256-little>> = :crypto.hash(:sha256, :crypto.hash_final(hash))
    Base.encode16(<<a::256-big>>, case: :lower)
  end
end
