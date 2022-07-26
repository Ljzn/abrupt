defmodule Abrupt do
  @moduledoc """
  Documentation for `Abrupt`.
  """

  @doc """

  """
  def decode_init(data \\ "") do
    {:abrupt, data, [type: :block], []}
  end

  @doc """

  """
  def decode_update({:abrupt, rest, stack, alt}, bin) do
    decode(rest <> bin, stack, alt)
  end

  @large_bytes_threshold 25

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
      type: {:vec, :byte},
      transformer: :only_p2pkh
    },
    %{
      name: :value,
      type: :int64
    }
  ]

  defp decode(bin, [:hash_start | t], alt) do
    decode(bin, t, [{:hash, :crypto.hash_init(:sha256)} | alt])
  end

  defp decode(bin, [:hash_stop, {:collect, _} = c | t], [{:hash, hash} | alt]) do
    decode(bin, [c, {:tag, :hash, final_hash(hash)} | t], alt)
  end

  defp decode(bin, [{:tag, k, v} | t], [ah | at]) do
    ah =
      if is_map(ah) do
        Map.put(ah, k, v)
      else
        %{:data => ah, k => v}
      end

    decode(bin, t, [ah | at])
  end

  defp decode(bin, [{:type, type} | t] = stack, alt) do
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

  defp decode(bin, [{:collect, n} | t], alt) when is_integer(n) do
    case alt do
      [{:hash, hash} | alt] ->
        {collect, alt} = Enum.split(alt, n)
        decode(bin, t, [{:hash, hash}, Enum.reverse(collect) | alt])

      alt ->
        {collect, alt} = Enum.split(alt, n)
        decode(bin, t, [Enum.reverse(collect) | alt])
    end
  end

  defp decode(bin, [{0, _type} | t], alt) do
    decode(bin, t, alt)
  end

  # FIXME: optimize the bytes
  defp decode(bin, [{n, type} | t], alt) when is_integer(n) do
    decode(bin, [{:type, type}, {n - 1, type} | t], alt)
  end

  defp decode(<<>>, [], alt) do
    {:done, Enum.reverse(alt)}
  end

  # edit alt

  defp decode(bin, [{:transform, f} | t], [{:hash, _} = ah1, ah2 | at]) do
    decode(bin, t, [ah1, apply(__MODULE__, f, [ah2]) | at])
  end

  defp decode(bin, [{:transform, f} | t], [ah | at]) do
    decode(bin, t, [apply(__MODULE__, f, [ah]) | at])
  end

  defp decode(bin, [:concat | t], [{:hash, _} = ah1, ah2, ah3 | at]) do
    decode(bin, t, [ah1, ah3 <> ah2 | at])
  end

  defp decode(bin, [:concat | t], [ah1, ah2 | at]) do
    decode(bin, t, [ah2 <> ah1 | at])
  end

  defp decode(bin, [{:alt, type} | t] = _stack, [ah | at] = _alt) when is_integer(ah) do
    case type do
      :byte ->
        decode(bin, [{:type, {:bytes, ah}} | t], at)

      _ ->
        decode(bin, [{ah, type}, {:collect, ah} | t], at)
    end
  end

  defp decode(bin, [{:alt, type} | t] = _stack, [{:hash, _} = ah1, ah2 | at] = _alt) do
    decode(bin, [{:alt, type} | t], [ah2, ah1 | at])
  end

  ##############################################################

  # basic types

  defp parse(_bin, {:bytes, 0}) do
    {:op, []}
  end

  defp parse(bin, {:bytes, n}) when byte_size(bin) > 0 do
    s = byte_size(bin)

    if s >= n do
      if n > @large_bytes_threshold do
        {"-", :binary.part(bin, n, s - n)}
      else
        {:binary.part(bin, 0, n), :binary.part(bin, n, s - n)}
      end
    else
      {:op,
       [
         {:type, {:bytes, s}},
         {:type, {:bytes, n - s}},
         :concat
       ]}
    end
  end

  defp parse(<<a::32-signed-little, rest::bytes>>, :int32) do
    {a, rest}
  end

  defp parse(<<a::64-signed-little, rest::bytes>>, :int64) do
    {a, rest}
  end

  defp parse(<<a::32-little, rest::bytes>>, :uint32) do
    {a, rest}
  end

  defp parse(<<a::256-little, rest::bytes>>, :hash) do
    a = <<a::256-big>>
    {Base.encode16(a, case: :lower), rest}
  end

  # varint

  defp parse(<<a::8, rest::bytes>>, :varint) when a < 0xFD do
    {a, rest}
  end

  defp parse(<<0xFD, a::16-little, rest::bytes>>, :varint) do
    {a, rest}
  end

  defp parse(<<0xFE, a::32-little, rest::bytes>>, :varint) do
    {a, rest}
  end

  defp parse(<<0xFF, a::64-little, rest::bytes>>, :varint) do
    {a, rest}
  end

  # complex types

  for %{type: type, name: name} = d <- @defs do
    hash = d[:hash]
    transformer = d[:transformer]

    cond do
      is_list(type) ->
        defp parse(_bin, unquote(name)) do
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
        defp parse(_bin, unquote(name)) do
          {
            :op,
            if unquote(transformer) do
              [{:type, unquote(type)}, {:transform, unquote(transformer)}]
            else
              {:type, unquote(type)}
            end
          }
        end
    end
  end

  # vec

  defp parse(_bin, {:vec, type}) do
    {
      :op,
      [{:type, :varint}, {:alt, type}]
    }
  end

  # not match

  defp parse(_, _) do
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

  # transformers

  def only_p2pkh(<<0x76, 0xA9, 0x14, _::160, 0x88, 0xAC>> = script) do
    script
  end

  def only_p2pkh(_) do
    nil
  end
end
