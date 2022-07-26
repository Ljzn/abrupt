defmodule Abrupt.Varint do
  @doc """
  Serialzie variable length integer. Serialization rules can be found at
  [Bitcoin protocol document](https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer)
  """

  def serialize(int) when is_integer(int) and int < 0xFD do
    <<int::unsigned-little-integer-size(8)>>
  end

  def serialize(int) when is_integer(int) and int <= 0xFFFF do
    <<0xFD, int::unsigned-little-integer-size(16)>>
  end

  def serialize(int) when is_integer(int) and int <= 0xFFFF_FFFF do
    <<0xFE, int::unsigned-little-integer-size(32)>>
  end

  def serialize(int) when is_integer(int) and int > 0xFFFF_FFFF do
    <<0xFF, int::unsigned-little-integer-size(64)>>
  end

  def deserialize(<<0xFD, data::unsigned-little-integer-size(16), remaining::binary>>) do
    {data, remaining}
  end

  def deserialize(<<0xFE, data::unsigned-little-integer-size(32), remaining::binary>>) do
    {data, remaining}
  end

  def deserialize(<<0xFF, data::unsigned-native-integer-size(64), remaining::binary>>) do
    {data, remaining}
  end

  def deserialize(<<data::unsigned-integer-size(8), remaining::binary>>) do
    {data, remaining}
  end
end
