defmodule Abrupt.Varstr do
  alias Abrupt.Varint

  @doc """
  Serialzie variable length string. Serialization rules can be found at [Bitcoin protocol document](https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_string)
  """
  def serialize(str) do
    (byte_size(str) |> Varint.serialize()) <> str
  end

  def deserialize(data) do
    {string_size, data} = Varint.deserialize(data)
    <<string::bytes-size(string_size), data::binary>> = data
    {string, data}
  end
end
