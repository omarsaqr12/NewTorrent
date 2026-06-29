"""A small, dependency-free bencode codec.

Bencode is the serialization format used throughout the BitTorrent protocol
(``.torrent`` files and tracker responses). This module implements both
directions of the codec from scratch:

* :func:`decode` parses a bencoded byte string into Python objects.
* :func:`encode` serializes Python objects back into bencode.

The encoder is deliberately careful about dictionaries: BitTorrent requires
keys to be emitted in lexicographic order so that the SHA-1 ``info`` hash is
reproducible across implementations.
"""

from __future__ import annotations

from typing import Tuple, Union

Bencodable = Union[int, bytes, str, list, dict]


def decode(data: bytes) -> Bencodable:
    """Decode a complete bencoded byte string into Python objects.

    Byte strings are returned as ``bytes`` (the protocol is binary-safe, e.g.
    piece hashes are raw 20-byte SHA-1 digests). Integers, lists and dicts map
    to their natural Python equivalents.
    """
    value, index = _decode_at(data, 0)
    if index != len(data):
        raise ValueError("Trailing data after top-level bencode value")
    return value


def _decode_at(data: bytes, index: int) -> Tuple[Bencodable, int]:
    """Decode the value starting at ``index`` and return ``(value, next)``."""
    prefix = data[index]

    if prefix == ord("i"):  # integer: i<number>e
        end = data.index(b"e", index)
        return int(data[index + 1 : end]), end + 1

    if ord("0") <= prefix <= ord("9"):  # byte string: <length>:<bytes>
        colon = data.index(b":", index)
        length = int(data[index:colon])
        start = colon + 1
        return data[start : start + length], start + length

    if prefix == ord("l"):  # list: l<items>e
        index += 1
        items = []
        while data[index] != ord("e"):
            item, index = _decode_at(data, index)
            items.append(item)
        return items, index + 1

    if prefix == ord("d"):  # dict: d<key><value>...e
        index += 1
        result = {}
        while data[index] != ord("e"):
            key, index = _decode_at(data, index)
            value, index = _decode_at(data, index)
            # Keys are byte strings; decode to str for ergonomic access.
            result[key.decode() if isinstance(key, bytes) else key] = value
        return result, index + 1

    raise ValueError(f"Invalid bencode prefix {prefix!r} at index {index}")


def encode(value: Bencodable) -> bytes:
    """Serialize a Python object into a bencoded byte string."""
    if isinstance(value, bool):
        raise TypeError("Booleans are not valid bencode values")

    if isinstance(value, int):
        return b"i" + str(value).encode() + b"e"

    if isinstance(value, bytes):
        return str(len(value)).encode() + b":" + value

    if isinstance(value, str):
        encoded = value.encode()
        return str(len(encoded)).encode() + b":" + encoded

    if isinstance(value, list):
        return b"l" + b"".join(encode(item) for item in value) + b"e"

    if isinstance(value, dict):
        out = b"d"
        for key in sorted(value):
            key_bytes = key.encode() if isinstance(key, str) else key
            out += encode(key_bytes) + encode(value[key])
        return out + b"e"

    raise TypeError(f"Unsupported type for bencode: {type(value).__name__}")
