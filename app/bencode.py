"""Small, binary-safe bencode codec for canonical BitTorrent v1 metainfo."""

from __future__ import annotations

from typing import Tuple, Union

Bencodable = Union[int, bytes, str, list, dict]


def decode(data: bytes) -> Bencodable:
    """Decode a complete bencoded value, rejecting malformed or trailing data.

    Values remain bytes; dictionary keys are decoded as UTF-8 strings for the
    client-facing torrent/tracker APIs. Noncanonical encodings are rejected so
    re-encoding a parsed info dictionary cannot silently change its info hash.
    """
    value, end = _decode_at(data, 0)
    if end != len(data):
        raise ValueError("Trailing data after top-level bencode value")
    return value


def _decode_at(data: bytes, index: int) -> Tuple[Bencodable, int]:
    if index >= len(data):
        raise ValueError("Truncated bencode value")
    prefix = data[index]

    if prefix == ord("i"):
        end = data.find(b"e", index + 1)
        if end < 0:
            raise ValueError("Unterminated bencode integer")
        raw = data[index + 1:end]
        digits = raw[1:] if raw.startswith(b"-") else raw
        if (not digits or not digits.isdigit() or
                (len(digits) > 1 and digits.startswith(b"0")) or raw == b"-0"):
            raise ValueError("Invalid or noncanonical bencode integer")
        return int(raw), end + 1

    if ord("0") <= prefix <= ord("9"):
        colon = data.find(b":", index)
        if colon < 0:
            raise ValueError("Missing bencode byte-string separator")
        raw_length = data[index:colon]
        if (not raw_length.isdigit() or
                (len(raw_length) > 1 and raw_length.startswith(b"0"))):
            raise ValueError("Invalid or noncanonical byte-string length")
        length = int(raw_length)
        start = colon + 1
        end = start + length
        if end > len(data):
            raise ValueError("Truncated bencode byte string")
        return data[start:end], end

    if prefix == ord("l"):
        items = []
        index += 1
        while True:
            if index >= len(data):
                raise ValueError("Unterminated bencode list")
            if data[index] == ord("e"):
                return items, index + 1
            item, index = _decode_at(data, index)
            items.append(item)

    if prefix == ord("d"):
        result = {}
        previous_key: bytes | None = None
        index += 1
        while True:
            if index >= len(data):
                raise ValueError("Unterminated bencode dictionary")
            if data[index] == ord("e"):
                return result, index + 1
            key, index = _decode_at(data, index)
            if not isinstance(key, bytes) or (previous_key is not None and key <= previous_key):
                raise ValueError("Dictionary keys must be unique, sorted byte strings")
            previous_key = key
            value, index = _decode_at(data, index)
            try:
                result[key.decode("utf-8")] = value
            except UnicodeDecodeError as error:
                raise ValueError("Dictionary key is not UTF-8") from error

    raise ValueError(f"Invalid bencode prefix {prefix!r} at index {index}")


def encode(value: Bencodable) -> bytes:
    """Encode integers, byte strings, lists and dictionaries canonically."""
    if isinstance(value, bool):
        raise TypeError("Booleans are not valid bencode values")
    if isinstance(value, int):
        return b"i" + str(value).encode("ascii") + b"e"
    if isinstance(value, bytes):
        return str(len(value)).encode("ascii") + b":" + value
    if isinstance(value, str):
        return encode(value.encode("utf-8"))
    if isinstance(value, list):
        return b"l" + b"".join(encode(item) for item in value) + b"e"
    if isinstance(value, dict):
        encoded_keys = []
        for key, item in value.items():
            if not isinstance(key, (str, bytes)):
                raise TypeError("Bencode dictionary keys must be text or bytes")
            encoded_keys.append((key.encode("utf-8") if isinstance(key, str) else key, item))
        encoded_keys.sort(key=lambda pair: pair[0])
        if any(encoded_keys[i][0] == encoded_keys[i - 1][0]
               for i in range(1, len(encoded_keys))):
            raise ValueError("Duplicate dictionary key after UTF-8 encoding")
        return b"d" + b"".join(encode(key) + encode(item) for key, item in encoded_keys) + b"e"
    raise TypeError(f"Unsupported type for bencode: {type(value).__name__}")
