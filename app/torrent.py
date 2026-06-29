"""Parsing and modelling of ``.torrent`` metainfo files."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import List

from . import bencode

PIECE_HASH_LEN = 20  # Each piece hash is a raw SHA-1 digest.


@dataclass
class Torrent:
    """A parsed single-file ``.torrent`` and the values derived from it."""

    announce: str
    name: str
    length: int
    piece_length: int
    piece_hashes: List[bytes]
    info_hash: bytes

    @classmethod
    def from_file(cls, path: str) -> "Torrent":
        with open(path, "rb") as handle:
            return cls.from_bytes(handle.read())

    @classmethod
    def from_bytes(cls, raw: bytes) -> "Torrent":
        meta = bencode.decode(raw)
        info = meta["info"]

        pieces = info["pieces"]
        if len(pieces) % PIECE_HASH_LEN != 0:
            raise ValueError("Corrupt torrent: 'pieces' is not a multiple of 20")
        piece_hashes = [
            pieces[i : i + PIECE_HASH_LEN]
            for i in range(0, len(pieces), PIECE_HASH_LEN)
        ]

        return cls(
            announce=meta["announce"].decode(),
            name=info["name"].decode(),
            length=info["length"],
            piece_length=info["piece length"],
            piece_hashes=piece_hashes,
            # The info hash is the SHA-1 of the bencoded `info` dict and is the
            # torrent's canonical identifier on trackers and in handshakes.
            info_hash=hashlib.sha1(bencode.encode(info)).digest(),
        )

    @property
    def num_pieces(self) -> int:
        return len(self.piece_hashes)

    def piece_size(self, index: int) -> int:
        """Return the length of piece ``index`` (the last piece is shorter)."""
        if index < self.num_pieces - 1:
            return self.piece_length
        return self.length - self.piece_length * (self.num_pieces - 1)
