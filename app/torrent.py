"""Parse and validate canonical single-file BitTorrent v1 metainfo."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import List

from . import bencode

PIECE_HASH_LEN = 20


@dataclass
class Torrent:
    """A parsed single-file torrent and its piece layout."""

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
        if not isinstance(meta, dict) or not isinstance(meta.get("info"), dict):
            raise ValueError("Torrent must contain an info dictionary")
        info = meta["info"]
        if "files" in info or info.get("meta version") == 2:
            raise ValueError("Only single-file BitTorrent v1 torrents are supported")
        pieces = info.get("pieces")
        length = info.get("length")
        piece_length = info.get("piece length")
        name = info.get("name")
        announce = meta.get("announce")
        if (not isinstance(pieces, bytes) or
                not isinstance(length, int) or isinstance(length, bool) or length < 0 or
                not isinstance(piece_length, int) or isinstance(piece_length, bool) or piece_length <= 0 or
                not isinstance(name, bytes) or not isinstance(announce, bytes)):
            raise ValueError("Invalid or missing single-file torrent fields")
        if len(pieces) % PIECE_HASH_LEN:
            raise ValueError("Corrupt torrent: piece hashes are not 20 bytes each")
        expected_count = (length + piece_length - 1) // piece_length
        if len(pieces) // PIECE_HASH_LEN != expected_count:
            raise ValueError("Torrent piece count does not match file length")
        try:
            decoded_name = name.decode("utf-8")
            decoded_announce = announce.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("Torrent name or announce URL is not UTF-8") from error
        return cls(
            announce=decoded_announce,
            name=decoded_name,
            length=length,
            piece_length=piece_length,
            piece_hashes=[pieces[i:i + PIECE_HASH_LEN]
                          for i in range(0, len(pieces), PIECE_HASH_LEN)],
            info_hash=hashlib.sha1(bencode.encode(info)).digest(),
        )

    @property
    def num_pieces(self) -> int:
        return len(self.piece_hashes)

    def piece_size(self, index: int) -> int:
        if index < 0 or index >= self.num_pieces:
            raise IndexError(f"Piece index {index} is out of range")
        if index < self.num_pieces - 1:
            return self.piece_length
        return self.length - self.piece_length * index
