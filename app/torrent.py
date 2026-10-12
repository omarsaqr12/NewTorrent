"""Canonical v1 metainfo and a safe logical concatenated file layout."""
from __future__ import annotations

import hashlib
import unicodedata
from dataclasses import dataclass, field
from pathlib import PureWindowsPath
from urllib.parse import urlsplit

from . import bencode

MAX_METAINFO = 8 * 1024 * 1024
MAX_PIECE = 16 * 1024 * 1024
MAX_FILES = 10000


def safe_component(raw: bytes) -> str:
    if not isinstance(raw, bytes):
        raise ValueError("Path component must be a UTF-8 byte string")
    name = raw.decode("utf-8")
    if (not name or name in (".", "..") or any(c in name for c in '/\\:<>"|?*')
            or any(ord(c) < 32 for c in name) or name.endswith((" ", "."))
            or PureWindowsPath(name).is_reserved()):
        raise ValueError("Unsafe torrent path component")
    return name


def tracker_url(raw: bytes) -> str:
    if not isinstance(raw, bytes):
        raise ValueError("Tracker URL must be bytes")
    value = raw.decode("utf-8")
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https", "udp") or not parsed.hostname:
        raise ValueError("Unsupported tracker URL")
    if parsed.fragment or parsed.username or parsed.password:
        raise ValueError("Tracker URL fragments/userinfo are unsupported")
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError("Invalid tracker port")
    return value


@dataclass(frozen=True)
class FileEntry:
    path: tuple[str, ...]
    length: int
    offset: int


@dataclass
class Torrent:
    announce: str
    name: str
    length: int
    piece_length: int
    piece_hashes: list[bytes]
    info_hash: bytes
    files: list[FileEntry] = field(default_factory=list)
    tiers: list[list[str]] = field(default_factory=list)
    multi_file: bool = False

    @classmethod
    def from_file(cls, path: str) -> Torrent:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_METAINFO + 1)
        return cls.from_bytes(raw)

    @classmethod
    def from_bytes(cls, raw: bytes) -> Torrent:
        meta = bencode.decode(raw, max_size=MAX_METAINFO)
        if not isinstance(meta, dict) or not isinstance(meta.get("info"), dict):
            raise ValueError("Torrent must contain an info dictionary")
        info = meta["info"]
        if "meta version" in info:
            raise ValueError("Only BitTorrent v1 is supported")
        name = safe_component(info.get("name"))
        size, pieces = info.get("piece length"), info.get("pieces")
        if (type(size) is not int or not 0 < size <= MAX_PIECE
                or not isinstance(pieces, bytes) or len(pieces) % 20):
            raise ValueError("Invalid piece length or hashes")
        if ("length" in info) == ("files" in info):
            raise ValueError("Exactly one of length/files is required")
        files, total = [], 0
        multi = "files" in info
        entries = info["files"] if multi else [{"length": info["length"], "path": [info["name"]]}]
        if not isinstance(entries, list) or not entries or len(entries) > MAX_FILES:
            raise ValueError("Invalid or excessive file list")
        paths = set()
        for entry in entries:
            if not isinstance(entry, dict) or type(entry.get("length")) is not int or entry["length"] < 0:
                raise ValueError("Invalid file length")
            parts = entry.get("path")
            if not isinstance(parts, list) or not parts or len(parts) > 64:
                raise ValueError("Invalid file path")
            path = tuple(safe_component(p) for p in parts)
            folded = tuple(unicodedata.normalize('NFC', p).casefold() for p in path)
            if folded in paths:
                raise ValueError("Duplicate file path")
            paths.add(folded)
            files.append(FileEntry(path, entry["length"], total))
            total += entry["length"]
            if total > 2**63 - 1:
                raise ValueError("Torrent length exceeds signed 64-bit storage limit")
        for path in paths:
            if any(path[:i] in paths for i in range(1, len(path))):
                raise ValueError("Conflicting file/directory paths")
        if len(pieces) // 20 != (total + size - 1) // size:
            raise ValueError("Torrent piece count does not match layout")
        if "announce-list" in meta:
            tiers_raw = meta["announce-list"]
            if not isinstance(tiers_raw, list) or not tiers_raw or len(tiers_raw) > 32:
                raise ValueError("Invalid tracker tiers")
            tiers = []
            count = 0
            for tier in tiers_raw:
                if not isinstance(tier, list) or not tier:
                    raise ValueError("Invalid tracker tier")
                count += len(tier)
                if count > 128:
                    raise ValueError("Too many trackers")
                tiers.append(list(dict.fromkeys(tracker_url(url) for url in tier)))
            announce = tiers[0][0]
        else:
            announce = tracker_url(meta.get("announce"))
            tiers = [[announce]]
        return cls(announce, name, total, size,
                   [pieces[i:i + 20] for i in range(0, len(pieces), 20)],
                   hashlib.sha1(bencode.encode(info)).digest(), files, tiers, multi)

    @property
    def num_pieces(self) -> int:
        return len(self.piece_hashes)

    @property
    def layout(self) -> list[FileEntry]:
        return self.files or [FileEntry((self.name,), self.length, 0)]

    def piece_size(self, index: int) -> int:
        if not 0 <= index < self.num_pieces:
            raise IndexError(f"Piece index {index} is out of range")
        return min(self.piece_length, self.length - self.piece_length * index)
