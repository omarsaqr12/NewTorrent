"""Tracker (HTTP) communication: announce and peer discovery."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

import requests

from . import bencode
from .torrent import Torrent

PEER_ID = b"-PC0001-123456789012"  # 20 bytes, our client's identity.
PORT = 6881
PEER_ENTRY_LEN = 6  # 4 bytes IPv4 + 2 bytes port (compact peer format).


@dataclass(frozen=True)
class Peer:
    ip: str
    port: int

    def __str__(self) -> str:
        return f"{self.ip}:{self.port}"


def get_peers(torrent: Torrent) -> List[Peer]:
    """Announce to the tracker and return the list of advertised peers."""
    params = {
        "info_hash": torrent.info_hash,
        "peer_id": PEER_ID,
        "port": PORT,
        "uploaded": 0,
        "downloaded": 0,
        "left": torrent.length,
        "compact": 1,
    }
    response = requests.get(torrent.announce, params=params, timeout=15)
    response.raise_for_status()

    body = bencode.decode(response.content)
    if b"failure reason" in body or "failure reason" in body:
        reason = body.get("failure reason", b"unknown")
        raise RuntimeError(f"Tracker error: {reason!r}")

    return _parse_compact_peers(body["peers"])


def _parse_compact_peers(blob: bytes) -> List[Peer]:
    peers = []
    for offset in range(0, len(blob), PEER_ENTRY_LEN):
        chunk = blob[offset : offset + PEER_ENTRY_LEN]
        ip = ".".join(str(b) for b in chunk[:4])
        port = int.from_bytes(chunk[4:6], "big")
        peers.append(Peer(ip, port))
    return peers
