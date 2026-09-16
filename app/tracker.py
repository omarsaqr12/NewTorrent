"""HTTP tracker announcement and compact IPv4 peer discovery (BEP 23)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

import requests

from . import bencode
from .torrent import Torrent

PEER_ID = b"-PC0001-123456789012"
PORT = 6881
PEER_ENTRY_LEN = 6


@dataclass(frozen=True)
class Peer:
    ip: str
    port: int

    def __str__(self) -> str:
        return f"{self.ip}:{self.port}"


def get_peers(torrent: Torrent) -> List[Peer]:
    """Announce to an HTTP tracker and parse compact IPv4 peers."""
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
    if not isinstance(body, dict):
        raise ValueError("Tracker response is not a dictionary")
    if "failure reason" in body:
        raise RuntimeError(f"Tracker error: {body['failure reason']!r}")
    peers = body.get("peers")
    if not isinstance(peers, bytes):
        raise ValueError("Tracker did not return supported compact IPv4 peers")
    return _parse_compact_peers(peers)


def _parse_compact_peers(blob: bytes) -> List[Peer]:
    if len(blob) % PEER_ENTRY_LEN:
        raise ValueError("Compact peer list contains an incomplete six-byte entry")
    peers = []
    for offset in range(0, len(blob), PEER_ENTRY_LEN):
        chunk = blob[offset:offset + PEER_ENTRY_LEN]
        port = int.from_bytes(chunk[4:6], "big")
        if port == 0:
            raise ValueError("Compact peer entry uses an invalid port")
        peers.append(Peer(".".join(str(b) for b in chunk[:4]), port))
    return peers
