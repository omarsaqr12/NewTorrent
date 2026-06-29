"""Command-line interface for the BitTorrent client.

Usage::

    python -m app.main decode <bencoded-string>
    python -m app.main info <file.torrent>
    python -m app.main peers <file.torrent>
    python -m app.main handshake <file.torrent> <ip:port>
    python -m app.main download_piece -o <output> <file.torrent> <index>
    python -m app.main download -o <output> <file.torrent>
"""

from __future__ import annotations

import json
import sys
from typing import List

from . import bencode, download
from .peer import PeerConnection
from .torrent import Torrent
from .tracker import PEER_ID, get_peers


def _to_json(value):
    """Make bencode output JSON-serializable (byte strings become text)."""
    if isinstance(value, bytes):
        try:
            return value.decode()
        except UnicodeDecodeError:
            return value.hex()
    raise TypeError(f"Type not serializable: {type(value).__name__}")


def cmd_decode(args: List[str]) -> None:
    decoded = bencode.decode(args[0].encode())
    print(json.dumps(decoded, default=_to_json))


def cmd_info(args: List[str]) -> None:
    torrent = Torrent.from_file(args[0])
    print(f"Tracker URL: {torrent.announce}")
    print(f"Length: {torrent.length}")
    print(f"Info Hash: {torrent.info_hash.hex()}")
    print(f"Piece Length: {torrent.piece_length}")
    print("Piece Hashes:")
    for piece_hash in torrent.piece_hashes:
        print(piece_hash.hex())


def cmd_peers(args: List[str]) -> None:
    torrent = Torrent.from_file(args[0])
    for peer in get_peers(torrent):
        print(peer)


def cmd_handshake(args: List[str]) -> None:
    torrent = Torrent.from_file(args[0])
    ip, port = args[1].rsplit(":", 1)
    with PeerConnection(ip, int(port), torrent.info_hash, PEER_ID) as conn:
        print(f"Peer ID: {conn.remote_peer_id.hex()}")


def cmd_download_piece(args: List[str]) -> None:
    output, torrent_path, index = _parse_output_args(args, extra=1)
    torrent = Torrent.from_file(torrent_path)
    peers = get_peers(torrent)
    data = download.download_piece(torrent, peers, int(index[0]))
    with open(output, "wb") as handle:
        handle.write(data)
    print(f"Piece {index[0]} downloaded to {output}.")


def cmd_download(args: List[str]) -> None:
    output, torrent_path, _ = _parse_output_args(args, extra=0)
    torrent = Torrent.from_file(torrent_path)
    peers = get_peers(torrent)
    download.download_file(torrent, peers, output)
    print(f"Downloaded {torrent_path} to {output}.")


def _parse_output_args(args: List[str], extra: int):
    """Parse ``-o <output> <torrent> [extra...]`` and return the parts."""
    if not args or args[0] != "-o":
        raise SystemExit("Expected: -o <output> <file.torrent> ...")
    output = args[1]
    torrent_path = args[2]
    extras = args[3 : 3 + extra]
    return output, torrent_path, extras


COMMANDS = {
    "decode": cmd_decode,
    "info": cmd_info,
    "peers": cmd_peers,
    "handshake": cmd_handshake,
    "download_piece": cmd_download_piece,
    "download": cmd_download,
}


def main(argv: List[str] | None = None) -> None:
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] not in COMMANDS:
        commands = ", ".join(COMMANDS)
        raise SystemExit(f"Usage: python -m app.main <{commands}> ...")
    COMMANDS[argv[0]](argv[1:])


if __name__ == "__main__":
    main()
