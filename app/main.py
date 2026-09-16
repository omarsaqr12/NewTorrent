"""Command-line interface for the single-file BitTorrent v1 client."""

from __future__ import annotations

import json
import sys
from typing import List

from . import bencode, download
from .peer import PeerConnection
from .torrent import Torrent
from .tracker import PEER_ID, get_peers


def _to_json(value):
    if isinstance(value, bytes):
        try:
            return value.decode()
        except UnicodeDecodeError:
            return value.hex()
    raise TypeError(f"Type not serializable: {type(value).__name__}")


def _require_args(args: List[str], count: int, usage: str) -> None:
    if len(args) != count:
        raise SystemExit(f"Usage: python -m app.main {usage}")


def cmd_decode(args: List[str]) -> None:
    _require_args(args, 1, "decode <bencoded-string>")
    print(json.dumps(bencode.decode(args[0].encode()), default=_to_json))


def cmd_info(args: List[str]) -> None:
    _require_args(args, 1, "info <file.torrent>")
    torrent = Torrent.from_file(args[0])
    print(f"Tracker URL: {torrent.announce}")
    print(f"Length: {torrent.length}")
    print(f"Info Hash: {torrent.info_hash.hex()}")
    print(f"Piece Length: {torrent.piece_length}")
    print("Piece Hashes:")
    for piece_hash in torrent.piece_hashes:
        print(piece_hash.hex())


def cmd_peers(args: List[str]) -> None:
    _require_args(args, 1, "peers <file.torrent>")
    torrent = Torrent.from_file(args[0])
    for peer in get_peers(torrent):
        print(peer)


def cmd_handshake(args: List[str]) -> None:
    _require_args(args, 2, "handshake <file.torrent> <ip:port>")
    torrent = Torrent.from_file(args[0])
    ip, port = args[1].rsplit(":", 1)
    with PeerConnection(ip, int(port), torrent.info_hash, PEER_ID) as conn:
        print(f"Peer ID: {conn.remote_peer_id.hex()}")


def cmd_download_piece(args: List[str]) -> None:
    output, torrent_path, index = _parse_output_args(args, extra=1)
    torrent = Torrent.from_file(torrent_path)
    data = download.download_piece(torrent, get_peers(torrent), int(index[0]))
    with open(output, "wb") as handle:
        handle.write(data)
    print(f"Piece {index[0]} downloaded to {output}.")


def cmd_download(args: List[str]) -> None:
    output, torrent_path, _ = _parse_output_args(args, extra=0)
    torrent = Torrent.from_file(torrent_path)
    download.download_file(torrent, get_peers(torrent), output)
    print(f"Downloaded {torrent_path} to {output}.")


def _parse_output_args(args: List[str], extra: int):
    if len(args) != 3 + extra or args[0] != "-o" or not args[1]:
        suffix = " <index>" if extra else ""
        raise SystemExit(f"Usage: python -m app.main download{'_piece' if extra else ''} -o <output> <file.torrent>{suffix}")
    return args[1], args[2], args[3:]


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
