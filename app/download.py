"""Public download API: persistent verified storage and bounded peer reactor."""
from __future__ import annotations

from pathlib import Path

from .engine import Engine, Options
from .peer import IntegrityError, PeerConnection
from .storage import Storage
from .torrent import Torrent
from .tracker import Announcer, Peer, TrackerService, new_peer_id


def download_piece(torrent: Torrent, peers: list[Peer], index: int) -> bytes:
    length = torrent.piece_size(index)
    peer_id = new_peer_id()
    last_error = None
    for peer in peers:
        try:
            with PeerConnection(peer.ip, peer.port, torrent.info_hash, peer_id) as conn:
                conn.num_pieces = torrent.num_pieces
                conn.prepare_download()
                conn.wait_available(index)
                return conn.download_piece(index, length, torrent.piece_hashes[index])
        except (OSError, IntegrityError, ConnectionError) as error:
            last_error = error
    raise RuntimeError(f"Could not download piece {index}: {last_error}")


def download_file(torrent: Torrent, peers: list[Peer] | None, output: str, *,
                  options: Options | None = None, resume: bool = True,
                  overwrite: bool = False, stop=None, progress=None,
                  tracker_timeout: float = 5):
    options = options or Options()
    options.validate(torrent)
    if peers == [] and torrent.num_pieces and not Path(output + '.newtorrent').exists():
        raise RuntimeError("No peers supplied")
    with Storage(torrent, output, resume=resume, overwrite=overwrite, stop=stop) as storage:
        service = None
        peer_id = new_peer_id()
        if peers is None and len(storage.verified) != torrent.num_pieces:
            service = TrackerService(Announcer(torrent, peer_id=peer_id,
                                               timeout=tracker_timeout, limit=options.max_discovery,
                                               stop=stop),
                                     left=torrent.length - sum(torrent.piece_size(i) for i in storage.verified))
            peers = service.take_peers()
        engine = Engine(torrent, storage, peers or [], options=options, peer_id=peer_id,
                        stop=stop, progress=progress, tracker=service)
        completed = False
        try:
            result = engine.run()
            completed = True
            return result
        finally:
            if service:
                service.close(engine.stats, completed)
