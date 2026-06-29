"""Download orchestration: single-piece and concurrent whole-file downloads."""

from __future__ import annotations

import queue
import threading
from typing import BinaryIO, List, Set

from .peer import IntegrityError, PeerConnection
from .torrent import Torrent
from .tracker import PEER_ID, Peer

MAX_WORKERS = 8  # Upper bound on simultaneous peer connections.


def download_piece(torrent: Torrent, peers: List[Peer], index: int) -> bytes:
    """Download and verify a single piece, trying peers until one succeeds."""
    last_error: Exception | None = None
    for peer in peers:
        try:
            with PeerConnection(peer.ip, peer.port, torrent.info_hash, PEER_ID) as conn:
                conn.prepare_download()
                return conn.download_piece(
                    index, torrent.piece_size(index), torrent.piece_hashes[index]
                )
        except (OSError, IntegrityError, ConnectionError) as error:
            last_error = error
    raise RuntimeError(f"Could not download piece {index} from any peer: {last_error}")


def download_file(torrent: Torrent, peers: List[Peer], output: str) -> None:
    """Download the whole file concurrently across multiple peers.

    Pieces are handed out from a shared work queue; one worker thread drives
    each peer connection and writes verified pieces straight to their offset in
    the output file. Any pieces left behind by failed peers are retried
    sequentially so the result is always complete and correct.
    """
    _preallocate(output, torrent.length)

    work: "queue.Queue[int]" = queue.Queue()
    for index in range(torrent.num_pieces):
        work.put(index)

    completed: Set[int] = set()
    completed_lock = threading.Lock()
    file_lock = threading.Lock()

    with open(output, "r+b") as handle:
        worker_peers = peers[:MAX_WORKERS]
        threads = [
            threading.Thread(
                target=_worker,
                args=(peer, torrent, work, handle, file_lock, completed, completed_lock),
                daemon=True,
            )
            for peer in worker_peers
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        # Safety net: any piece a failed peer dropped is retried sequentially.
        missing = [i for i in range(torrent.num_pieces) if i not in completed]
        for index in missing:
            data = download_piece(torrent, peers, index)
            _write_piece(handle, file_lock, torrent, index, data)


def _worker(
    peer: Peer,
    torrent: Torrent,
    work: "queue.Queue[int]",
    handle: BinaryIO,
    file_lock: threading.Lock,
    completed: Set[int],
    completed_lock: threading.Lock,
) -> None:
    try:
        conn = PeerConnection(peer.ip, peer.port, torrent.info_hash, PEER_ID)
        conn.connect()
        conn.prepare_download()
    except (OSError, ConnectionError):
        return  # This peer is unusable; its pieces stay queued for others.

    try:
        while True:
            try:
                index = work.get_nowait()
            except queue.Empty:
                return
            try:
                data = conn.download_piece(
                    index, torrent.piece_size(index), torrent.piece_hashes[index]
                )
            except (OSError, IntegrityError, ConnectionError):
                work.put(index)  # Hand the piece back for another worker/fallback.
                return
            _write_piece(handle, file_lock, torrent, index, data)
            with completed_lock:
                completed.add(index)
    finally:
        conn.close()


def _write_piece(
    handle: BinaryIO,
    file_lock: threading.Lock,
    torrent: Torrent,
    index: int,
    data: bytes,
) -> None:
    offset = index * torrent.piece_length
    with file_lock:
        handle.seek(offset)
        handle.write(data)


def _preallocate(path: str, size: int) -> None:
    """Create ``path`` as a sparse file of ``size`` bytes for offset writes."""
    with open(path, "wb") as handle:
        if size > 0:
            handle.seek(size - 1)
            handle.write(b"\x00")
