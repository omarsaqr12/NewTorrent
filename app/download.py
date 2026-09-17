"""Verified single-piece and concurrent whole-file download orchestration."""

from __future__ import annotations

import os
import queue
import tempfile
import threading
from pathlib import Path
from typing import BinaryIO, List, Set

from .peer import IntegrityError, PeerConnection
from .torrent import Torrent
from .tracker import PEER_ID, Peer

MAX_WORKERS = 8


def download_piece(torrent: Torrent, peers: List[Peer], index: int) -> bytes:
    """Try advertised peers in order until one supplies a verified piece."""
    length = torrent.piece_size(index)  # Reject invalid indices before connecting.
    last_error: Exception | None = None
    for peer in peers:
        try:
            with PeerConnection(peer.ip, peer.port, torrent.info_hash, PEER_ID) as conn:
                conn.prepare_download()
                return conn.download_piece(index, length, torrent.piece_hashes[index])
        except (OSError, IntegrityError, ConnectionError) as error:
            last_error = error
    raise RuntimeError(f"Could not download piece {index} from any peer: {last_error}")


def download_file(torrent: Torrent, peers: List[Peer], output: str) -> None:
    """Download to a temporary sibling, publishing only on full verification.

    An unsuccessful download removes its temporary file and leaves any existing
    destination untouched. Replacement on success is atomic on the same volume.
    """
    if torrent.num_pieces and not peers:
        raise RuntimeError("Tracker returned no peers")
    destination = Path(output)
    fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".part",
                                    dir=str(destination.parent))
    os.close(fd)
    try:
        _preallocate(temporary, torrent.length)
        work: "queue.Queue[int]" = queue.Queue()
        for index in range(torrent.num_pieces):
            work.put(index)
        completed: Set[int] = set()
        completed_lock = threading.Lock()
        file_lock = threading.Lock()
        with open(temporary, "r+b") as handle:
            threads = [
                threading.Thread(
                    target=_worker,
                    args=(peer, torrent, work, handle, file_lock, completed, completed_lock),
                )
                for peer in peers[:MAX_WORKERS]
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            # Workers may exit on unavailable peers or corrupt pieces. Retry all
            # missing pieces; a failure aborts before the destination is replaced.
            for index in range(torrent.num_pieces):
                if index not in completed:
                    data = download_piece(torrent, peers, index)
                    _write_piece(handle, file_lock, torrent, index, data)
            handle.flush()
        os.replace(temporary, output)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


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
        with PeerConnection(peer.ip, peer.port, torrent.info_hash, PEER_ID) as conn:
            conn.prepare_download()
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
                    work.put(index)
                    return
                _write_piece(handle, file_lock, torrent, index, data)
                with completed_lock:
                    completed.add(index)
    except (OSError, IntegrityError, ConnectionError):
        return


def _write_piece(
    handle: BinaryIO,
    file_lock: threading.Lock,
    torrent: Torrent,
    index: int,
    data: bytes,
) -> None:
    if len(data) != torrent.piece_size(index):
        raise ValueError(f"Piece {index} has an unexpected byte count")
    with file_lock:
        handle.seek(index * torrent.piece_length)
        handle.write(data)


def _preallocate(path: str, size: int) -> None:
    with open(path, "wb") as handle:
        handle.truncate(size)
