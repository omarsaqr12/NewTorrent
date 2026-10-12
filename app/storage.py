"""Locked, persistent staging with hash revalidation and verified publication."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
from bisect import bisect_right
from collections import OrderedDict
from pathlib import Path

from .torrent import Torrent


def reject_links(path: Path) -> None:
    # Check before resolve: resolving first would hide a symlink escape.
    for part in (path, *path.parents):
        if part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()):
            raise ValueError("Symlink/junction in output or staging path")
        if os.name == "nt" and part.exists():
            if part.lstat().st_file_attributes & 0x400:  # all Windows reparse points
                raise ValueError("Reparse point in output or staging path")


def sync_directory(path: Path) -> None:
    if os.name != "nt":
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def atomic_json(path: Path, value: dict) -> None:
    reject_links(path)
    temporary = path.with_suffix(".tmp")
    reject_links(temporary)
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(value, handle, sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    sync_directory(path.parent)


class DownloadLock:
    """Kernel lock: released automatically on process exit, never delete lock file."""
    def __init__(self, path: Path):
        reject_links(path)
        self.handle = open(path, "a+b")
        try:
            if os.name == "nt":
                import msvcrt
                self.handle.seek(0)
                if not self.handle.read(1):
                    self.handle.write(b"0")
                    self.handle.flush()
                self.handle.seek(0)
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            self.handle.close()
            raise RuntimeError("Another process owns this staging download") from error

    def close(self) -> None:
        if not self.handle.closed:
            if os.name == "nt":
                import msvcrt
                self.handle.seek(0)
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
            self.handle.close()


class Storage:
    def __init__(self, torrent: Torrent, output: str, *, resume: bool = True,
                 overwrite: bool = False, stop=None):
        self.torrent = torrent
        self.destination = Path(os.path.abspath(output))
        reject_links(self.destination)
        if not self.destination.parent.is_dir():
            raise ValueError("Output parent directory must exist")
        if self.destination.exists() and (torrent.multi_file or not overwrite):
            raise FileExistsError("Destination exists; single files require --overwrite")
        if self.destination.exists() and not self.destination.is_file():
            raise ValueError("Single-file destination must be a regular file")
        self.overwrite = overwrite
        self.stage = self.destination.with_name(self.destination.name + ".newtorrent")
        reject_links(self.stage)
        self.lock = DownloadLock(self.stage.with_name(self.stage.name + ".lock"))
        self.handles = OrderedDict()
        self.verified: set[int] = set()
        self.revalidation_seconds = 0.0
        try:
            existed = self.stage.exists()
            if existed and not resume:
                raise FileExistsError("Staging exists; use resume or choose another output")
            self.stage.mkdir(exist_ok=True)
            self.data = self.stage / "data"
            self.identity = {
                "version": 1, "info_hash": torrent.info_hash.hex(),
                "destination": str(self.destination), "stage": str(self.stage),
                "piece_length": torrent.piece_length, "multi_file": torrent.multi_file,
                "files": [[list(f.path), f.length] for f in torrent.layout],
            }
            identity_path = self.stage / "identity.json"
            reject_links(identity_path)
            if existed:
                try:
                    identity = json.loads(identity_path.read_text(encoding="utf-8"))
                except (OSError, ValueError) as error:
                    raise ValueError("Missing/corrupt staging identity; choose a fresh output") from error
                if identity != self.identity:
                    raise ValueError("Staging identity does not match torrent/layout/location")
            else:
                atomic_json(identity_path, self.identity)
            if torrent.multi_file:
                reject_links(self.data)
                self.data.mkdir(exist_ok=True)
            self.paths = []
            for entry in torrent.layout:
                if stop is not None and stop.is_set():
                    raise InterruptedError("Staging preparation interrupted")
                path = self.data.joinpath(*entry.path) if torrent.multi_file else self.data
                reject_links(path)
                path.parent.mkdir(parents=True, exist_ok=True)
                if path.exists() and not path.is_file():
                    raise ValueError("Staging payload is not a regular file")
                if not path.exists():
                    with open(path, "xb") as handle:
                        handle.truncate(entry.length)
                self.paths.append(path)
            self.offsets = [entry.offset for entry in torrent.layout]
            # Checkpoint is a hint only. Rehash all on-disk pieces, even if JSON
            # was truncated or stale. Identity remains mandatory and immutable.
            start = time.monotonic()
            if existed:
                for index, digest in enumerate(torrent.piece_hashes):
                    if stop is not None and stop.is_set():
                        raise InterruptedError("Resume revalidation interrupted")
                    raw = self.read(index * torrent.piece_length, torrent.piece_size(index))
                    if len(raw) == torrent.piece_size(index) and hashlib.sha1(raw).digest() == digest:
                        self.verified.add(index)
            self.revalidation_seconds = time.monotonic() - start
            self.checkpoint()
        except BaseException:
            self.close()
            raise

    def _handle(self, path: Path):
        handle = self.handles.get(path)
        if handle is None:
            handle = open(path, "r+b")
            self.handles[path] = handle
        self.handles.move_to_end(path)
        while len(self.handles) > 32:
            _, old = self.handles.popitem(last=False)
            old.close()
        return handle

    def _close_handles(self):
        for handle in self.handles.values():
            handle.close()
        self.handles.clear()

    def _segments(self, offset: int, length: int):
        if offset < 0 or length < 0 or offset + length > self.torrent.length:
            raise ValueError("Out-of-range storage access")
        start = max(0, bisect_right(self.offsets, offset) - 1)
        for position in range(start, len(self.paths)):
            entry, path = self.torrent.layout[position], self.paths[position]
            if entry.offset >= offset + length:
                break
            lo, hi = max(offset, entry.offset), min(offset + length, entry.offset + entry.length)
            if lo < hi:
                reject_links(path)
                yield path, lo - entry.offset, lo - offset, hi - lo

    def read(self, offset: int, length: int) -> bytes:
        data = bytearray()
        for path, file_offset, _, count in self._segments(offset, length):
            handle = self._handle(path)
            handle.seek(file_offset)
            chunk = handle.read(count)
            data.extend(chunk)
            if len(chunk) != count:
                break
        return bytes(data)

    def commit(self, index: int, data: bytes | bytearray) -> None:
        if (len(data) != self.torrent.piece_size(index)
                or hashlib.sha1(data).digest() != self.torrent.piece_hashes[index]):
            raise ValueError("Cannot commit an unverified piece")
        if index in self.verified:
            raise ValueError("Piece already committed")
        for path, file_offset, data_offset, count in self._segments(index * self.torrent.piece_length, len(data)):
            handle = self._handle(path)
            handle.seek(file_offset)
            if handle.write(memoryview(data)[data_offset:data_offset + count]) != count:
                raise OSError("Short disk write")
            handle.flush()
            os.fsync(handle.fileno())
        self.verified.add(index)
        self.checkpoint()  # durable payload precedes checkpoint publication

    def checkpoint(self) -> None:
        atomic_json(self.stage / "checkpoint.json", {**self.identity, "verified": sorted(self.verified)})

    def publish(self) -> None:
        if len(self.verified) != self.torrent.num_pieces:
            raise RuntimeError("Cannot publish an incomplete download")
        reject_links(self.destination)
        # Remove extra bytes left by an externally extended staging file.
        for entry, path in zip(self.torrent.layout, self.paths):
            reject_links(path)
            handle = self._handle(path)
            handle.truncate(entry.length)
            handle.flush()
            os.fsync(handle.fileno())
        self._close_handles()
        if self.torrent.multi_file:
            if self.destination.exists():
                raise FileExistsError("Multi-file publication needs a fresh destination")
            os.rename(self.data, self.destination)
        elif self.overwrite:
            os.replace(self.data, self.destination)
        else:
            os.link(self.data, self.destination)  # atomic no-clobber creation
            self.data.unlink()
        sync_directory(self.destination.parent)
        shutil.rmtree(self.stage)

    def close(self) -> None:
        self._close_handles()
        self.lock.close()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()
