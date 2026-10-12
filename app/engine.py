"""Bounded nonblocking peer reactor. All mutable transfer state has one owner."""
from __future__ import annotations

import errno
import ipaddress
import selectors
import socket
import struct
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field

from .peer import BLOCK_SIZE, HANDSHAKE_LEN, PROTOCOL_STRING, ProtocolError
from .scheduler import Block, Scheduler
from .storage import Storage
from .torrent import Torrent
from .tracker import Peer, new_peer_id


def frame(kind: int, payload: bytes = b"") -> bytes:
    return struct.pack(">I", 1 + len(payload)) + bytes([kind]) + payload


@dataclass
class Options:
    max_peers: int = 8
    window: int = 5
    max_pending: int = 128
    max_active: int = 8
    max_buffer_bytes: int = 64 * 1024 * 1024
    max_discovery: int = 256
    connect_timeout: float = 5
    handshake_timeout: float = 5
    request_timeout: float = 10
    inactivity_timeout: float = 20
    no_progress_timeout: float = 60
    max_retries: int = 3
    backoff: float = .25
    endgame: int = 16
    seed: int = 0
    strategy: str = "rarest"

    def validate(self, torrent: Torrent) -> None:
        for name in ("max_peers", "window", "max_pending", "max_active", "max_buffer_bytes", "max_discovery"):
            if type(getattr(self, name)) is not int or getattr(self, name) <= 0:
                raise ValueError(f"{name} must be a positive integer")
        for name in ("connect_timeout", "handshake_timeout", "request_timeout", "inactivity_timeout", "no_progress_timeout", "backoff"):
            import math
            if not math.isfinite(getattr(self, name)) or getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive and finite")
        if self.max_retries < 0 or self.endgame < 0 or self.strategy not in ("rarest", "sequential"):
            raise ValueError("Invalid retries, endgame or strategy")
        if torrent.num_pieces and torrent.piece_length > self.max_buffer_bytes:
            raise ValueError("Piece exceeds configured buffer budget")


@dataclass
class Stats:
    downloaded_bytes: int = 0
    duplicate_bytes: int = 0
    requested_bytes: int = 0
    verified_bytes: int = 0
    resumed_bytes: int = 0
    retries: int = 0
    hash_failures: int = 0
    protocol_errors: int = 0
    timeouts: int = 0
    cancels: int = 0
    peak_peers: int = 0
    peak_pending: int = 0
    peak_active: int = 0
    elapsed_seconds: float = 0
    revalidation_seconds: float = 0
    peer_failures: list = field(default_factory=list)


@dataclass
class Session:
    id: int
    peer: Peer
    sock: socket.socket
    phase: str
    deadline: float
    last_progress: float
    incoming: bytearray = field(default_factory=bytearray)
    outgoing: bytearray = field(default_factory=bytearray)
    available: set[int] = field(default_factory=set)
    pending: dict[Block, float] = field(default_factory=dict)
    history: OrderedDict = field(default_factory=OrderedDict)
    choked: bool = True
    interested: bool = False
    first_message: bool = True


class Engine:
    def __init__(self, torrent: Torrent, storage: Storage, peers: list[Peer], *,
                 options: Options | None = None, peer_id: bytes | None = None,
                 stop: threading.Event | None = None, progress=None, tracker=None):
        self.options = options or Options()
        self.options.validate(torrent)
        self.torrent, self.storage = torrent, storage
        self.peer_id = peer_id or new_peer_id()
        self.stop = stop or threading.Event()
        self.progress, self.tracker = progress, tracker
        self.selector = selectors.DefaultSelector()
        active = min(self.options.max_active, self.options.max_buffer_bytes // torrent.piece_length)
        self.scheduler = Scheduler(torrent, storage.verified, max_active=max(1, active),
                                   max_pending=self.options.max_pending, endgame=self.options.endgame,
                                   seed=self.options.seed, strategy=self.options.strategy)
        self.sessions: dict[int, Session] = {}
        self.discovered: dict[Peer, tuple[int, float]] = {}
        self.next_id = 0
        self.stats = Stats(resumed_bytes=sum(torrent.piece_size(i) for i in storage.verified),
                           revalidation_seconds=storage.revalidation_seconds)
        self.stats.verified_bytes = self.stats.resumed_bytes
        self.add_peers(peers)

    def add_peers(self, peers: list[Peer]) -> None:
        for peer in peers:
            if peer in self.discovered:
                continue
            if len(self.discovered) >= self.options.max_discovery:
                break
            ipaddress.IPv4Address(peer.ip)
            if not 1 <= peer.port <= 65535:
                raise ValueError("Invalid peer port")
            self.discovered[peer] = (0, 0)

    def _open(self, peer: Peer, now: float) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        session = Session(self.next_id, peer, sock, "connect",
                          now + self.options.connect_timeout, now)
        self.next_id += 1
        self.sessions[session.id] = session
        try:
            code = sock.connect_ex((peer.ip, peer.port))
            if code not in (0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY, 10035):
                raise OSError(code, "Peer connection failed")
            self.selector.register(sock, selectors.EVENT_READ | selectors.EVENT_WRITE, session)
        except OSError as error:
            self._drop(session, error, now)

    def _remember(self, session: Session, block: Block, now: float) -> None:
        session.history[block] = now + self.options.request_timeout
        session.history.move_to_end(block)
        limit = max(32, self.options.window * 4)
        while len(session.history) > limit:
            session.history.popitem(last=False)

    def _drop(self, session: Session, error: Exception, now: float) -> None:
        self.scheduler.disconnect(session.id)
        self.sessions.pop(session.id, None)
        try:
            self.selector.unregister(session.sock)
        except KeyError:
            pass
        session.sock.close()
        attempts, _ = self.discovered[session.peer]
        self.discovered[session.peer] = (attempts + 1, now + self.options.backoff * 2 ** min(attempts, 8))
        self.stats.retries += 1
        self.stats.protocol_errors += isinstance(error, ProtocolError)
        self.stats.timeouts += isinstance(error, TimeoutError)
        # Bound observability as well as work queues. No tracker URLs logged.
        if len(self.stats.peer_failures) < self.options.max_discovery * (self.options.max_retries + 1):
            self.stats.peer_failures.append({"peer": str(session.peer), "reason": str(error),
                                            "attempt": attempts + 1})

    def _interest(self, session: Session) -> None:
        interested = self.scheduler.has_work(session.id)
        if interested != session.interested:
            session.outgoing.extend(frame(2 if interested else 3))
            session.interested = interested

    def _message(self, session: Session, kind: int, payload: bytes, now: float) -> None:
        fixed = {0: 0, 1: 0, 2: 0, 3: 0, 4: 4, 6: 12, 8: 12, 9: 2}
        if kind in fixed and len(payload) != fixed[kind]:
            raise ProtocolError("Invalid known message shape")
        if kind == 5:
            size = (self.torrent.num_pieces + 7) // 8
            if not session.first_message or len(payload) != size:
                raise ProtocolError("Invalid bitfield length/order")
            spare = (-self.torrent.num_pieces) % 8
            if spare and payload[-1] & ((1 << spare) - 1):
                raise ProtocolError("Nonzero bitfield padding")
            session.available = {i for i in range(self.torrent.num_pieces)
                                 if payload[i // 8] & (128 >> (i % 8))}
            self.scheduler.update(session.id, session.available)
        elif kind == 4:
            index = struct.unpack(">I", payload)[0]
            if index >= self.torrent.num_pieces:
                raise ProtocolError("HAVE index out of range")
            session.available.add(index)
            self.scheduler.update(session.id, session.available)
        elif kind == 0:
            session.choked = True
            for block in list(session.pending):
                self.scheduler.release(session.id, block)
                self._remember(session, block, now)
            session.pending.clear()
        elif kind == 1:
            session.choked = False
        elif kind == 7:
            if not 8 < len(payload) <= BLOCK_SIZE + 8:
                raise ProtocolError("Invalid piece message size")
            index, begin = struct.unpack(">II", payload[:8])
            block = (index, begin, len(payload) - 8)
            self.stats.downloaded_bytes += block[2]
            if block not in session.pending:
                if session.history.get(block, 0) < now:
                    raise ProtocolError("Unsolicited block")
                self.stats.duplicate_bytes += block[2]
                return  # valid recently requested late response; no progress
            session.pending.pop(block)
            self._remember(session, block, now)
            losers, complete, corrupt = self.scheduler.accept(session.id, block, payload[8:])
            session.last_progress = now  # a first accepted block is useful peer progress
            for owner, losing in losers:
                other = self.sessions.get(owner)
                if other and losing in other.pending:
                    other.pending.pop(losing)
                    self._remember(other, losing, now)
                    other.outgoing.extend(frame(8, struct.pack(">III", *losing)))
                    self.stats.cancels += 1
            if corrupt:
                self.stats.hash_failures += 1
                # Mixed-source failures cannot identify a faulty peer. The
                # scheduler retries this piece from one source before applying
                # a cooldown, preserving healthy contributors' retry budgets.
                if len(corrupt) == 1:
                    contributor = self.sessions.get(next(iter(corrupt)))
                    if contributor:
                        self._drop(contributor, ConnectionError("Single-source piece failed hash verification"), now)
            if complete is not None:
                try:
                    self.storage.commit(index, complete)
                except OSError as error:
                    raise RuntimeError("Disk commit failed; staging preserved") from error
                self.stats.verified_bytes += len(complete)
                self.last_verified = now  # swarm progress requires verified commitment
        elif kind in (6, 8):
            index, begin, length = struct.unpack(">III", payload)
            if (index >= self.torrent.num_pieces or not 0 < length <= BLOCK_SIZE
                    or begin + length > self.torrent.piece_size(index)):
                raise ProtocolError("Invalid request/cancel bounds")
            # Remain choked: uploading is unsupported.
        elif kind not in (2, 3, 9):
            raise ProtocolError("Unsupported unnegotiated peer message")
        session.first_message = False

    def _read(self, session: Session, now: float) -> None:
        chunk = session.sock.recv(65536)
        if not chunk:
            raise ConnectionError("Peer disconnected")
        session.incoming.extend(chunk)
        if session.phase == "handshake":
            if len(session.incoming) < HANDSHAKE_LEN:
                return
            response = bytes(session.incoming[:HANDSHAKE_LEN])
            del session.incoming[:HANDSHAKE_LEN]
            if response[:20] != bytes([19]) + PROTOCOL_STRING or response[28:48] != self.torrent.info_hash:
                raise ProtocolError("Invalid handshake")
            session.phase = "ready"
            session.last_progress = now
            self.scheduler.update(session.id, set())
        if session.phase != "ready":
            return
        limit = max(BLOCK_SIZE + 9, 1 + (self.torrent.num_pieces + 7) // 8)
        while len(session.incoming) >= 4:
            length = struct.unpack(">I", session.incoming[:4])[0]
            if length > limit:
                raise ProtocolError("Frame exceeds torrent-specific bound")
            if len(session.incoming) < length + 4:
                break
            body = bytes(session.incoming[4:4 + length])
            del session.incoming[:4 + length]
            if body:
                self._message(session, body[0], body[1:], now)
            if session.id not in self.sessions:
                return

    def run(self) -> Stats:
        start = self.last_verified = time.monotonic()
        next_report = start
        try:
            while len(self.storage.verified) < self.torrent.num_pieces:
                now = time.monotonic()
                if self.stop.is_set():
                    raise InterruptedError("Download interrupted; verified staging preserved")
                if now - self.last_verified > self.options.no_progress_timeout:
                    raise RuntimeError("No verified piece progress within deadline")
                if self.tracker:
                    self.tracker.poll(self.stats, self.torrent.length - self.stats.verified_bytes)
                    self.add_peers(self.tracker.take_peers())
                connected = {s.peer for s in self.sessions.values()}
                for peer, (attempts, retry_at) in list(self.discovered.items()):
                    if len(self.sessions) >= self.options.max_peers:
                        break
                    if peer not in connected and attempts <= self.options.max_retries and retry_at <= now:
                        self._open(peer, now)
                for session in list(self.sessions.values()):
                    expired = any(now - sent > self.options.request_timeout for sent in session.pending.values())
                    if ((session.phase != "ready" and now > session.deadline) or expired
                            or (session.phase == "ready" and now - session.last_progress > self.options.inactivity_timeout)):
                        self._drop(session, TimeoutError("Peer useful-progress deadline expired"), now)
                        continue
                    if session.phase == "ready":
                        self._interest(session)
                        if not session.choked:
                            while len(session.pending) < self.options.window:
                                block = self.scheduler.request(session.id)
                                if block is None:
                                    break
                                session.pending[block] = now
                                session.outgoing.extend(frame(6, struct.pack(">III", *block)))
                                self.stats.requested_bytes += block[2]
                    if len(session.outgoing) > 65536:
                        self._drop(session, ProtocolError("Outbound control backlog exceeded"), now)
                        continue
                    events = selectors.EVENT_READ
                    if session.phase == "connect" or session.outgoing:
                        events |= selectors.EVENT_WRITE
                    self.selector.modify(session.sock, events, session)
                self.stats.peak_peers = max(self.stats.peak_peers, len(self.sessions))
                if self.progress and now >= next_report:
                    self.progress(self.stats, len(self.sessions))
                    next_report = now + .5
                if not self.sessions:
                    self.stop.wait(.05)  # Windows select() rejects empty fd sets.
                    continue
                for key, events in self.selector.select(.05):
                    session = key.data
                    if session.id not in self.sessions:
                        continue
                    try:
                        if session.phase == "connect":
                            code = session.sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                            if code:
                                raise OSError(code, "Connect failed")
                            session.phase = "handshake"
                            session.deadline = time.monotonic() + self.options.handshake_timeout
                            session.outgoing.extend(bytes([19]) + PROTOCOL_STRING + bytes(8) + self.torrent.info_hash + self.peer_id)
                        if events & selectors.EVENT_WRITE and session.outgoing:
                            count = session.sock.send(session.outgoing)
                            del session.outgoing[:count]
                        if events & selectors.EVENT_READ:
                            self._read(session, time.monotonic())
                    except BlockingIOError:
                        pass
                    except (OSError, ConnectionError) as error:
                        if session.id in self.sessions:
                            self._drop(session, error, time.monotonic())
            # Flush queued CANCELs once before shutting down the completed swarm.
            for session in self.sessions.values():
                if session.outgoing:
                    try:
                        session.sock.send(session.outgoing)
                    except OSError:
                        pass
            self.storage.publish()
            return self.stats
        finally:
            for session in list(self.sessions.values()):
                self.scheduler.disconnect(session.id)
                session.sock.close()
            self.sessions.clear()
            self.selector.close()
            self.stats.peak_pending = self.scheduler.peak_pending
            self.stats.peak_active = self.scheduler.peak_active
            self.stats.elapsed_seconds = time.monotonic() - start
