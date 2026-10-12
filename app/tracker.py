"""Bounded HTTP/HTTPS and BEP 15 UDP announcements with BEP 12 failover."""
from __future__ import annotations

import ipaddress
import math
import queue
import random
import secrets
import select
import socket
import struct
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, build_opener
from urllib.error import URLError

from . import bencode
from .torrent import Torrent

MAX_RESPONSE = 1024 * 1024
MAX_PEERS = 256
PORT = 6881  # Announce metadata only; this client has no inbound listener.


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def new_peer_id() -> bytes:
    return b"-NT0200-" + secrets.token_hex(6).encode("ascii")


PEER_ID = new_peer_id()  # legacy helper commands share one process identity


@dataclass(frozen=True)
class Peer:
    ip: str
    port: int

    def __str__(self) -> str:
        return f"{self.ip}:{self.port}"


def _peer(ip: str, port: int) -> Peer:
    address = ipaddress.IPv4Address(ip)
    if address.is_unspecified or address.is_multicast or address == ipaddress.IPv4Address('255.255.255.255'):
        raise ValueError("Invalid peer address")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Invalid peer port")
    return Peer(str(address), port)


def _parse_compact_peers(blob: bytes, limit: int = MAX_PEERS) -> list[Peer]:
    if len(blob) % 6:
        raise ValueError("Incomplete compact IPv4 entry")
    peers = dict.fromkeys(_peer(socket.inet_ntoa(blob[i:i + 4]),
                               int.from_bytes(blob[i + 4:i + 6], "big"))
                          for i in range(0, len(blob), 6))
    return list(peers)[:limit]


def parse_response(raw: bytes, limit: int = MAX_PEERS):
    body = bencode.decode(raw, max_size=MAX_RESPONSE)
    if not isinstance(body, dict):
        raise ValueError("Tracker response is not a dictionary")
    if "failure reason" in body:
        raise ValueError("Tracker reported failure")
    interval = body.get("interval")
    if type(interval) is not int or not 0 < interval <= 2**31 - 1:
        raise ValueError("Invalid tracker interval")
    minimum = body.get("min interval", 0)
    if type(minimum) is not int or not 0 <= minimum <= 2**31 - 1:
        raise ValueError("Invalid minimum tracker interval")
    interval = max(interval, minimum)
    peers = body.get("peers")
    if isinstance(peers, bytes):
        result = _parse_compact_peers(peers, limit)
    elif isinstance(peers, list):
        unique = {}
        for item in peers:
            if not isinstance(item, dict) or not isinstance(item.get("ip"), bytes):
                raise ValueError("Invalid dictionary peer entry")
            peer = _peer(item["ip"].decode("ascii"), item.get("port"))
            if "peer id" in item and (not isinstance(item["peer id"], bytes) or len(item["peer id"]) != 20):
                raise ValueError("Invalid tracker peer ID")
            if len(unique) < limit:
                unique[peer] = None
        result = list(unique)
    else:
        raise ValueError("Tracker peers must be compact bytes or dictionaries")
    return result, interval


class Announcer:
    def __init__(self, torrent: Torrent, *, peer_id: bytes | None = None,
                 port: int = PORT, timeout: float = 5, limit: int = MAX_PEERS,
                 stop: threading.Event | None = None, clock=time.monotonic,
                 udp_wait=None, seed: int = 0):
        if not math.isfinite(timeout) or timeout <= 0 or not 1 <= port <= 65535 or limit <= 0:
            raise ValueError("Invalid tracker options")
        self.torrent = torrent
        self.peer_id = peer_id or new_peer_id()
        self.port, self.timeout, self.limit = port, timeout, limit
        self.stop, self.clock = stop or threading.Event(), clock
        self.udp_wait = udp_wait
        self.tiers = [list(tier) for tier in (torrent.tiers or [[torrent.announce]])]
        rng = random.Random(seed)
        for tier in self.tiers:
            rng.shuffle(tier)
        self.connections = {}
        self.started_urls = set()
        self.last_url = None
        self.key = secrets.randbits(32)
        self.operation_deadline = float('inf')

    def _http(self, url, event, downloaded, left):
        params = {"info_hash": self.torrent.info_hash, "peer_id": self.peer_id,
                  "port": self.port, "uploaded": 0, "downloaded": downloaded,
                  "left": left, "compact": 1, "numwant": self.limit}
        if event:
            params["event"] = event
        # urlencode percent-encodes bytes without a UTF-8 conversion, including +.
        query = urlencode(params)
        deadline = min(self.clock() + self.timeout, self.operation_deadline)
        opener = build_opener(NoRedirect())
        with opener.open(url + ('&' if '?' in url else '?') + query,
                         timeout=max(.001, deadline - self.clock())) as response:
            if response.status != 200:
                raise ValueError("Tracker must return HTTP 200")
            if response.headers.get("Content-Encoding", "identity") != "identity":
                raise ValueError("Compressed tracker responses unsupported")
            body = bytearray()
            while True:
                if self.stop.is_set():
                    raise InterruptedError("Tracker cancelled")
                if self.clock() >= deadline:
                    raise TimeoutError("Tracker overall response deadline")
                chunk = response.read1(min(16384, MAX_RESPONSE + 1 - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
                if len(body) > MAX_RESPONSE:
                    raise ValueError("Tracker response exceeds limit")
        return parse_response(bytes(body), self.limit)

    def _exchange(self, sock, packet, action, transaction, deadline):
        sock.send(packet)
        while self.clock() < deadline:
            if self.stop.is_set():
                raise InterruptedError("UDP tracker cancelled")
            wait = min(.2, deadline - self.clock())
            ready = self.udp_wait(sock, wait) if self.udp_wait else select.select([sock], [], [], wait)[0]
            if not ready:
                continue
            data = sock.recv(MAX_RESPONSE + 1)
            if len(data) < 8:
                continue
            got_action, got_transaction = struct.unpack(">II", data[:8])
            if got_transaction != transaction:
                continue  # unrelated response cannot reset deadline
            if got_action == 3:
                raise ValueError("UDP tracker reported failure")
            if got_action != action:
                raise ValueError("UDP tracker action mismatch")
            if len(data) < (16 if action == 0 else 20):
                raise ValueError("Truncated UDP tracker response")
            return data
        raise TimeoutError("UDP tracker response deadline")

    def _udp(self, url, event, downloaded, left):
        parsed = urlsplit(url)
        addresses = socket.getaddrinfo(parsed.hostname, parsed.port or 80, socket.AF_INET, socket.SOCK_DGRAM)
        deadline = min(self.clock() + self.timeout, self.operation_deadline)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(addresses[0][4])  # source validation by connected UDP socket
            sock.setblocking(False)
            for attempt in range(3):
                now = self.clock()
                if now >= deadline:
                    break
                transaction = secrets.randbits(32)
                connection = self.connections.get(url)
                try:
                    if connection is None or now >= connection[1]:
                        data = self._exchange(sock, struct.pack(">QII", 0x41727101980, 0, transaction),
                                              0, transaction, min(deadline, now + 15 * 2 ** attempt))
                        connection = (struct.unpack(">Q", data[8:16])[0], self.clock() + 60)
                        self.connections[url] = connection
                    transaction = secrets.randbits(32)
                    packet = struct.pack(">QII20s20sQQQIIIiH", connection[0], 1, transaction,
                                         self.torrent.info_hash, self.peer_id, downloaded, left, 0,
                                         {"": 0, "completed": 1, "started": 2, "stopped": 3}[event],
                                         0, self.key, self.limit, self.port)
                    data = self._exchange(sock, packet, 1, transaction,
                                          min(deadline, self.clock() + 15 * 2 ** attempt))
                    interval = struct.unpack(">I", data[8:12])[0]
                    if interval <= 0:
                        raise ValueError("Invalid UDP interval")
                    return _parse_compact_peers(data[20:], self.limit), interval
                except TimeoutError:
                    # No early retransmission: budget exhaustion terminates the
                    # operation rather than violating BEP 15's 15*2^n schedule.
                    continue
        raise TimeoutError("UDP tracker retry budget exhausted")

    def announce(self, event="", *, downloaded=0, left=None):
        self.operation_deadline = self.clock() + self.timeout
        left = self.torrent.length if left is None else left
        for tier in self.tiers:
            for url in list(tier):
                if self.clock() >= self.operation_deadline:
                    raise RuntimeError("Tracker discovery operation budget exhausted")
                if self.stop.is_set():
                    raise InterruptedError("Tracker cancelled")
                try:
                    effective_event = event
                    if not event and url not in self.started_urls:
                        effective_event = "started"
                    result = (self._udp if url.startswith("udp:") else self._http)(url, effective_event, downloaded, left)
                    tier.remove(url)
                    tier.insert(0, url)
                    self.last_url = url
                    if effective_event == "started":
                        self.started_urls.add(url)
                    return result
                except (OSError, ValueError, URLError):
                    continue
        raise RuntimeError("All tracker tiers failed (URLs omitted to protect credentials)")

    def finish(self, *, completed: bool, downloaded: int, left: int):
        self.operation_deadline = self.clock() + self.timeout
        # Best-effort terminal events only to trackers which saw this session.
        for url in list(self.started_urls):
            method = self._udp if url.startswith("udp:") else self._http
            if completed:
                try:
                    method(url, "completed", downloaded, left)
                except (OSError, ValueError, URLError):
                    pass
            try:
                method(url, "stopped", downloaded, left)
            except (OSError, ValueError, URLError):
                pass


class TrackerService:
    """One daemon I/O worker, one bounded discovery result, snapshot counters."""
    def __init__(self, announcer: Announcer, *, left=None):
        self.announcer = announcer
        self.results = queue.Queue(maxsize=1)
        self.wake = threading.Event()
        self.closed = threading.Event()
        self.snapshot = (0, announcer.torrent.length)
        self.terminal = None
        peers, interval = announcer.announce("started", left=left)
        self.results.put(peers)
        self.next_announce = time.monotonic() + interval
        self.thread = threading.Thread(target=self._run, name="newtorrent-tracker", daemon=True)
        self.thread.start()

    def poll(self, stats, left):
        self.snapshot = (stats.downloaded_bytes, left)
        if time.monotonic() >= self.next_announce:
            self.wake.set()

    def take_peers(self):
        try:
            return self.results.get_nowait()
        except queue.Empty:
            return []

    def _run(self):
        while not self.closed.is_set():
            self.wake.wait(.1)
            self.wake.clear()
            if self.closed.is_set():
                break
            if time.monotonic() < self.next_announce:
                continue
            downloaded, left = self.snapshot
            try:
                peers, interval = self.announcer.announce(downloaded=downloaded, left=left)
                if self.results.empty():
                    self.results.put_nowait(peers)
                self.next_announce = time.monotonic() + interval
            except (RuntimeError, OSError, ValueError, URLError):
                self.next_announce = time.monotonic() + 5
        if self.terminal:
            completed, downloaded, left = self.terminal
            self.announcer.finish(completed=completed, downloaded=downloaded, left=left)

    def close(self, stats, completed):
        self.terminal = (completed, stats.downloaded_bytes, self.announcer.torrent.length - stats.verified_bytes)
        self.closed.set()
        self.wake.set()
        # Bound main-thread shutdown; network/DNS cleanup may outlive this join.
        self.thread.join(min(2, self.announcer.timeout))


def get_peers(torrent: Torrent) -> list[Peer]:
    return Announcer(torrent, peer_id=PEER_ID).announce("started")[0]
