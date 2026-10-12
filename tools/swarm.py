"""Programmable real TCP peers and HTTP/UDP trackers on IPv4 loopback."""
from __future__ import annotations

import hashlib
import heapq
import json
import select
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote_to_bytes, urlsplit

from app import bencode
from app.engine import frame
from app.torrent import Torrent
from app.tracker import Peer


def payload(size: int, seed: int = 0) -> bytes:
    pattern = b"".join(hashlib.sha256(f"{seed}:{i}".encode()).digest() for i in range(1024))
    return (pattern * ((size + len(pattern) - 1) // len(pattern)))[:size]


def metainfo(data: bytes, piece_length: int = 65536, *, announce="http://127.0.0.1:1/announce",
             files=None, tiers=None) -> bytes:
    info = {"name": b"synthetic", "piece length": piece_length,
            "pieces": b"".join(hashlib.sha1(data[i:i + piece_length]).digest()
                                for i in range(0, len(data), piece_length))}
    if files is None:
        info["length"] = len(data)
    else:
        if sum(size for _, size in files) != len(data):
            raise ValueError("Fixture file lengths do not match payload")
        info["files"] = [{"path": [p.encode() for p in parts], "length": size} for parts, size in files]
    meta = {"announce": announce.encode(), "info": info}
    if tiers:
        meta["announce-list"] = [[url.encode() for url in tier] for tier in tiers]
    return bencode.encode(meta)


class TCPPeer:
    def __init__(self, torrent: Torrent, data: bytes, *, pieces=None, delay=.002,
                 bitfield=True, have_after=None, corrupt=False, silent=False,
                 keepalive=False, fragment=False, duplicate=False, reorder=False,
                 disconnect_after=None, choke_once=False, slow_block=None,
                 malformed=False, drop_first=False, handshake_delay=0, unchoke_delay=0):
        self.torrent, self.data = torrent, data
        self.pieces = set(range(torrent.num_pieces)) if pieces is None else set(pieces)
        self.delay, self.bitfield, self.have_after = delay, bitfield, have_after
        self.corrupt, self.silent, self.keepalive = corrupt, silent, keepalive
        self.fragment, self.duplicate, self.reorder = fragment, duplicate, reorder
        self.disconnect_after, self.choke_once = disconnect_after, choke_once
        self.slow_block, self.malformed, self.drop_first = slow_block, malformed, drop_first
        self.handshake_delay = handshake_delay
        self.unchoke_delay = unchoke_delay
        self.stop = threading.Event()
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(16)
        self.listener.settimeout(.1)
        self.peer = Peer(*self.listener.getsockname())
        self.requests, self.cancels, self.sent_bytes, self.invalid_requests = [], [], 0, 0
        self.connections, self.threads = [], []
        self.thread = threading.Thread(target=self._accept, name="fixture-peer", daemon=True)
        self.thread.start()

    def _accept(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if len(self.threads) >= 32:
                conn.close()
                continue
            self.connections.append(conn)
            worker = threading.Thread(target=self._serve, args=(conn,), name="fixture-session", daemon=True)
            self.threads.append(worker)
            worker.start()

    def _send(self, conn, wire):
        if self.fragment:
            # Split length/message headers and payload without turning a test
            # into tens of thousands of tiny system calls on Windows.
            for lo, hi in ((0, 1), (1, 3), (3, 7)):
                conn.sendall(wire[lo:hi])
            for index in range(7, len(wire), 1024):
                conn.sendall(wire[index:index + 1024])
        else:
            conn.sendall(wire)

    def _serve(self, conn):
        incoming = bytearray()
        handshaken = False
        available = set(self.pieces)
        due, counter = [], 0
        start = time.monotonic()
        have_sent = choked_once = False
        last_keepalive = start
        unchoke_at = None
        try:
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            conn.settimeout(.5)
            while not self.stop.is_set():
                now = time.monotonic()
                if unchoke_at is not None and now >= unchoke_at:
                    self._send(conn, frame(1))
                    unchoke_at = None
                if handshaken and self.have_after and not have_sent and now - start >= self.have_after[0]:
                    available.update(self.have_after[1])
                    self._send(conn, b"".join(frame(4, struct.pack(">I", i)) for i in self.have_after[1]))
                    have_sent = True
                if handshaken and self.keepalive and now - last_keepalive >= .02:
                    self._send(conn, bytes(4))
                    last_keepalive = now
                while due and due[0][0] <= now:
                    _, _, block = heapq.heappop(due)
                    index, begin, length = block
                    offset = index * self.torrent.piece_length + begin
                    raw = self.data[offset:offset + length]
                    if self.corrupt:
                        raw = bytes([raw[0] ^ 1]) + raw[1:]
                    wire = frame(7, struct.pack(">II", index, begin) + raw)
                    self._send(conn, wire + (wire if self.duplicate else b""))
                    self.sent_bytes += length * (2 if self.duplicate else 1)
                if not select.select([conn], [], [], .005)[0]:
                    continue
                chunk = conn.recv(65536)
                if not chunk:
                    return
                incoming.extend(chunk)
                if not handshaken:
                    if len(incoming) < 68:
                        continue
                    request = bytes(incoming[:68])
                    del incoming[:68]
                    if request[:20] != bytes([19]) + b"BitTorrent protocol" or request[28:48] != self.torrent.info_hash:
                        return
                    response = request[:48] + b"-FIXTURE" + bytes(12)
                    if self.handshake_delay:
                        self.stop.wait(self.handshake_delay)
                    if self.silent:
                        continue
                    wire = response
                    if self.bitfield:
                        bits = bytearray((self.torrent.num_pieces + 7) // 8)
                        for i in available:
                            bits[i // 8] |= 128 >> (i % 8)
                        wire += frame(5, bytes(bits))
                    else:
                        wire += b"".join(frame(4, struct.pack(">I", i)) for i in available)
                    if self.unchoke_delay:
                        unchoke_at = time.monotonic() + self.unchoke_delay
                    else:
                        wire += frame(1)
                    if self.malformed:
                        wire += frame(4, bytes(2))
                    self._send(conn, wire)
                    handshaken = True
                while len(incoming) >= 4:
                    length = struct.unpack(">I", incoming[:4])[0]
                    if length > 65536:
                        return
                    if len(incoming) < 4 + length:
                        break
                    body = bytes(incoming[4:4 + length])
                    del incoming[:4 + length]
                    if not body:
                        continue
                    if body[0] in (6, 8):
                        block = struct.unpack(">III", body[1:])
                        if body[0] == 8:
                            self.cancels.append(block)
                            # Deliberately send already queued blocks despite CANCEL,
                            # modeling bytes already in transport.
                            continue
                        self.requests.append(block)
                        if block[0] not in available:
                            self.invalid_requests += 1
                            continue
                        if self.disconnect_after and len(self.requests) >= self.disconnect_after:
                            return
                        if self.choke_once and not choked_once:
                            choked_once = True
                            due.clear()
                            self._send(conn, frame(0) + frame(1))
                            continue
                        if self.keepalive or (self.drop_first and len(self.requests) == 1):
                            continue
                        delay = self.delay
                        if self.slow_block and block[:2] == self.slow_block[:2]:
                            delay = self.slow_block[2]
                        if self.reorder:
                            delay += .001 * (4 - (block[1] // 16384) % 4)
                        heapq.heappush(due, (time.monotonic() + delay, counter, block))
                        counter += 1
        except (OSError, ValueError, struct.error):
            pass
        finally:
            conn.close()

    def close(self):
        self.stop.set()
        self.listener.close()
        for conn in self.connections:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.thread.join(1)
        for worker in self.threads:
            worker.join(1)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class HTTPTracker:
    def __init__(self, peers=None, *, dictionary=False, fail=False, interval=1):
        self.peers, self.dictionary, self.fail = peers or [], dictionary, fail
        self.interval, self.announces = interval, []
        outer = self
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                params = {unquote_to_bytes(k): unquote_to_bytes(v.replace('+', ' '))
                          for pair in urlsplit(self.path).query.split('&')
                          for k, v in [pair.split('=', 1)]}
                outer.announces.append(params)
                if outer.fail:
                    self.send_error(503)
                    return
                if outer.dictionary:
                    peers = [{"ip": p.ip.encode(), "port": p.port} for p in outer.peers]
                else:
                    peers = b"".join(socket.inet_aton(p.ip) + struct.pack(">H", p.port) for p in outer.peers)
                body = bencode.encode({"interval": outer.interval, "peers": peers})
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        self.url = f'http://127.0.0.1:{self.server.server_port}/announce'
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": .05},
                                       name='fixture-http', daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(1)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class UDPTracker:
    def __init__(self, peers=None, *, mismatch=False, malformed=False, action_mismatch=False):
        self.peers = peers or []
        self.mismatch, self.malformed, self.action_mismatch = mismatch, malformed, action_mismatch
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', 0))
        self.sock.settimeout(.1)
        self.url = f'udp://127.0.0.1:{self.sock.getsockname()[1]}/announce'
        self.stop = threading.Event()
        self.connects, self.announces = 0, []
        self.thread = threading.Thread(target=self._run, name='fixture-udp', daemon=True)
        self.thread.start()

    def _run(self):
        while not self.stop.is_set():
            try:
                data, address = self.sock.recvfrom(4096)
                connection, action, transaction = struct.unpack('>QII', data[:16])
                if self.mismatch:
                    self.sock.sendto(struct.pack('>IIQ', action, transaction ^ 1, 42), address)
                if self.action_mismatch:
                    response = struct.pack('>IIQ', 9, transaction, 42)
                elif action == 0:
                    self.connects += 1
                    response = struct.pack('>IIQ', 0, transaction, 42)
                elif action == 1 and connection == 42:
                    self.announces.append(data)
                    response = struct.pack('>IIIII', 1, transaction, 1, 0, len(self.peers))
                    response += b''.join(socket.inet_aton(p.ip) + struct.pack('>H', p.port) for p in self.peers)
                else:
                    continue
                if self.malformed:
                    response = response[:10]
                self.sock.sendto(response, address)
            except socket.timeout:
                pass
            except (OSError, struct.error):
                if self.stop.is_set():
                    break

    def close(self):
        self.stop.set()
        self.sock.close()
        self.thread.join(1)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def main():
    import tempfile
    from dataclasses import asdict
    from pathlib import Path
    from app.download import download_file
    data = payload(1024 * 1024 + 17)
    torrent = Torrent.from_bytes(metainfo(data))
    with TCPPeer(torrent, data, pieces={0, 2, 4, 6, 8, 10, 12, 14, 16}) as a, \
            TCPPeer(torrent, data, pieces={1, 3, 5, 7, 9, 11, 13, 15}) as b, \
            HTTPTracker([a.peer, b.peer]) as tracker, tempfile.TemporaryDirectory() as directory:
        torrent.announce, torrent.tiers = tracker.url, [[tracker.url]]
        output = Path(directory) / 'demo.bin'
        stats = download_file(torrent, None, str(output))
        assert output.read_bytes() == data
        print('Local HTTP tracker + complementary TCP peers: exact content verified.')
        print(json.dumps(asdict(stats), indent=2))


if __name__ == '__main__':
    main()
