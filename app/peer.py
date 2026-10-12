"""A bounded BitTorrent v1 peer-wire connection with verified piece downloads."""

from __future__ import annotations

import hashlib
import socket
import struct
import time
from collections import deque

PROTOCOL_STRING = b"BitTorrent protocol"
HANDSHAKE_LEN = 68
RESERVED = b"\x00" * 8
BLOCK_SIZE = 2 ** 14
PIPELINE_DEPTH = 5
MAX_MESSAGE_SIZE = 2 ** 20  # Reject implausibly large inbound peer-wire frames.

MSG_CHOKE = 0
MSG_UNCHOKE = 1
MSG_INTERESTED = 2
MSG_BITFIELD = 5
MSG_REQUEST = 6
MSG_PIECE = 7


class IntegrityError(Exception):
    """A completed piece did not match its metainfo SHA-1 digest."""


class ProtocolError(ConnectionError):
    """A remote peer sent an invalid or unexpected protocol message."""


class PeerConnection:
    """One TCP peer connection; this downloader does not upload or seed."""

    def __init__(self, ip: str, port: int, info_hash: bytes, peer_id: bytes):
        if len(info_hash) != 20 or len(peer_id) != 20:
            raise ValueError("Info hash and peer ID must each contain 20 bytes")
        self.ip = ip
        self.port = port
        self.info_hash = info_hash
        self.peer_id = peer_id
        self.sock: socket.socket | None = None
        self.remote_peer_id: bytes | None = None
        self.num_pieces: int | None = None
        self.available: set[int] = set()
        self._first_message = True
        self._deadline = time.monotonic() + 30

    def __enter__(self) -> "PeerConnection":
        self.connect()
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def connect(self, timeout: float = 15.0) -> bytes:
        self._deadline = time.monotonic() + timeout
        self.sock = socket.create_connection((self.ip, self.port), timeout=timeout)
        try:
            handshake = bytes([len(PROTOCOL_STRING)]) + PROTOCOL_STRING + RESERVED + self.info_hash + self.peer_id
            self.sock.sendall(handshake)
            response = self._recv_exact(HANDSHAKE_LEN)
            if (response[0] != len(PROTOCOL_STRING)
                    or response[1:20] != PROTOCOL_STRING
                    or response[28:48] != self.info_hash):
                raise ProtocolError("Peer handshake does not match this torrent")
            self.remote_peer_id = response[48:68]
            return self.remote_peer_id
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        if self.sock is not None:
            self.sock.close()
            self.sock = None

    def prepare_download(self) -> None:
        """Express interest and wait for unchoke; bitfield is optional (BEP 3)."""
        self._deadline = time.monotonic() + 30
        self._send(MSG_INTERESTED)
        self._wait_for(MSG_UNCHOKE)

    def wait_available(self, index: int) -> None:
        while index not in self.available:
            self._recv_message()

    def download_piece(
        self, index: int, length: int, expected_hash: bytes,
        pipeline_depth: int = PIPELINE_DEPTH,
    ) -> bytes:
        self._deadline = time.monotonic() + 30
        if index < 0 or not 0 < length <= 16 * 1024 * 1024 or len(expected_hash) != 20 or pipeline_depth < 1:
            raise ValueError("Invalid piece index, size, hash, or pipeline depth")
        blocks = {
            begin: min(BLOCK_SIZE, length - begin)
            for begin in range(0, length, BLOCK_SIZE)
        }
        remaining = deque(blocks)
        inflight: dict[int, int] = {}
        received: set[int] = set()
        data = bytearray(length)

        while len(received) < len(blocks):
            while remaining and len(inflight) < pipeline_depth:
                begin = remaining.popleft()
                block_len = blocks[begin]
                self._send(MSG_REQUEST, struct.pack(">III", index, begin, block_len))
                inflight[begin] = block_len

            msg_id, payload = self._recv_message()
            if msg_id == MSG_CHOKE:
                # A choked peer may drop requests. Re-request unfinished blocks
                # after unchoke, rather than accepting untracked responses.
                self._wait_for(MSG_UNCHOKE)
                remaining = deque(begin for begin in blocks if begin not in received)
                inflight.clear()
            elif msg_id == MSG_PIECE:
                if len(payload) < 8:
                    raise ProtocolError("Truncated piece message")
                piece_index, begin = struct.unpack(">II", payload[:8])
                if piece_index != index:
                    raise ProtocolError("Piece response has an unexpected index")
                if begin in received:
                    continue  # An already-accepted response may arrive after a choke.
                expected_length = inflight.get(begin)
                if expected_length is None or len(payload) - 8 != expected_length:
                    raise ProtocolError("Unrequested or incorrectly sized piece block")
                data[begin:begin + expected_length] = payload[8:]
                received.add(begin)
                del inflight[begin]
            # Keepalive, HAVE and other unrelated messages do not complete blocks.

        digest = hashlib.sha1(data).digest()
        if digest != expected_hash:
            raise IntegrityError(
                f"Piece {index} failed SHA-1 verification "
                f"(expected {expected_hash.hex()}, got {digest.hex()})"
            )
        return bytes(data)

    def _send(self, msg_id: int, payload: bytes = b"") -> None:
        if self.sock is None:
            raise ConnectionError("Peer is not connected")
        body = bytes([msg_id]) + payload
        self.sock.sendall(struct.pack(">I", len(body)) + body)

    def _recv_message(self) -> tuple[int | None, bytes]:
        length = struct.unpack(">I", self._recv_exact(4))[0]
        if length == 0:
            return None, b""
        if length > MAX_MESSAGE_SIZE:
            raise ProtocolError("Peer-wire message exceeds the size limit")
        body = self._recv_exact(length)
        kind, payload = body[0], body[1:]
        if kind in (0, 1, 2, 3) and payload:
            raise ProtocolError("Invalid control message")
        if kind == 4:
            if len(payload) != 4:
                raise ProtocolError("Invalid HAVE")
            index = struct.unpack(">I", payload)[0]
            if self.num_pieces is not None and index >= self.num_pieces:
                raise ProtocolError("Invalid HAVE index")
            self.available.add(index)
        if kind == 5 and self.num_pieces is not None:
            spare = (-self.num_pieces) % 8
            if (not self._first_message or len(payload) != (self.num_pieces + 7) // 8
                    or (spare and payload[-1] & ((1 << spare) - 1))):
                raise ProtocolError("Invalid bitfield")
            self.available = {i for i in range(self.num_pieces) if payload[i // 8] & (128 >> (i % 8))}
        self._first_message = False
        return body[0], body[1:]

    def _wait_for(self, wanted_id: int) -> bytes:
        while True:
            msg_id, payload = self._recv_message()
            if msg_id == wanted_id:
                return payload

    def _recv_exact(self, count: int) -> bytes:
        if self.sock is None:
            raise ConnectionError("Peer is not connected")
        chunks = []
        while count > 0:
            remaining = self._deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Peer operation deadline expired")
            if hasattr(self.sock, "settimeout"):
                self.sock.settimeout(remaining)
            chunk = self.sock.recv(count)
            if not chunk:
                raise ConnectionError("Peer closed the connection unexpectedly")
            chunks.append(chunk)
            count -= len(chunk)
        return b"".join(chunks)
