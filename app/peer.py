"""The BitTorrent peer-wire protocol over a single TCP connection.

A :class:`PeerConnection` performs the handshake, exchanges peer-wire messages,
and downloads individual pieces. Block requests are *pipelined*: several
``request`` messages are kept in flight at once instead of the slow
request-wait-request-wait pattern, which keeps the TCP pipe full and is the
main reason a real client is dramatically faster than a naive one.

Every completed piece is verified against the SHA-1 digest from the torrent's
metainfo before it is accepted.
"""

from __future__ import annotations

import hashlib
import socket
import struct

PROTOCOL_STRING = b"BitTorrent protocol"
HANDSHAKE_LEN = 68
RESERVED = b"\x00" * 8

BLOCK_SIZE = 2 ** 14  # 16 KiB, the standard maximum block size.
PIPELINE_DEPTH = 5    # Number of block requests kept in flight per piece.

# Peer-wire message identifiers.
MSG_CHOKE = 0
MSG_UNCHOKE = 1
MSG_INTERESTED = 2
MSG_BITFIELD = 5
MSG_REQUEST = 6
MSG_PIECE = 7


class IntegrityError(Exception):
    """Raised when a downloaded piece fails its SHA-1 check."""


class PeerConnection:
    """A handshaked TCP connection to a single peer."""

    def __init__(self, ip: str, port: int, info_hash: bytes, peer_id: bytes):
        self.ip = ip
        self.port = port
        self.info_hash = info_hash
        self.peer_id = peer_id
        self.sock: socket.socket | None = None
        self.remote_peer_id: bytes | None = None

    # -- connection lifecycle ------------------------------------------------

    def __enter__(self) -> "PeerConnection":
        self.connect()
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def connect(self, timeout: float = 15.0) -> bytes:
        """Open the socket and complete the BitTorrent handshake."""
        self.sock = socket.create_connection((self.ip, self.port), timeout=timeout)
        handshake = (
            bytes([len(PROTOCOL_STRING)])
            + PROTOCOL_STRING
            + RESERVED
            + self.info_hash
            + self.peer_id
        )
        self.sock.sendall(handshake)
        response = self._recv_exact(HANDSHAKE_LEN)
        self.remote_peer_id = response[48:68]
        return self.remote_peer_id

    def close(self) -> None:
        if self.sock is not None:
            self.sock.close()
            self.sock = None

    # -- download ------------------------------------------------------------

    def prepare_download(self) -> None:
        """Exchange the messages required before requesting blocks.

        Waits for the peer's ``bitfield``, expresses ``interested``, then blocks
        until the peer sends ``unchoke``.
        """
        self._wait_for(MSG_BITFIELD)
        self._send(MSG_INTERESTED)
        self._wait_for(MSG_UNCHOKE)

    def download_piece(self, index: int, length: int, expected_hash: bytes) -> bytes:
        """Download and verify a single piece, using a pipelined request window."""
        blocks = [
            (begin, min(BLOCK_SIZE, length - begin))
            for begin in range(0, length, BLOCK_SIZE)
        ]
        data = bytearray(length)
        next_request = 0
        outstanding = 0
        received = 0

        while received < len(blocks):
            # Keep the request window full.
            while outstanding < PIPELINE_DEPTH and next_request < len(blocks):
                begin, block_len = blocks[next_request]
                self._send(MSG_REQUEST, struct.pack(">III", index, begin, block_len))
                next_request += 1
                outstanding += 1

            msg_id, payload = self._recv_message()
            if msg_id == MSG_PIECE:
                begin = struct.unpack(">I", payload[4:8])[0]
                block = payload[8:]
                data[begin : begin + len(block)] = block
                outstanding -= 1
                received += 1
            elif msg_id == MSG_CHOKE:
                # The peer choked us mid-piece; wait for a fresh unchoke and
                # re-send the outstanding window.
                self._wait_for(MSG_UNCHOKE)
                next_request -= outstanding
                outstanding = 0
            # Any other message (have, keepalive, ...) is ignored.

        digest = hashlib.sha1(data).digest()
        if digest != expected_hash:
            raise IntegrityError(
                f"Piece {index} failed SHA-1 verification "
                f"(expected {expected_hash.hex()}, got {digest.hex()})"
            )
        return bytes(data)

    # -- message framing -----------------------------------------------------

    def _send(self, msg_id: int, payload: bytes = b"") -> None:
        body = bytes([msg_id]) + payload
        self.sock.sendall(struct.pack(">I", len(body)) + body)

    def _recv_message(self):
        """Receive one peer-wire message as ``(msg_id, payload)``.

        A keepalive (zero-length) message is returned as ``(None, b"")``.
        """
        length = struct.unpack(">I", self._recv_exact(4))[0]
        if length == 0:
            return None, b""
        body = self._recv_exact(length)
        return body[0], body[1:]

    def _wait_for(self, wanted_id: int) -> bytes:
        """Read messages until one with ``wanted_id`` arrives; return its payload."""
        while True:
            msg_id, payload = self._recv_message()
            if msg_id == wanted_id:
                return payload

    def _recv_exact(self, count: int) -> bytes:
        """Read exactly ``count`` bytes, looping until the buffer is full."""
        chunks = []
        remaining = count
        while remaining > 0:
            chunk = self.sock.recv(remaining)
            if not chunk:
                raise ConnectionError("Peer closed the connection unexpectedly")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
