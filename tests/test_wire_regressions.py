"""End-to-end peer-wire simulations without external network access."""

import hashlib
import struct
import unittest
from unittest.mock import patch

from app import bencode, download, tracker
from app.peer import MSG_CHOKE, MSG_PIECE, MSG_REQUEST, MSG_UNCHOKE, PROTOCOL_STRING, PeerConnection
from app.torrent import Torrent
from app.tracker import Peer

INFO_HASH = b"i" * 20
PEER_ID = b"p" * 20


def message(kind, data=b""):
    payload = bytes([kind]) + data
    return struct.pack(">I", len(payload)) + payload


class WireSocket:
    def __init__(self, data):
        self.data = bytearray(data)
        self.sent = []
        self.closed = False

    def recv(self, count):
        chunk = bytes(self.data[:count])
        del self.data[:count]
        return chunk

    def sendall(self, payload):
        self.sent.append(payload)

    def close(self):
        self.closed = True


class WireRegressions(unittest.TestCase):
    def test_choke_then_unchoke_retransmits_missing_block(self):
        data = b"good"
        wire = (message(MSG_CHOKE) + message(MSG_UNCHOKE) +
                message(MSG_PIECE, struct.pack(">II", 0, 0) + data))
        sock = WireSocket(wire)
        conn = PeerConnection("127.0.0.1", 1234, INFO_HASH, PEER_ID)
        conn.sock = sock
        self.assertEqual(conn.download_piece(0, 4, hashlib.sha1(data).digest()), data)
        self.assertEqual(len(sock.sent), 2)
        self.assertTrue(all(sent[4] == MSG_REQUEST for sent in sock.sent))

    def test_corrupt_peer_is_retried_against_another_peer(self):
        handshake = bytes([19]) + PROTOCOL_STRING + bytes(8) + INFO_HASH + PEER_ID
        def scripted(block):
            return WireSocket(handshake + message(MSG_UNCHOKE) +
                              message(MSG_PIECE, struct.pack(">II", 0, 0) + block))
        sockets = {"bad": scripted(b"evil"), "good": scripted(b"good")}
        torrent = Torrent("http://example.test", "sample", 4, 4,
                          [hashlib.sha1(b"good").digest()], INFO_HASH)
        def connect(address, timeout):
            return sockets[address[0]]
        with patch("app.peer.socket.create_connection", side_effect=connect):
            result = download.download_piece(torrent, [Peer("bad", 1), Peer("good", 2)], 0)
        self.assertEqual(result, b"good")
        self.assertTrue(all(sock.closed for sock in sockets.values()))

    def test_invalid_tracker_payload_fails_with_clear_error(self):
        torrent = Torrent("http://example.test", "sample", 0, 1, [], INFO_HASH)
        class Response:
            def __init__(self, body):
                self.content = bencode.encode(body)
            def raise_for_status(self):
                pass
        for body in ([], {"peers": b"partial"}, {"peers": []}):
            with self.subTest(body=body), patch("app.tracker.requests.get", return_value=Response(body)):
                with self.assertRaises(ValueError):
                    tracker.get_peers(torrent)


if __name__ == "__main__":
    unittest.main()
