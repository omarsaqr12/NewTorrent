"""Deterministic offline regression tests; no tracker or internet is contacted."""

import hashlib
import io
import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import bencode, download, main
from app.peer import (BLOCK_SIZE, HANDSHAKE_LEN, MSG_INTERESTED, MSG_PIECE,
                      MSG_REQUEST, MSG_UNCHOKE, PROTOCOL_STRING,
                      IntegrityError, PeerConnection, ProtocolError)
from app.torrent import Torrent
from app.tracker import Peer, _parse_compact_peers

INFO_HASH = b"h" * 20
PEER_ID = b"p" * 20


def frame(message_id, payload=b""):
    body = bytes([message_id]) + payload
    return struct.pack(">I", len(body)) + body


class FakeSocket:
    def __init__(self, incoming=b""):
        self.incoming = bytearray(incoming)
        self.sent = []
        self.closed = False

    def recv(self, length):
        chunk = bytes(self.incoming[:length])
        del self.incoming[:length]
        return chunk

    def sendall(self, payload):
        self.sent.append(payload)

    def close(self):
        self.closed = True


class BencodeTests(unittest.TestCase):
    def test_binary_round_trip_and_canonical_keys(self):
        value = {"z": [b"\x00\xff", -12], "a": b"hello"}
        self.assertEqual(bencode.decode(bencode.encode(value)), value)
        self.assertTrue(bencode.encode(value).startswith(b"d1:a"))

    def test_truncated_and_noncanonical_values_rejected(self):
        for raw in (b"", b"4:abc", b"i1", b"i01e", b"i-0e", b"i-e",
                    b"l1:a", b"d1:a", b"d1:bi1e1:ai2ee",
                    b"d1:ai1e1:ai2ee", b"i1ee", b"02:hi"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                bencode.decode(raw)

    def test_nonstring_dictionary_keys_rejected(self):
        with self.assertRaises(TypeError):
            bencode.encode({1: "bad"})


class TorrentTests(unittest.TestCase):
    def make_metainfo(self, **overrides):
        info = {"name": b"sample", "length": 5, "piece length": 4,
                "pieces": hashlib.sha1(b"abcd").digest() + hashlib.sha1(b"e").digest()}
        info.update(overrides)
        return bencode.encode({"announce": b"http://example.test/announce", "info": info})

    def test_piece_layout(self):
        torrent = Torrent.from_bytes(self.make_metainfo())
        self.assertEqual((torrent.num_pieces, torrent.piece_size(0), torrent.piece_size(1)), (2, 4, 1))
        with self.assertRaises(IndexError):
            torrent.piece_size(-1)
        with self.assertRaises(IndexError):
            torrent.piece_size(2)

    def test_inconsistent_layout_rejected(self):
        for changes in ({"piece length": 0}, {"length": -1},
                        {"pieces": b"x" * 20}, {"pieces": b"x" * 19},
                        {"files": []}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                Torrent.from_bytes(self.make_metainfo(**changes))


class PeerTests(unittest.TestCase):
    def connection(self, incoming=b""):
        peer = PeerConnection("127.0.0.1", 1234, INFO_HASH, PEER_ID)
        sock = FakeSocket(incoming)
        peer.sock = sock
        return peer, sock

    def test_handshake_checks_info_hash_and_closes_failed_socket(self):
        valid = bytes([19]) + PROTOCOL_STRING + bytes(8) + INFO_HASH + PEER_ID
        self.assertEqual(len(valid), HANDSHAKE_LEN)
        for handshake, accepted in ((valid, True), (valid[:28] + b"x" * 20 + PEER_ID, False),
                                    (bytes([19]) + b"X" * 19 + valid[20:], False)):
            sock = FakeSocket(handshake)
            peer = PeerConnection("127.0.0.1", 1, INFO_HASH, PEER_ID)
            with patch("app.peer.socket.create_connection", return_value=sock):
                if accepted:
                    self.assertEqual(peer.connect(), PEER_ID)
                    peer.close()
                else:
                    with self.assertRaises(ProtocolError):
                        peer.connect()
            self.assertTrue(sock.closed)

    def test_unchoke_without_bitfield(self):
        peer, sock = self.connection(frame(MSG_UNCHOKE))
        peer.prepare_download()
        self.assertEqual(sock.sent, [frame(MSG_INTERESTED)])

    def test_out_of_order_pipeline_blocks_verified(self):
        first, second = b"a" * BLOCK_SIZE, b"b" * 3
        replies = (frame(MSG_PIECE, struct.pack(">II", 0, BLOCK_SIZE) + second) +
                   frame(MSG_PIECE, struct.pack(">II", 0, 0) + first))
        peer, sock = self.connection(replies)
        self.assertEqual(peer.download_piece(0, len(first + second), hashlib.sha1(first + second).digest(), 2), first + second)
        self.assertEqual(len(sock.sent), 2)
        self.assertTrue(all(message[4] == MSG_REQUEST for message in sock.sent))

    def test_reject_unrequested_short_and_wrong_index_blocks(self):
        data = b"good"
        good_hash = hashlib.sha1(data).digest()
        for payload in (struct.pack(">II", 0, 10) + data,
                        struct.pack(">II", 0, 0) + data[:-1],
                        struct.pack(">II", 1, 0) + data,
                        b"short"):
            with self.subTest(payload=payload):
                peer, _ = self.connection(frame(MSG_PIECE, payload))
                with self.assertRaises(ProtocolError):
                    peer.download_piece(0, len(data), good_hash)

    def test_hash_mismatch_and_depth_validation(self):
        peer, _ = self.connection(frame(MSG_PIECE, struct.pack(">II", 0, 0) + b"bad"))
        with self.assertRaises(IntegrityError):
            peer.download_piece(0, 3, hashlib.sha1(b"ok!").digest())
        with self.assertRaises(ValueError):
            peer.download_piece(0, 3, b"h" * 20, 0)

    def test_reject_oversized_message_before_reading_body(self):
        peer, _ = self.connection(struct.pack(">I", 2 ** 20 + 1))
        with self.assertRaises(ProtocolError):
            peer._recv_message()


class DownloadTests(unittest.TestCase):
    def setUp(self):
        self.parts = [b"abcd", b"e"]
        self.torrent = Torrent("http://example.test", "sample", 5, 4,
                               [hashlib.sha1(x).digest() for x in self.parts], INFO_HASH)
        self.peers = [Peer("127.0.0.1", 1234)]

    def test_publish_only_complete_file_and_preserve_existing_on_failure(self):
        class OfflineConnection:
            fail = False

            def __init__(self, *args):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def prepare_download(self):
                pass

            def download_piece(self, index, *args):
                if self.fail:
                    raise ConnectionError("offline peer failure")
                return [b"abcd", b"e"][index]

        with tempfile.TemporaryDirectory() as directory:
            dest = Path(directory) / "existing.bin"
            dest.write_bytes(b"ORIGINAL")
            with patch("app.download.PeerConnection", OfflineConnection):
                OfflineConnection.fail = True
                with self.assertRaises(RuntimeError):
                    download.download_file(self.torrent, self.peers, str(dest))
                self.assertEqual(dest.read_bytes(), b"ORIGINAL")
                self.assertEqual(list(Path(directory).iterdir()), [dest])
                OfflineConnection.fail = False
                download.download_file(self.torrent, self.peers, str(dest))
                self.assertEqual(dest.read_bytes(), b"abcde")
                self.assertEqual(list(Path(directory).iterdir()), [dest])

    def test_no_peers_does_not_touch_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            with self.assertRaises(RuntimeError):
                download.download_file(self.torrent, [], str(output))
            self.assertFalse(output.exists())


class TrackerAndCliTests(unittest.TestCase):
    def test_compact_peer_entry(self):
        self.assertEqual(_parse_compact_peers(b"\x7f\x00\x00\x01\x1a\xe1"), [Peer("127.0.0.1", 6881)])
        for bad in (b"short", b"\x7f\x00\x00\x01\x00\x00"):
            with self.assertRaises(ValueError):
                _parse_compact_peers(bad)

    def test_missing_output_arguments_are_usage_errors(self):
        for args in ([], ["-o"], ["-o", "dest"], ["-o", "dest", "file", "extra"]):
            with self.subTest(args=args), self.assertRaises(SystemExit):
                main._parse_output_args(args, extra=0)


if __name__ == "__main__":
    unittest.main()
