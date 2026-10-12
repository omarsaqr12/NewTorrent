"""Precise state-transition tests supplement real-socket integration cases."""
import socket
import struct
import tempfile
import time
import unittest
from pathlib import Path

from app.engine import Engine, Options, Session
from app.peer import ProtocolError
from app.storage import Storage
from app.torrent import Torrent
from app.tracker import Peer
from tools.swarm import metainfo


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.torrent = Torrent.from_bytes(metainfo(b'goodMORE', piece_length=4))
        self.storage = Storage(self.torrent, str(Path(self.directory.name) / 'out'))
        self.addCleanup(self.storage.close)
        self.engine = Engine(self.torrent, self.storage, [], options=Options(endgame=2))
        self.addCleanup(self.engine.selector.close)
        self.sessions = []
        for index in (1, 2):
            sock = socket.socket()
            self.addCleanup(sock.close)
            session = Session(index, Peer('127.0.0.1', index), sock, 'ready', 0, time.monotonic())
            self.engine.sessions[index] = session
            self.sessions.append(session)

    def test_bitfield_length_padding_order_and_have_bounds(self):
        for payload in (b'', b'\xc1', b'\xc0\x00'):
            with self.subTest(payload=payload), self.assertRaises(ProtocolError):
                self.engine._message(self.sessions[0], 5, payload, time.monotonic())
        self.engine._message(self.sessions[0], 5, b'\xc0', time.monotonic())
        self.assertEqual(self.engine.scheduler.availability, [1, 1])
        with self.assertRaises(ProtocolError):
            self.engine._message(self.sessions[0], 5, b'\xc0', time.monotonic())
        with self.assertRaises(ProtocolError):
            self.engine._message(self.sessions[0], 4, struct.pack('>I', 2), time.monotonic())

    def test_late_cancel_and_choke_responses_are_bounded_and_not_committed_twice(self):
        first, second = self.sessions
        now = time.monotonic()
        for session in self.sessions:
            self.engine.scheduler.update(session.id, {0, 1})
        a = self.engine.scheduler.request(first.id)
        b = self.engine.scheduler.request(first.id)
        duplicate = self.engine.scheduler.request(second.id)
        for block in (a, b):
            first.pending[block] = now
        second.pending[duplicate] = now
        index = duplicate[0]
        data = [b'good', b'MORE'][index]
        response = struct.pack('>II', index, 0) + data
        self.engine._message(first, 7, response, now)
        self.assertNotIn(duplicate, second.pending)
        self.assertEqual(self.engine.stats.cancels, 1)
        self.engine._message(second, 7, response, now)
        self.assertEqual(self.engine.stats.duplicate_bytes, 4)
        self.assertEqual(self.engine.stats.verified_bytes, 4)
        outstanding = next(iter(first.pending))
        self.engine._message(first, 0, b'', now)
        self.engine._message(first, 7, struct.pack('>II', outstanding[0], 0) + [b'good', b'MORE'][outstanding[0]], now)
        self.assertEqual(self.engine.stats.verified_bytes, 4)
        with self.assertRaises(ProtocolError):
            self.engine._message(second, 7, struct.pack('>II', 999, 0) + b'evil', now)
