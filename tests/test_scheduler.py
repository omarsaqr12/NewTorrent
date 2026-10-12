import unittest

from app.scheduler import Scheduler
from app.torrent import Torrent, safe_component
from app.tracker import Announcer, Peer, parse_response
from app import bencode
from tools.swarm import metainfo, payload


class SchedulerTests(unittest.TestCase):
    def setUp(self):
        self.torrent = Torrent.from_bytes(metainfo(payload(4 * 16384), piece_length=16384))

    def test_rarest_first_counts_have_and_disconnect(self):
        scheduler = Scheduler(self.torrent, set(), endgame=0, max_active=1)
        scheduler.update(1, {0, 1, 2, 3})
        scheduler.update(2, {0, 1, 2})
        self.assertEqual(scheduler.request(1)[0], 3)
        self.assertIsNone(scheduler.request(1))
        scheduler.update(2, {0, 1, 2, 3})
        self.assertEqual(scheduler.availability, [2, 2, 2, 2])
        scheduler.disconnect(1)
        self.assertEqual(scheduler.pending, 0)
        self.assertEqual(scheduler.availability, [1, 1, 1, 1])
        self.assertEqual(scheduler.request(2)[0], 3)

    def test_empty_availability_is_not_full(self):
        scheduler = Scheduler(self.torrent, set())
        scheduler.update(1, set())
        self.assertIsNone(scheduler.request(1))

    def test_ownership_duplicate_cap_and_exactly_once_acceptance(self):
        torrent = Torrent.from_bytes(metainfo(b'good', piece_length=4))
        scheduler = Scheduler(torrent, set(), endgame=1)
        for peer in (1, 2, 3):
            scheduler.update(peer, {0})
        block = scheduler.request(1)
        self.assertEqual(scheduler.request(2), block)
        self.assertIsNone(scheduler.request(3))
        losers, data, corrupt = scheduler.accept(1, block, b'good')
        self.assertEqual(losers, [(2, block)])
        self.assertEqual(data, b'good')
        self.assertEqual(corrupt, set())
        self.assertEqual(scheduler.pending, 0)
        with self.assertRaises(ConnectionError):
            scheduler.accept(2, block, b'good')

    def test_corruption_attributes_all_contributors_without_certainty(self):
        torrent = Torrent.from_bytes(metainfo(payload(32768), piece_length=32768))
        scheduler = Scheduler(torrent, set(), endgame=0)
        scheduler.update(1, {0})
        scheduler.update(2, {0})
        a, b = scheduler.request(1), scheduler.request(2)
        scheduler.accept(1, a, bytes(a[2]))
        _, data, suspects = scheduler.accept(2, b, bytes(b[2]))
        self.assertIsNone(data)
        self.assertEqual(suspects, {1, 2})
        self.assertEqual(scheduler.remaining, 2)
        a = scheduler.request(1)
        self.assertIsNone(scheduler.request(2))
        scheduler.accept(1, a, payload(32768)[:a[2]])
        scheduler.disconnect(1)
        self.assertEqual(scheduler.remaining, 2)
        for _ in range(2):
            block = scheduler.request(2)
            _, data, suspects = scheduler.accept(
                2, block, payload(32768)[block[1]:block[1] + block[2]])
        self.assertEqual(data, payload(32768))
        self.assertEqual(suspects, set())
        self.assertEqual(scheduler.pending, 0)
        self.assertEqual(scheduler.remaining, 0)
        self.assertFalse(scheduler.isolated)

    def test_codec_limits_and_unsafe_paths(self):
        with self.assertRaises(ValueError):
            bencode.decode(b'l' * 66 + b'e' * 66)
        with self.assertRaises(ValueError):
            bencode.decode(b'3:abc', max_size=4)
        for path in (b'..', b'/tmp', b'C:foo', b'a\\b', b'CON', b'a.', b'a\x00b'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                safe_component(path)
        for files in ([(('a',), 2), (('A',), 2)], [(('a',), 2), (('a', 'b'), 2)]):
            with self.assertRaises(ValueError):
                Torrent.from_bytes(metainfo(b'good', piece_length=4, files=files))

    def test_tracker_parsing_limits_and_validation(self):
        response = bencode.encode({'interval': 1, 'peers': [
            {'ip': b'127.0.0.1', 'port': 1234}, {'ip': b'127.0.0.1', 'port': 1234}]})
        self.assertEqual(parse_response(response), ([Peer('127.0.0.1', 1234)], 1))
        for ip in (b'0.0.0.0', b'224.0.0.1', b'invalid', b'::1'):
            with self.assertRaises(ValueError):
                parse_response(bencode.encode({'interval': 1, 'peers': [{'ip': ip, 'port': 1}]}))

    def test_udp_retry_timing_with_fake_clock(self):
        now, sends = [0.0], []
        class Socket:
            def send(self, _packet):
                sends.append(now[0])
        def wait(_sock, seconds):
            now[0] += seconds
            return []
        announcer = Announcer(self.torrent, timeout=106, clock=lambda: now[0], udp_wait=wait)
        for attempt in range(3):
            with self.assertRaises(TimeoutError):
                announcer._exchange(Socket(), b'packet', 0, 1, now[0] + 15 * 2 ** attempt)
        self.assertEqual(sends, [0, 15, 45])


if __name__ == '__main__':
    unittest.main()
