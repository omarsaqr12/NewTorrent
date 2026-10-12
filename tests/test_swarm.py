"""Bounded real-loopback integration tests. No public trackers or peers."""
import json
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from app.download import download_file, download_piece
from app.engine import Options
from app.storage import Storage
from app.torrent import Torrent
from app.tracker import Announcer
from tools.swarm import HTTPTracker, TCPPeer, UDPTracker, metainfo, payload


def fast_options(**kwargs):
    values = dict(connect_timeout=.25, handshake_timeout=.25, request_timeout=.25,
                  inactivity_timeout=.5, no_progress_timeout=3, backoff=.03, max_retries=1)
    values.update(kwargs)
    return Options(**values)


class SwarmTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.directory = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.output = self.directory / 'result'
        self.data = payload(262144 + 13)
        self.torrent = Torrent.from_bytes(metainfo(self.data))

    def peer(self, **kwargs):
        return self.stack.enter_context(TCPPeer(self.torrent, self.data, **kwargs))

    def run_download(self, peers, **kwargs):
        stats = download_file(self.torrent, peers, str(self.output), options=fast_options(**kwargs))
        self.assertEqual(self.output.read_bytes(), self.data)
        self.assertFalse(Path(str(self.output) + '.newtorrent').exists())
        self.assertLessEqual(stats.peak_pending, kwargs.get('max_pending', 128))
        self.assertLessEqual(stats.peak_active, kwargs.get('max_active', 8))
        return stats

    def test_complementary_availability_have_and_rare_piece(self):
        a = self.peer(pieces={0, 2}, have_after=(.08, {4}))
        b = self.peer(pieces={1, 3}, bitfield=False)
        self.run_download([a.peer, b.peer])
        self.assertEqual(a.invalid_requests + b.invalid_requests, 0)
        self.assertIn(4, [request[0] for request in a.requests])

    def test_no_initial_bitfield_later_have_announcements(self):
        peer = self.peer(pieces=set(), bitfield=False,
                         have_after=(.05, set(range(self.torrent.num_pieces))))
        self.run_download([peer.peer])
        self.assertEqual(peer.invalid_requests, 0)

    def test_fragmentation_coalescing_reorder_choke_and_duplicates(self):
        peer = self.peer(fragment=True, reorder=True, choke_once=True, duplicate=True)
        stats = self.run_download([peer.peer], request_timeout=1, inactivity_timeout=2, no_progress_timeout=8)
        self.assertGreater(stats.duplicate_bytes, 0)

    def test_churn_releases_blocks_preserving_usable_progress(self):
        churn = self.peer(disconnect_after=3)
        good = self.peer(delay=.005)
        stats = self.run_download([churn.peer, good.peer], window=2)
        self.assertGreater(stats.retries, 0)

    def test_silent_keepalive_malformed_and_corrupt_peer_recovery(self):
        for behavior in ({'silent': True}, {'keepalive': True}, {'malformed': True}, {'corrupt': True}):
            with self.subTest(behavior=behavior):
                bad = self.peer(**behavior)
                good = self.peer(delay=.01)
                stats = self.run_download([bad.peer, good.peer], endgame=0, window=4)
                if behavior.get('corrupt'):
                    self.assertGreater(stats.hash_failures, 0)
                self.output.unlink()

    def test_keepalive_only_swarm_has_bounded_failure_and_releases_lock(self):
        bad = self.peer(keepalive=True)
        start = time.monotonic()
        with self.assertRaisesRegex(RuntimeError, 'progress'):
            download_file(self.torrent, [bad.peer], str(self.output),
                          options=fast_options(no_progress_timeout=.6))
        self.assertLess(time.monotonic() - start, 2)
        self.assertFalse(self.output.exists())
        with Storage(self.torrent, str(self.output)):
            pass  # kernel lock released on failure

    def test_endgame_cancels_losing_requests(self):
        self.data = payload(65536)
        self.torrent = Torrent.from_bytes(metainfo(self.data))
        slow = self.peer(delay=.15)
        fast = self.peer(delay=.005)
        stats = self.run_download([slow.peer, fast.peer], window=4, endgame=8)
        self.assertGreater(stats.cancels, 0)
        deadline = time.monotonic() + .5
        while not slow.cancels and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertTrue(slow.cancels)

    def test_resource_limits_and_no_duplicate_normal_requests(self):
        a, b = self.peer(), self.peer()
        stats = self.run_download([a.peer, b.peer], endgame=0, max_active=1,
                                  max_pending=3, window=5, max_peers=1,
                                  max_buffer_bytes=65536, max_discovery=1)
        self.assertEqual(len(a.requests), len(set(a.requests)))
        self.assertEqual(b.requests, [])
        self.assertEqual(stats.peak_peers, 1)
        with self.assertRaises(ValueError):
            Options(max_buffer_bytes=10).validate(self.torrent)

    def test_cooperative_interruption_resume_and_checkpoint_corruption(self):
        peer = self.peer(delay=.02)
        stop = threading.Event()
        def progress(stats, _):
            if stats.verified_bytes:
                stop.set()
        with self.assertRaises(InterruptedError):
            download_file(self.torrent, [peer.peer], str(self.output), options=fast_options(window=1),
                          stop=stop, progress=progress)
        stage = Path(str(self.output) + '.newtorrent')
        (stage / 'checkpoint.json').write_text('{truncated')
        before = len(peer.requests)
        stats = self.run_download([peer.peer], window=1)
        self.assertGreater(stats.resumed_bytes, 0)
        self.assertLess(sum(b[2] for b in peer.requests[before:]), len(self.data))

    def test_killed_subprocess_then_verified_resume(self):
        self.data = payload(1024 * 1024)
        self.torrent = Torrent.from_bytes(metainfo(self.data))
        peer = self.peer(delay=.025)
        tracker = self.stack.enter_context(HTTPTracker([peer.peer]))
        torrent_path = self.directory / 'fixture.torrent'
        torrent_path.write_bytes(metainfo(self.data, announce=tracker.url))
        process = subprocess.Popen([sys.executable, '-m', 'app.main', 'download', '-o', str(self.output),
                                    str(torrent_path), '--window', '1', '--quiet'],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        checkpoint = Path(str(self.output) + '.newtorrent') / 'checkpoint.json'
        deadline = time.monotonic() + 8
        verified = []
        try:
            while time.monotonic() < deadline and process.poll() is None:
                try:
                    verified = json.loads(checkpoint.read_text())['verified']
                except (OSError, ValueError):
                    pass
                if verified:
                    break
                time.sleep(.02)
            self.assertTrue(verified, 'Subprocess made no verified progress')
        finally:
            process.kill()
            process.communicate(timeout=3)
        before = len(peer.requests)
        stats = self.run_download([peer.peer])
        self.assertGreater(stats.resumed_bytes, 0)
        self.assertLess(sum(b[2] for b in peer.requests[before:]), len(self.data))

    def test_modified_verified_piece_and_missing_partial_data(self):
        with Storage(self.torrent, str(self.output)) as store:
            store.commit(0, self.data[:65536])
            store.commit(1, self.data[65536:131072])
        stage = Path(str(self.output) + '.newtorrent')
        with open(stage / 'data', 'r+b') as handle:
            handle.write(b'X')
        with Storage(self.torrent, str(self.output)) as store:
            self.assertNotIn(0, store.verified)
            self.assertIn(1, store.verified)
        (stage / 'data').unlink()
        with Storage(self.torrent, str(self.output)) as store:
            self.assertEqual(store.verified, set())
        self.run_download([self.peer().peer])

    def test_fully_verified_resume_needs_no_peers(self):
        with Storage(self.torrent, str(self.output)) as store:
            for index in range(self.torrent.num_pieces):
                store.commit(index, self.data[index * 65536:(index + 1) * 65536])
        stats = self.run_download([])
        self.assertEqual(stats.requested_bytes, 0)
        self.assertEqual(stats.resumed_bytes, len(self.data))

    def test_truncated_payload_and_mismatched_identity(self):
        with Storage(self.torrent, str(self.output)) as store:
            store.commit(0, self.data[:65536])
        stage = Path(str(self.output) + '.newtorrent')
        with open(stage / 'data', 'r+b') as handle:
            handle.truncate(42)
        with Storage(self.torrent, str(self.output)) as store:
            self.assertEqual(store.verified, set())
        other = Torrent.from_bytes(metainfo(payload(len(self.data), seed=2)))
        with self.assertRaisesRegex(ValueError, 'identity'):
            Storage(other, str(self.output))
        self.run_download([self.peer().peer])

    def test_multifile_cross_boundaries_zero_files_and_short_piece(self):
        files = [(('nested', 'a'), 3), (('empty',), 0), (('b',), 65539),
                 (('nested', 'c'), len(self.data) - 65542)]
        self.torrent = Torrent.from_bytes(metainfo(self.data, files=files))
        peer = self.peer()
        stats = download_file(self.torrent, [peer.peer], str(self.output), options=fast_options())
        self.assertEqual(stats.verified_bytes, len(self.data))
        concatenated = b''.join(self.output.joinpath(*parts).read_bytes() for parts, _ in files)
        self.assertEqual(concatenated, self.data)
        self.assertEqual((self.output / 'empty').stat().st_size, 0)
        with self.assertRaises(FileExistsError):
            Storage(self.torrent, str(self.output), overwrite=True)

    def test_disk_failure_preserves_existing_destination(self):
        self.output.write_bytes(b'old')
        peer = self.peer()
        with patch.object(Storage, 'commit', side_effect=OSError('disk full')):
            with self.assertRaisesRegex(RuntimeError, 'Disk commit'):
                download_file(self.torrent, [peer.peer], str(self.output), overwrite=True, options=fast_options())
        self.assertEqual(self.output.read_bytes(), b'old')
        with Storage(self.torrent, str(self.output), overwrite=True):
            pass

    def test_lock_collision_and_corrupt_identity(self):
        with Storage(self.torrent, str(self.output)):
            with self.assertRaisesRegex(RuntimeError, 'Another process'):
                Storage(self.torrent, str(self.output))
        identity = Path(str(self.output) + '.newtorrent') / 'identity.json'
        identity.write_text('{broken')
        with self.assertRaisesRegex(ValueError, 'identity'):
            Storage(self.torrent, str(self.output))

    def test_symlink_escape_rejected(self):
        link = self.directory / 'escape'
        try:
            link.symlink_to(self.directory, target_is_directory=True)
        except OSError:
            self.skipTest('Host does not grant symlink creation')
        with self.assertRaisesRegex(ValueError, 'Symlink|Reparse'):
            Storage(self.torrent, str(link / 'outside'))

    def test_http_formats_tier_failover_binary_encoding_and_lifecycle(self):
        self.data = payload(1024 * 1024)
        self.torrent = Torrent.from_bytes(metainfo(self.data))
        peer = self.peer(delay=.02)
        for dictionary in (False, True):
            primary = self.stack.enter_context(HTTPTracker(fail=True))
            backup = self.stack.enter_context(HTTPTracker([peer.peer, peer.peer], dictionary=dictionary))
            self.torrent.tiers = [[primary.url], [backup.url]]
            stats = self.run_download(None, window=1, request_timeout=1, inactivity_timeout=2, no_progress_timeout=8)
            events = [a.get(b'event', b'') for a in backup.announces]
            self.assertEqual(events[0], b'started')
            self.assertIn(b'', events)
            self.assertIn(b'completed', events)
            self.assertEqual(events[-1], b'stopped')
            self.assertTrue(primary.announces)
            self.assertTrue(all(a[b'info_hash'] == self.torrent.info_hash for a in backup.announces))
            self.assertEqual(backup.announces[-1][b'left'], b'0')
            self.assertEqual(int(backup.announces[-1][b'downloaded']), stats.downloaded_bytes)
            self.output.unlink()

    def test_udp_mismatch_ignored_expiry_reconnect_and_download(self):
        peer = self.peer()
        tracker = self.stack.enter_context(UDPTracker([peer.peer], mismatch=True))
        self.torrent.tiers = [[tracker.url]]
        clock = [0.0]
        announcer = Announcer(self.torrent, timeout=.5, clock=lambda: clock[0])
        self.assertEqual(announcer.announce('started')[0], [peer.peer])
        clock[0] = 61
        self.assertEqual(announcer.announce()[0], [peer.peer])
        self.assertEqual(tracker.connects, 2)
        self.run_download(None)

    def test_udp_malformed_action_mismatch_and_tracker_failure(self):
        for kwargs in ({'malformed': True}, {'action_mismatch': True}):
            tracker = self.stack.enter_context(UDPTracker(**kwargs))
            self.torrent.tiers = [[tracker.url]]
            with self.subTest(kwargs=kwargs), self.assertRaises(RuntimeError):
                Announcer(self.torrent, timeout=.1).announce('started')

    def test_legacy_piece_command_and_handshake_use_real_sockets(self):
        peer = self.peer()
        self.assertEqual(download_piece(self.torrent, [peer.peer], 0), self.data[:65536])
        tracker = self.stack.enter_context(HTTPTracker([peer.peer]))
        path = self.directory / 'test.torrent'
        path.write_bytes(metainfo(self.data, announce=tracker.url))
        for command in (['peers', str(path)], ['handshake', str(path), str(peer.peer)],
                        ['download_piece', '-o', str(self.directory / 'piece'), str(path), '0']):
            result = subprocess.run([sys.executable, '-m', 'app.main', *command], capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_no_client_socket_threads_or_lock_leak(self):
        before = {t.ident for t in threading.enumerate()}
        peer = self.peer()
        self.run_download([peer.peer])
        peer.close()
        leaked = [t.name for t in threading.enumerate() if t.ident not in before and t.name.startswith('newtorrent')]
        self.assertEqual(leaked, [])
        # Lock remains as a stable inode, but has no owner.
        self.output.unlink()
        with Storage(self.torrent, str(self.output)):
            pass


if __name__ == '__main__':
    unittest.main()
