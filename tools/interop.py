"""Independent libtorrent seed on loopback; install .[interop] to run."""
import argparse
import json
import platform
import tempfile
import time
from dataclasses import asdict
from pathlib import Path

from app.download import download_file
from app.engine import Options
from app.torrent import Torrent
from app.tracker import Peer
from tools.swarm import metainfo, payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', default='docs/interop.json')
    args = parser.parse_args()
    record = {'python': platform.python_version(), 'platform': platform.platform(),
              'command': 'python -m tools.interop', 'size_bytes': 1048593,
              'configuration': 'IPv4 loopback TCP, DHT/LSD/UPnP/NAT-PMP off, no tracker discovery'}
    try:
        import libtorrent as lt
    except ImportError as error:
        record.update(status='blocked', reason=str(error))
    else:
        record['client'] = 'libtorrent ' + lt.__version__
        data = payload(record['size_bytes'])
        raw = metainfo(data)
        torrent = Torrent.from_bytes(raw)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'seed').mkdir()
            (root / 'seed' / torrent.name).write_bytes(data)
            session = lt.session({'listen_interfaces': '127.0.0.1:0', 'enable_dht': False,
                                  'enable_lsd': False, 'enable_upnp': False, 'enable_natpmp': False,
                                  'enable_incoming_utp': False, 'enable_outgoing_utp': False})
            params = lt.add_torrent_params()
            params.ti = lt.torrent_info(lt.bdecode(raw))
            params.save_path = str(root / 'seed')
            params.flags &= ~lt.torrent_flags.auto_managed
            params.flags &= ~lt.torrent_flags.paused
            handle = session.add_torrent(params)
            handle.replace_trackers([])
            deadline = time.monotonic() + 15
            try:
                while (not handle.status().is_seeding or not session.listen_port()) and time.monotonic() < deadline:
                    time.sleep(.05)
                if not handle.status().is_seeding:
                    raise RuntimeError('Independent client did not reach seeding state')
                stats = download_file(torrent, [Peer('127.0.0.1', session.listen_port())], str(root / 'result'),
                                      options=Options(no_progress_timeout=15))
                if (root / 'result').read_bytes() != data:
                    raise RuntimeError('Independent-client output differs')
                record.update(status='verified', stats=asdict(stats))
            except Exception as error:
                record.update(status='failed', reason=str(error), alerts=[str(a) for a in session.pop_alerts()][-20:])
            finally:
                session.remove_torrent(handle)
                del handle
                del session
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))
    if record['status'] == 'failed':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
