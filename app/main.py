"""NewTorrent command line: inspect, discover and download verified v1 content."""
from __future__ import annotations

import argparse
import json
import signal
import sys
import threading
import time
from dataclasses import asdict

from . import bencode, download
from .engine import Options
from .peer import PeerConnection
from .storage import Storage, atomic_json
from .torrent import Torrent
from .tracker import get_peers, new_peer_id


def _to_json(value):
    if isinstance(value, bytes):
        try:
            return value.decode('utf-8')
        except UnicodeDecodeError:
            return value.hex()
    raise TypeError("Value is not serializable")


def _parse_output_args(args, extra):
    # Compatibility helper used by the original argument regression tests.
    if len(args) != 3 + extra or args[0] != '-o' or not args[1]:
        raise SystemExit('Usage: download[_piece] -o output file.torrent [index]')
    return args[1], args[2], args[3:]


def parser():
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest='command', required=True)
    commands.add_parser('decode', help='Decode canonical bencode').add_argument('value')
    for name in ('info', 'peers', 'handshake', 'download_piece', 'download', 'recheck'):
        sub = commands.add_parser(name)
        sub.add_argument('torrent')
        if name == 'handshake':
            sub.add_argument('address', help='IPv4:port')
        if name in ('download_piece', 'download', 'recheck'):
            sub.add_argument('-o', '--output', required=True)
        if name == 'download_piece':
            sub.add_argument('index', type=int)
        if name in ('download', 'recheck'):
            sub.add_argument('--overwrite', action='store_true', help='Replace an existing single file after verification')
        if name == 'download':
            sub.add_argument('--no-resume', action='store_true', help='Refuse existing staging')
            sub.add_argument('--stats', help='Write JSON transfer statistics')
            sub.add_argument('--quiet', action='store_true')
            defaults = Options()
            for option in ('max_peers', 'window', 'max_pending', 'max_active', 'max_buffer_bytes',
                           'max_discovery', 'max_retries', 'endgame', 'seed'):
                sub.add_argument('--' + option.replace('_', '-'), type=int, default=getattr(defaults, option))
            for option in ('connect_timeout', 'handshake_timeout', 'request_timeout',
                           'inactivity_timeout', 'no_progress_timeout', 'backoff'):
                sub.add_argument('--' + option.replace('_', '-'), type=float, default=getattr(defaults, option))
            sub.add_argument('--tracker-timeout', type=float, default=5)
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    stop = threading.Event()
    previous = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    try:
        if args.command == 'decode':
            print(json.dumps(bencode.decode(args.value.encode()), default=_to_json))
            return
        torrent = Torrent.from_file(args.torrent)
        if args.command == 'info':
            print(f'Length: {torrent.length}\nInfo Hash: {torrent.info_hash.hex()}\nPiece Length: {torrent.piece_length}')
            print(f'Files: {len(torrent.layout)}\nTrackers: {sum(map(len, torrent.tiers))}')
            print('Piece Hashes:')
            for digest in torrent.piece_hashes:
                print(digest.hex())
        elif args.command == 'peers':
            for peer in get_peers(torrent):
                print(peer)
        elif args.command == 'handshake':
            ip, port = args.address.rsplit(':', 1)
            with PeerConnection(ip, int(port), torrent.info_hash, new_peer_id()) as conn:
                print(f'Peer ID: {conn.remote_peer_id.hex()}')
        elif args.command == 'download_piece':
            data = download.download_piece(torrent, get_peers(torrent), args.index)
            with open(args.output, 'xb') as handle:
                handle.write(data)
            print(f'Piece {args.index} verified.')
        elif args.command == 'recheck':
            with Storage(torrent, args.output, overwrite=args.overwrite, stop=stop) as storage:
                print(json.dumps({'verified_pieces': len(storage.verified), 'total_pieces': torrent.num_pieces,
                                  'revalidation_seconds': storage.revalidation_seconds}))
        else:
            options = Options(**{name: getattr(args, name) for name in Options.__dataclass_fields__ if hasattr(args, name)})
            start = time.monotonic()
            def progress(stats, connected):
                if not args.quiet:
                    speed = (stats.verified_bytes - stats.resumed_bytes) / max(.001, time.monotonic() - start)
                    print(f'\rVerified {stats.verified_bytes}/{torrent.length} bytes | {speed / 1024:.0f} KiB/s | '
                          f'{connected} peers | retries {stats.retries} | hash failures {stats.hash_failures} | '
                          f'reused {stats.resumed_bytes}', end='', file=sys.stderr, flush=True)
            stats = download.download_file(torrent, None, args.output, options=options,
                                           resume=not args.no_resume, overwrite=args.overwrite,
                                           stop=stop, progress=progress, tracker_timeout=args.tracker_timeout)
            if not args.quiet:
                print(file=sys.stderr)
            if args.stats:
                from pathlib import Path
                atomic_json(Path(args.stats).absolute(), asdict(stats))
            print(f'Download verified: {torrent.length} bytes, {stats.resumed_bytes} reused.')
    except (InterruptedError, KeyboardInterrupt):
        print('\nInterrupted; staged verified pieces are available for resume.', file=sys.stderr)
        raise SystemExit(130)
    except (OSError, ValueError, RuntimeError, IndexError) as error:
        print(f'newtorrent: {error}', file=sys.stderr)
        raise SystemExit(1)
    finally:
        signal.signal(signal.SIGINT, previous)


if __name__ == '__main__':
    main()
