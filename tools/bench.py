"""Local real-transport experiments; each row is an isolated child process."""
from __future__ import annotations

import argparse
import cProfile
import csv
import hashlib
import json
import os
import platform
import random
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import ExitStack
from dataclasses import asdict
from pathlib import Path

import psutil

from app.download import download_file
from app.engine import Engine, Options
from app.storage import Storage
from app.torrent import Torrent
from tools.swarm import TCPPeer, metainfo, payload

CONFIGS = {'pipeline': ('window1', 'window5'), 'peers': ('one', 'four'),
           'scheduling': ('sequential', 'rarest'), 'endgame': ('off', 'on'),
           'resume': ('scratch', 'resume')}


def experiment(case, config, size, seed, profile=None):
    data = payload(size, seed)
    piece_length = 262144 if size >= 64 * 1024 * 1024 else 65536
    torrent = Torrent.from_bytes(metainfo(data, piece_length))
    options = Options(window=5, max_active=8, seed=seed, endgame=0,
                      request_timeout=2, inactivity_timeout=3, no_progress_timeout=4, max_retries=0)
    delay = .001 if size >= 64 * 1024 * 1024 else .008
    record = {'experiment': case, 'config': config, 'size_bytes': size, 'piece_length': piece_length,
              'seed': seed, 'delay_seconds': delay, 'status': 'failed'}
    process = psutil.Process()
    peak = [process.memory_info().rss]
    done = threading.Event()
    def sample():
        while not done.wait(.01):
            peak[0] = max(peak[0], process.memory_info().rss)
    sampler = threading.Thread(target=sample, daemon=True)
    sampler.start()
    with ExitStack() as stack:
        directory = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        output = directory / 'result'
        if case == 'scheduling':
            # Scarce peer leaves after one piece. Common peer cannot supply the
            # final rare piece. Sequential order spends the scarce opportunity
            # on piece zero; rarest-first can obtain the unique piece in time.
            common = stack.enter_context(TCPPeer(torrent, data, pieces=set(range(torrent.num_pieces - 1)),
                                                delay=delay, unchoke_delay=.15))
            scarce = stack.enter_context(TCPPeer(torrent, data, pieces={0, torrent.num_pieces - 1},
                                                handshake_delay=.02, delay=delay,
                                                disconnect_after=(piece_length // 16384) + 1))
            peers = [common.peer, scarce.peer]
            options.strategy, options.window = config, piece_length // 16384
        elif case == 'endgame':
            last = torrent.num_pieces - 1
            last_begin = ((torrent.piece_size(last) - 1) // 16384) * 16384
            slow = stack.enter_context(TCPPeer(torrent, data, pieces={last}, delay=delay,
                                               slow_block=(last, last_begin, .5)))
            fast = stack.enter_context(TCPPeer(torrent, data, delay=delay))
            peers = [slow.peer, fast.peer]
            options.endgame = 16 if config == 'on' else 0
        else:
            count = 4 if case == 'peers' and config == 'four' else 1
            fixtures = [stack.enter_context(TCPPeer(torrent, data, delay=delay)) for _ in range(count)]
            peers = [peer.peer for peer in fixtures]
            if case == 'pipeline':
                options.window = 1 if config == 'window1' else 5
        if case == 'resume':
            options.window = 1
            stop = threading.Event()
            def interrupt(stats, _):
                if stats.verified_bytes >= size // 3:
                    stop.set()
            try:
                download_file(torrent, peers, str(output), options=options, stop=stop, progress=interrupt)
            except InterruptedError:
                pass
            else:
                raise RuntimeError('Controlled interruption did not occur')
            record['preparation'] = 'Actual transfer interrupted after at least one third verified; excluded from timing'
            if config == 'scratch':
                output = directory / 'fresh'
        start = time.perf_counter()
        cpu = time.process_time()
        stats = None
        profiler = cProfile.Profile() if profile else None
        try:
            # Keep Engine available after failure so failed rows retain counters.
            with Storage(torrent, str(output)) as store:
                stats_engine = Engine(torrent, store, peers, options=options)
                if profiler:
                    profiler.enable()
                try:
                    stats = stats_engine.run()
                finally:
                    stats = stats_engine.stats
                    if profiler:
                        profiler.disable()
            if hashlib.sha1(output.read_bytes()).digest() != hashlib.sha1(data).digest():
                raise RuntimeError('Output content mismatch')
            record['status'] = 'ok'
        except Exception as error:
            record['error'] = str(error)
        finally:
            elapsed, cpu_cost = time.perf_counter() - start, time.process_time() - cpu
            done.set()
            sampler.join(1)
            if profiler:
                profiler.dump_stats(profile)
        if stats:
            record.update(asdict(stats))
        record.update(wall_seconds=elapsed, cpu_seconds=cpu_cost, peak_rss_bytes=peak[0],
                      goodput_bytes_second=((size - (stats.resumed_bytes if stats else 0)) / elapsed
                                            if record['status'] == 'ok' else 0),
                      retransmitted_requested_bytes=max(0, (stats.requested_bytes - (size - stats.resumed_bytes))
                                                        if stats else 0),
                      options=asdict(options))
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', default='benchmarks/local')
    parser.add_argument('--trials', type=int, default=5)
    parser.add_argument('--sizes-mib', nargs='+', type=int, default=[1, 64])
    parser.add_argument('--cases', nargs='+', choices=CONFIGS, default=list(CONFIGS))
    parser.add_argument('--seed', type=int, default=20261012)
    parser.add_argument('--worker', action='store_true')
    parser.add_argument('--config')
    parser.add_argument('--size', type=int)
    parser.add_argument('--profile')
    args = parser.parse_args()
    if args.worker:
        print(json.dumps(experiment(args.cases[0], args.config, args.size, args.seed, args.profile)))
        return
    if args.trials < 1 or any(size < 1 for size in args.sizes_mib):
        parser.error('Trials and sizes must be positive')
    root = Path(args.output)
    root.mkdir(parents=True, exist_ok=True)
    jobs = [(case, config, size * 1024 * 1024, args.seed + trial, trial)
            for size in args.sizes_mib for case in args.cases
            for trial in range(args.trials) for config in CONFIGS[case]]
    random.Random(args.seed).shuffle(jobs)
    metadata = {'python': sys.version, 'platform': platform.platform(), 'cpu': platform.processor(),
                'logical_cpus': os.cpu_count(), 'command': ['python', '-m', 'tools.bench', *sys.argv[1:]],
                'seed': args.seed,
                'timestamp_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
                'transfer_source_sha256': {
                    source: hashlib.sha256(Path(source).read_text(encoding='utf-8-sig').encode()).hexdigest()
                    for source in ('app/engine.py', 'app/scheduler.py')
                },
                'memory_scope': 'Whole isolated process including synthetic payload and local peer fixtures',
                'cpu_scope': 'Whole worker process, storage revalidation/transfer/content comparison included',
                'transport': 'Loopback TCP; scheduled application response delay, not simulated network RTT/loss',
                'bottleneck': 'Per-peer request window and response delay plus disk fsync/checkpoint overhead; no bandwidth cap',
                'comparison': 'One engine with one experimental factor varied per comparison',
                'jobs': jobs}
    (root / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
    rows = []
    with open(root / 'raw.jsonl', 'w', encoding='utf-8') as handle:
        for case, config, size, seed, trial in jobs:
            command = [sys.executable, '-m', 'tools.bench', '--worker', '--cases', case,
                       '--config', config, '--size', str(size), '--seed', str(seed)]
            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=180)
                if result.returncode:
                    raise RuntimeError(result.stderr)
                row = json.loads(result.stdout)
            except Exception as error:
                row = dict(experiment=case, config=config, size_bytes=size, seed=seed,
                           status='failed', error=str(error))
            row['trial'] = trial
            rows.append(row)
            handle.write(json.dumps(row) + '\n')
            handle.flush()
            print(f'{case} {config} {size // 1048576} MiB trial {trial + 1}: {row["status"]} '
                  f'{row.get("wall_seconds", 0):.3f}s', flush=True)
    fields = sorted({key for row in rows for key in row if key not in ('options', 'peer_failures')})
    with open(root / 'raw.csv', 'w', newline='', encoding='utf-8') as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)
    from tools.summarize import summarize
    summarize(root)


if __name__ == '__main__':
    main()
