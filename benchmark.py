"""Measure the speedup from pipelining + concurrency against a naive baseline.

The *baseline* mirrors a naive implementation: a single peer, one block request
in flight at a time, pieces downloaded one after another. The *optimized* path
is the client's real concurrent, pipelined multi-peer download.

Both download the same torrent from the same live tracker, so the comparison
reflects the actual protocol behaviour rather than a synthetic loop. Network
conditions vary, so each approach is run several times and the median and best
wall-clock times are reported.

Usage::

    python benchmark.py [file.torrent] [runs]
"""

from __future__ import annotations

import statistics
import sys
import tempfile
import time

from app import download
from app.peer import PeerConnection
from app.torrent import Torrent
from app.tracker import PEER_ID, get_peers


def naive_download(torrent: Torrent, peers, output: str) -> None:
    """Baseline: one peer, serial blocks (depth 1), pieces in sequence."""
    with open(output, "wb") as handle:
        with PeerConnection(peers[0].ip, peers[0].port, torrent.info_hash, PEER_ID) as conn:
            conn.prepare_download()
            for index in range(torrent.num_pieces):
                data = conn.download_piece(
                    index,
                    torrent.piece_size(index),
                    torrent.piece_hashes[index],
                    pipeline_depth=1,
                )
                handle.write(data)


def time_run(func, torrent: Torrent, output: str) -> float:
    peers = get_peers(torrent)  # Fresh peer list per run.
    start = time.perf_counter()
    func(torrent, peers, output)
    return time.perf_counter() - start


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else "sample.torrent"
    runs = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    torrent = Torrent.from_file(path)

    print(f"Torrent: {torrent.name}  ({torrent.length} bytes, {torrent.num_pieces} pieces)")
    print(f"Runs per approach: {runs}\n")

    out = tempfile.NamedTemporaryFile(delete=False).name
    results = {}
    for label, func in (("naive (serial)", naive_download),
                        ("optimized (pipelined + concurrent)", download.download_file)):
        times = []
        for _ in range(runs):
            try:
                times.append(time_run(func, torrent, out))
            except Exception as error:  # noqa: BLE001 - report and keep going
                print(f"  {label}: run failed ({error})")
        if times:
            results[label] = times
            print(f"{label:38s}  median {statistics.median(times):.3f}s  best {min(times):.3f}s")

    if len(results) == 2:
        naive = statistics.median(results["naive (serial)"])
        opt = statistics.median(results["optimized (pipelined + concurrent)"])
        print(f"\nSpeedup (median): {naive / opt:.2f}x")


if __name__ == "__main__":
    main()
