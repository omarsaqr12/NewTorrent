"""Optional live-network serial vs concurrent download comparison.

This is a comparison of combined strategies, NOT an isolated pipelining
experiment. Both modes use freshly discovered peers; swarm conditions vary.

Usage: python benchmark.py [file.torrent] [runs]
"""

from __future__ import annotations

import statistics
import sys
import tempfile
import time
from pathlib import Path

from app import download
from app.peer import PeerConnection
from app.torrent import Torrent
from app.tracker import PEER_ID, get_peers


def naive_download(torrent: Torrent, peers, output: str) -> None:
    """Baseline: one peer, one outstanding block, pieces in order."""
    if not peers and torrent.num_pieces:
        raise RuntimeError("Tracker returned no peers")
    with open(output, "wb") as handle:
        if torrent.num_pieces:
            with PeerConnection(peers[0].ip, peers[0].port, torrent.info_hash, PEER_ID) as conn:
                conn.prepare_download()
                for index in range(torrent.num_pieces):
                    handle.write(conn.download_piece(
                        index, torrent.piece_size(index), torrent.piece_hashes[index],
                        pipeline_depth=1,
                    ))


def time_run(func, torrent: Torrent, output: str) -> float:
    peers = get_peers(torrent)  # Tracker discovery is excluded from the timing.
    start = time.perf_counter()
    func(torrent, peers, output)
    elapsed = time.perf_counter() - start
    if Path(output).stat().st_size != torrent.length:
        raise RuntimeError("Benchmark output has the wrong size")
    return elapsed


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else "sample.torrent"
    runs = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    if runs < 1:
        raise SystemExit("Runs must be a positive integer")
    torrent = Torrent.from_file(path)
    print(f"Torrent: {torrent.name} ({torrent.length} bytes, {torrent.num_pieces} pieces)")
    print(f"Runs per approach: {runs}\n")
    results = {}
    with tempfile.TemporaryDirectory(prefix="newtorrent-benchmark-") as directory:
        for label, func in (("serial (single peer)", naive_download),
                            ("concurrent + pipelined", download.download_file)):
            times = []
            for run in range(runs):
                output = str(Path(directory) / f"{label.split()[0]}-{run}.bin")
                try:
                    times.append(time_run(func, torrent, output))
                except Exception as error:  # Individual live runs can fail.
                    print(f"  {label}: run {run + 1} failed ({error})")
            if times:
                results[label] = times
                print(f"{label:28s} median {statistics.median(times):.3f}s "
                      f"best {min(times):.3f}s ({len(times)}/{runs} successful)")
    if len(results) == 2:
        baseline = statistics.median(results["serial (single peer)"])
        optimized = statistics.median(results["concurrent + pipelined"])
        print(f"\nMedian ratio: {baseline / optimized:.2f}x")
    else:
        print("\nInsufficient successful runs for a comparison")


if __name__ == "__main__":
    main()
