# Local benchmark results

## Method

Each trial runs in an isolated process with generated payloads, real loopback TCP
peers and the same SHA-1 verification and fsync/checkpoint policy. Comparison order
is shuffled with seed 20261012; payload/tie-break seeds are 20261012 through 20261016.
Each configuration has five trials. Failed runs remain in the raw data and summaries.

The 1 MiB workload uses 64 KiB pieces and an 8 ms scheduled response delay. The
64 MiB workload uses 256 KiB pieces and a 1 ms delay. The delay is introduced by the
peer application; it is not network RTT, packet loss or kernel traffic shaping.
There is no bandwidth cap. Request windows, peer count and synchronous disk writes
determine the transport and storage bottlenecks.

Recorded environment: CPython 3.11.1, Windows build 26200, eight logical CPUs,
Intel family 6/model 140. Metadata in each dataset includes workload order, seeds,
platform details and hashes of the measured reactor and scheduler source.
The retained runs used [revision 273754b](https://github.com/omarsaqr12/NewTorrent/commit/273754b78979cb4440f1e98a336ae2334c924792),
before single-source retries for corrupt pieces were added.

## Results

| Workload | Configuration | Median wall time, s | Successes |
|---|---|---:|---:|
| 1 MiB, one peer | Request window 1 / 5 | 1.151 / 0.381 | 5/5 each |
| 1 MiB, window 5 | One / four peers | 0.369 / 0.204 | 5/5 each |
| 64 MiB, window 5 | One / four peers | 15.722 / 5.400 | 5/5 each |
| Scarce-peer departure | Sequential / rarest-first | 4.565 / 0.539 | 0/5 / 5/5 |
| Slow final block | Endgame off / on | 0.548 / 0.361 | 5/5 each |
| Interrupted transfer | Fresh restart / verified resume | 1.233 / 0.754 | 5/5 each |

The window-5 pipelining runs range from 0.309 to 2.617 s. That slower outlier is
retained. The 64 MiB one-peer runs range from 15.548 to 18.707 s; four-peer runs
range from 5.143 to 7.224 s. These measurements compare settings of one engine,
not different releases or public-network throughput.

The scheduling fixture holds the common peer choked briefly while a scarce peer
can supply one complete piece before leaving. Only the scarce peer has the final
piece. Sequential scheduling spends that opportunity on a common piece and fails
after its progress deadline. Rarest-first completes all five trials. The failed
sequential runs demonstrate a scheduling failure, rather than a timing speedup.

Endgame requests a median 16,384 additional payload bytes while reducing completion
time in the slow-final-block fixture. Median received duplicate payload is zero:
an extra request does not necessarily result in a delivered duplicate.

Resume preparation is an actual interrupted transfer after at least one-third of
the bytes are verified, excluded from both configurations' timing. Median final
requested payload is 1,048,576 bytes for a fresh restart and 655,360 for resume;
393,216 verified bytes are reused. Median revalidation time is 0.031 s, included
in wall time and also reported separately.

For the 64 MiB workload, one/four peers use median process CPU time of 3.250/3.328 s
and peak RSS of 161,636,352/161,873,920 bytes. These process measurements include
synthetic payloads, fixture peers and full-output comparison. They are not
standalone-client memory measurements. Raw records also include observed pending
requests, active buffers, retries, requested bytes and received duplicate bytes.

## Reproduce

```sh
python -m pip install -e ".[bench]"
python benchmark.py --output benchmarks/reproduced --trials 5 --sizes-mib 1
python benchmark.py --output benchmarks/reproduced-large --trials 5 --sizes-mib 64 --cases peers
python -m tools.summarize benchmarks/local
python -m tools.summarize benchmarks/large
```

[Small-workload results](../benchmarks/local/summary.md) and
[64 MiB results](../benchmarks/large/summary.md) have raw CSV/JSONL, environment
metadata, JSON summaries and generated charts. The retained datasets contain
60 trials: 55 completed downloads and five sequential-policy failures.

To investigate a bottleneck locally:

```sh
python -m tools.bench --worker --cases peers --config four --size 67108864 --seed 20261012 --profile transfer.prof
python -c "import pstats; pstats.Stats('transfer.prof').sort_stats('cumulative').print_stats(20)"
```

Profiling identified repeated payload-file opens as a storage cost. A 32-handle
LRU now reuses handles while preserving fsync-before-checkpoint ordering.
Checkpoint/fsync frequency and scheduler sorting remain potential optimization
targets; batching writes would require revisiting the recovery guarantees.
