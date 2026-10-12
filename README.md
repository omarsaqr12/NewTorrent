# NewTorrent

![Tests](https://github.com/omarsaqr12/NewTorrent/actions/workflows/tests.yml/badge.svg)

A BitTorrent v1 download engine written in Python. NewTorrent discovers peers,
downloads blocks over TCP, verifies each piece against its SHA-1 hash, and resumes
interrupted single-file or multi-file downloads from disk.

The client implements the tracker and peer-wire protocols directly, without a
torrent library or third-party runtime dependencies. It downloads content over
IPv4; uploading, incoming connections, DHT, magnet links and v2 torrents are outside
its current scope.

## Quickstart

Requires Python 3.10 or later. From the repository root:

```sh
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
python -m tools.swarm
```

The demo starts a local HTTP tracker and two TCP peers with complementary pieces,
downloads a generated torrent, and checks the exact result. It runs entirely on
loopback and does not depend on a public swarm.

To download a `.torrent` file:

```sh
newtorrent info file.torrent
newtorrent download -o downloaded.bin file.torrent --stats transfer.json
newtorrent download -o downloaded.bin file.torrent    # resume the same download
newtorrent recheck -o downloaded.bin file.torrent     # rehash staged pieces offline
newtorrent download -o collection multifile.torrent
newtorrent download --help
```

The output's parent directory must exist. Failed or interrupted downloads keep
`OUTPUT.newtorrent` for resume and leave completed destinations intact. Resume
rehashes staged bytes before reusing them. Existing single files require
`--overwrite`; multi-file downloads require a fresh destination directory.
`--no-resume` refuses existing staging. The `recheck` command checks staging data.

## How it works

- A nonblocking TCP reactor owns peer sessions, deadlines and request state.
- Bitfield and HAVE messages feed rarest-first selection. Disconnects, choking and
  expired requests release work for another eligible peer.
- Each piece is assembled from 16 KiB blocks and hashed before it is committed.
  Endgame mode allows two owners per remaining block and cancels the losing request.
- Persistent staging uses kernel locking and atomic checkpoints. Multi-file pieces
  use a concatenated byte layout, including pieces that cross file boundaries.
- HTTP/HTTPS and UDP trackers support tier failover, unique peer IDs, periodic
  announcements and transfer counters.

Defaults are 8 peers, 5 requests per peer, 128 pending requests overall, 8 active
pieces and a 64 MiB active payload budget. Writes are synchronous, so disk throughput
applies backpressure. Limits, retry settings and separate connection, handshake,
request, inactivity and no-progress timeouts are configurable through the CLI.

See [the design notes](docs/design.md) for the architecture diagram, scheduling
invariants, memory model, write ordering and filesystem assumptions.

## Tests

```sh
python -m ruff check .
python -m unittest discover -s tests -v
```

The 51-test suite includes real loopback TCP peers and HTTP/UDP trackers, alongside
parser, scheduler and generated layout tests. Fault scenarios cover complementary
availability, peer churn, corruption, keepalive stalls, fragmented messages,
cancellation, process termination, verified resume, path validation and disk errors.
CI runs the suite and local demo on Linux and Windows.

An independent libtorrent seeding session is available as a separate check:

```sh
python -m pip install -e ".[interop]"
python -m tools.interop
```

See [testing and interoperability](docs/validation.md) for the recorded environment
and the commands used to validate the client.

## Benchmarks

The controlled local harness measures request pipelining, peer count, scheduling,
endgame and resume. It retains raw results, seeds, failures and environment metadata.

```sh
python -m pip install -e ".[bench]"
python benchmark.py --output benchmarks/reproduced --trials 5 --sizes-mib 1
python benchmark.py --output benchmarks/reproduced-large --trials 5 --sizes-mib 64 --cases peers
```

In the recorded 64 MiB workload, median completion time was **15.72 s with one peer**
and **5.40 s with four**, using the same five-request window and verification policy.
These are loopback results with scheduled application delays. CPU and memory
measurements include the synthetic peers and payloads.

[Benchmark methodology and results](docs/benchmarks.md) explain the comparisons,
variability and tradeoffs. [Small-workload data](benchmarks/local/summary.md) and
[64 MiB data](benchmarks/large/summary.md) include five trials per configuration.

## Other commands and limits

```sh
newtorrent decode d3:foo3:bare
newtorrent peers file.torrent
newtorrent handshake file.torrent 127.0.0.1:6881
newtorrent download_piece -o first-piece.dat file.torrent 0
```

These commands also work through `python -m app.main` and `your_bittorrent.sh`.
The example handshake address requires a running peer. Progress reports verified
bytes, speed, peers, retries and resumed bytes; `--quiet` suppresses it. Exit codes
are 0 for success, 1 for an operational error, 2 for invalid arguments and 130 for
an interrupted download.

Tracker dictionary responses currently require numeric IPv4 addresses. Extensions,
encrypted transport, tracker redirects and compressed tracker responses are
unsupported. The advertised port is tracker metadata; the client has no inbound
listener. Shutdown waits for an active filesystem operation, and blocking DNS or
HTTP cleanup can continue after the tracker worker's two-second join limit.

Protocol references: [BEP 3](https://www.bittorrent.org/beps/bep_0003.html),
[BEP 12](https://www.bittorrent.org/beps/bep_0012.html),
[BEP 15](https://www.bittorrent.org/beps/bep_0015.html),
[BEP 23](https://www.bittorrent.org/beps/bep_0023.html).
The project started with the [CodeCrafters BitTorrent challenge](https://app.codecrafters.io/courses/bittorrent/overview).

[MIT license](LICENSE).
