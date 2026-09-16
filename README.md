# NewTorrent — a small BitTorrent v1 client in Python

An educational, command-line **single-file BitTorrent downloader** built without a torrent-client library. It parses bencoded metainfo, discovers peers through HTTP trackers, speaks the TCP peer-wire protocol, pipelines block requests, downloads pieces across multiple peers, and checks every assembled piece against its SHA-1 hash before publishing a completed file.

**Status:** learning project, not a general-purpose or security-hardened torrent client. It does not seed, resume interrupted transfers, or support magnet links, DHT, UDP trackers, IPv6, multi-file torrents, or BitTorrent v2. It supports compact IPv4 tracker responses; it does not yet support the expanded peer-list format. These are intentional scope boundaries, not claims of full protocol compliance.

## Quickstart

Python **3.10+** and `requests` are required. Run from the repository root:

```sh
python -m pip install -r requirements.txt
python -m app.main info sample.torrent         # offline: inspect bundled metainfo
python -m app.main decode 'd3:foo3:bare'      # offline: decode a bencoded value
python -m unittest discover -s tests -v      # offline: deterministic regression suite
```

A tracker and reachable peers are required for the network commands below. Use a `.torrent` file for content you are authorized to download; `sample.torrent` is a metainfo fixture and does not guarantee a reachable swarm.

```sh
python -m app.main peers path/to/file.torrent
python -m app.main handshake path/to/file.torrent 203.0.113.1:6881
python -m app.main download_piece -o piece-0.bin path/to/file.torrent 0
python -m app.main download -o downloaded.bin path/to/file.torrent
```

The handshake address above is a documentation-only example, **not** a live peer. `download` writes to a temporary file in the output directory and replaces the target only after all pieces have been verified. A successful download **will overwrite** an existing file at that target path; an unsuccessful download leaves it unchanged. Provide a writable output directory with enough space for the complete file.

## What was implemented

| Component | Responsibility |
| --- | --- |
| [`app/bencode.py`](app/bencode.py) | Binary-safe bencode encoding/decoding and malformed-input checks |
| [`app/torrent.py`](app/torrent.py) | Single-file v1 metainfo and piece-layout validation; SHA-1 info hash |
| [`app/tracker.py`](app/tracker.py) | HTTP announce and compact IPv4 peer-list parsing |
| [`app/peer.py`](app/peer.py) | Validated handshake, bounded peer-wire framing, pipelined block requests and piece hash verification |
| [`app/download.py`](app/download.py) | Multi-peer work queue, fallback retries, and publish-on-success file output |
| [`app/main.py`](app/main.py) | CLI commands and argument validation |
| [`benchmark.py`](benchmark.py) | Optional live-network comparison of a serial baseline and the concurrent downloader |
| [`tests/test_client.py`](tests/test_client.py) | Offline protocol, parsing, malformed-response, CLI, and output-preservation regression tests |

The downloader splits each piece into blocks of at most 16 KiB and keeps a limited number of requests in flight. It checks the returned piece index, block offset, and exact requested byte count before incorporating each response. A verified piece can be written to its destination offset; unfinished pieces are retried against available peers. The output is only moved into place after all pieces have been obtained.

## Verification and benchmarking

The offline suite uses simulated socket replies and peer connections: it tests good and malformed handshakes, out-of-order blocks, invalid response sizes and offsets, SHA-1 mismatches, malformed metainfo, and preservation of an existing output on failure. Run `python -m unittest discover -s tests -v`. [CI workflow](.github/workflows/tests.yml) runs the same suite on Python 3.12. **Offline tests do not establish success against arbitrary live trackers or peers.**

For an optional, network-dependent comparison:

```sh
python benchmark.py path/to/file.torrent 5
```

The benchmark contrasts one peer downloading serially with the concurrent/pipelined implementation. Peer availability, network conditions, and differing concurrency mean that results are specific to each run; this is **not** an isolated measurement of pipelining alone. An earlier version of the README reported an approximately 1.7× median speedup on a small sample, but the underlying raw measurements and environment were not retained here, and that result has **not** been independently reproduced for this revision. No general performance improvement is claimed.

## Protocol scope and references

This project originated in the [CodeCrafters Build Your Own BitTorrent challenge](https://app.codecrafters.io/courses/bittorrent/overview); the implementation and its limits are described here rather than claiming completion of all challenge stages. The relevant protocol references are [BEP 3 (BitTorrent v1)](https://www.bittorrent.org/beps/bep_0003.html) and [BEP 23 (compact tracker peers)](https://www.bittorrent.org/beps/bep_0023.html). In particular, a bitfield is optional, and `compact=1` does not require a tracker to return compact peers; this client explicitly rejects unsupported expanded lists.

The client has no resume state, piece-availability-aware scheduling, peer penalties, encrypted peer connections, or protection against every possible hostile-network behavior. Live tracker interoperability and throughput should be tested separately before relying on it for anything beyond learning and experimentation.

## License

[MIT](LICENSE)
