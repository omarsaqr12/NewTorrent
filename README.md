# PyTorrent — a BitTorrent client from scratch

A working command-line **BitTorrent client written in pure Python**, with no
torrent libraries. It implements the protocol end to end: a bencode codec, the
HTTP tracker protocol, peer-wire handshakes and messaging, SHA-1 piece
verification, **pipelined block requests**, and **concurrent multi-peer
downloads**.

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

```console
$ python -m app.main download -o ubuntu.iso ubuntu.torrent
Downloaded ubuntu.torrent to ubuntu.iso.
```

## Features

- **Bencode codec** — encode/decode of the serialization format used by
  `.torrent` files and tracker responses, with deterministic key ordering so
  the `info` hash is reproducible.
- **Tracker protocol** — announces to the HTTP tracker and parses the compact
  peer list.
- **Peer-wire protocol** — performs the 68-byte handshake and exchanges
  `bitfield` / `interested` / `unchoke` / `request` / `piece` messages.
- **SHA-1 piece verification** — every downloaded piece is checked against the
  digest in the metainfo before it is written; a mismatch is rejected.
- **Request pipelining** — keeps several 16 KiB block requests in flight per
  peer instead of a slow request-wait-request loop, keeping the TCP pipe full.
- **Concurrent multi-peer downloads** — distributes pieces across peers using a
  thread pool and a shared work queue, with a sequential fallback so the result
  is always complete and correct.

## Architecture

The client is split into focused modules under [`app/`](app/):

| Module | Responsibility |
| --- | --- |
| [`bencode.py`](app/bencode.py) | Bencode encode/decode codec |
| [`torrent.py`](app/torrent.py) | Parse `.torrent` files; derive info hash, piece hashes and sizes |
| [`tracker.py`](app/tracker.py) | Announce to the tracker and discover peers |
| [`peer.py`](app/peer.py) | Peer-wire connection: handshake, messaging, pipelined + verified piece download |
| [`download.py`](app/download.py) | Single-piece and concurrent whole-file orchestration |
| [`main.py`](app/main.py) | Command-line interface |

## Installation

Requires Python 3.8+. The only third-party dependency is
[`requests`](https://pypi.org/project/requests/).

```bash
git clone https://github.com/omarsaqr12/NewTorrent.git
cd NewTorrent
pip install -r requirements.txt
```

## Usage

```bash
# Decode a bencoded value
python -m app.main decode "d3:foo3:bar5:helloi52ee"

# Inspect a torrent's metadata (tracker, length, info hash, piece hashes)
python -m app.main info sample.torrent

# Discover peers from the tracker
python -m app.main peers sample.torrent

# Handshake with a specific peer
python -m app.main handshake sample.torrent 165.232.38.164:51433

# Download a single (verified) piece
python -m app.main download_piece -o piece-0.bin sample.torrent 0

# Download the whole file concurrently across peers
python -m app.main download -o output.bin sample.torrent
```

A `sample.torrent` is included for a quick end-to-end try.

## How it works

**Pipelining.** A piece is split into 16 KiB blocks. Rather than sending one
`request`, waiting for the `piece` reply, then sending the next, the client
keeps a window of several requests outstanding (see `PIPELINE_DEPTH` in
[`peer.py`](app/peer.py)). The peer can stream replies back-to-back, which is
the main reason this is far faster than a naive serial implementation.

**Concurrency.** [`download.py`](app/download.py) loads every piece index into a
thread-safe queue and starts one worker thread per peer. Each worker pulls
indices, downloads and verifies them, and writes each verified piece directly to
its byte offset in the pre-allocated output file under a lock. If a peer drops a
piece, it is requeued and a final sequential pass guarantees completeness.

**Integrity.** Each assembled piece is hashed with SHA-1 and compared to the
expected digest from the torrent's `info["pieces"]`; only matching pieces are
accepted.

## Benchmark

[`benchmark.py`](benchmark.py) compares the optimized download (concurrent,
pipelined, multi-peer) against a naive baseline (a single peer, one block
request in flight at a time, pieces fetched in sequence) over several live runs:

```bash
python benchmark.py sample.torrent 11
```

On the bundled `sample.torrent` (92 KB, 3 pieces) the optimized client is about
**1.7× faster (median), up to ~1.9× best case**. The gap is bounded here by the
tiny file: with only three pieces, TCP/handshake round-trips dominate and there
is little payload for pipelining and concurrency to accelerate. The speedup
widens on larger torrents with more pieces and peers, where transfer time —
rather than connection setup — is the bottleneck. (Results vary with network
conditions and the peers the tracker returns.)

## Scope and limitations

This is a learning-focused client. It supports single-file torrents over HTTP
trackers and is download-only (it does not seed). It does not implement UDP
trackers, the DHT, magnet links, or multi-file torrents.

## Acknowledgements

Built by implementing the protocol from scratch as part of the
[CodeCrafters "Build Your Own BitTorrent"](https://app.codecrafters.io/courses/bittorrent/overview)
challenge.

## License

[MIT](LICENSE)
