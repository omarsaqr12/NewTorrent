# Implementation history

The initial single-file implementation is available at
[`e16e2a4`](https://github.com/omarsaqr12/NewTorrent/commit/e16e2a4d1380dc473b945d75cc01af1e50f79738).
It includes canonical bencode parsing, HTTP compact peer discovery, TCP handshakes,
pipelined block requests, SHA-1 verification and temporary-file publication. Its
18 regression tests use simulated sockets.

The current architecture replaces the blind piece queue with availability-aware
block scheduling and a nonblocking reactor. Persistent staging supports verified
resume and multi-file layouts. Tracker tiers, UDP announcements, operation deadlines
and real loopback fault tests extend the protocol and lifecycle coverage.

The benchmark harness compares settings of the current engine with one experimental
factor varied at a time. It does not compare the initial implementation against the
current release; the original live-network benchmark changed both peer count and
request-window size.

To inspect the initial implementation separately:

```sh
git worktree add ../NewTorrent-baseline e16e2a4
```
