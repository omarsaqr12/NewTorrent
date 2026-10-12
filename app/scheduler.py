"""Single-owner scheduler: explicit block leases, rarest-first and bounded endgame."""
from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field

from .peer import BLOCK_SIZE, ProtocolError
from .torrent import Torrent

Block = tuple[int, int, int]  # piece, offset, exact byte count


@dataclass
class PieceState:
    data: bytearray
    received: set[int] = field(default_factory=set)
    contributors: set[int] = field(default_factory=set)
    source: int | None = None


class Scheduler:
    def __init__(self, torrent: Torrent, verified: set[int], *, max_active: int = 8,
                 max_pending: int = 128, endgame: int = 16, seed: int = 0,
                 strategy: str = "rarest"):
        self.torrent = torrent
        self.verified = verified
        self.max_active, self.max_pending, self.endgame = max_active, max_pending, endgame
        self.strategy = strategy
        self.availability = [0] * torrent.num_pieces
        self.peers: dict[int, set[int]] = {}
        self.active: dict[int, PieceState] = {}
        self.isolated: set[int] = set()
        self.owners: dict[Block, set[int]] = {}
        self.pending = 0
        self.peak_pending = self.peak_active = 0
        order = list(range(torrent.num_pieces))
        random.Random(seed).shuffle(order)
        self.rank = {piece: rank for rank, piece in enumerate(order)}
        self.remaining = sum((torrent.piece_size(i) + BLOCK_SIZE - 1) // BLOCK_SIZE
                             for i in range(torrent.num_pieces) if i not in verified)

    def update(self, peer: int, pieces: set[int]) -> None:
        if any(not 0 <= index < self.torrent.num_pieces for index in pieces):
            raise ProtocolError("Invalid availability index")
        old = self.peers.get(peer, set())
        for index in old - pieces:
            self.availability[index] -= 1
        for index in pieces - old:
            self.availability[index] += 1
        self.peers[peer] = set(pieces)

    def release(self, peer: int, block: Block) -> None:
        owners = self.owners.get(block)
        if owners and peer in owners:
            owners.remove(peer)
            self.pending -= 1
            if not owners:
                del self.owners[block]

    def disconnect(self, peer: int) -> None:
        for block in list(self.owners):
            self.release(peer, block)
        # A failed piece must be retried entirely from one source. Mixing a
        # replacement peer into its partial retry would lose that attribution.
        for index, state in list(self.active.items()):
            if state.source == peer:
                self.remaining += len(state.received)
                del self.active[index]
        self.update(peer, set())
        self.peers.pop(peer, None)

    def has_work(self, peer: int) -> bool:
        return bool(self.peers.get(peer, set()) - self.verified)

    def request(self, peer: int) -> Block | None:
        if self.pending >= self.max_pending:
            return None
        candidates = self.peers.get(peer, set()) - self.verified
        # Rarity precedes buffer preference; ties favor allocated pieces.
        def key(i):
            return (self.availability[i] if self.strategy == "rarest" else i,
                    i not in self.active,
                    self.rank[i])
        duplicate = None
        for index in sorted(candidates, key=key):
            state = self.active.get(index)
            if state is None:
                if len(self.active) >= self.max_active:
                    evictable = next((i for i in self.active if self.availability[i] == 0
                                      and not any(b[0] == i for b in self.owners)), None)
                    if evictable is None:
                        continue
                    abandoned = self.active.pop(evictable)
                    self.remaining += len(abandoned.received)
                state = PieceState(bytearray(self.torrent.piece_size(index)),
                                   source=peer if index in self.isolated else None)
                self.active[index] = state
                self.peak_active = max(self.peak_active, len(self.active))
            if state.source is not None and state.source != peer:
                continue
            for begin in range(0, len(state.data), BLOCK_SIZE):
                if begin in state.received:
                    continue
                block = (index, begin, min(BLOCK_SIZE, len(state.data) - begin))
                owners = self.owners.get(block, set())
                if not owners:
                    self._own(peer, block)
                    return block
                if (self.endgame and self.remaining <= self.endgame
                        and len(owners) < 2 and peer not in owners):
                    duplicate = block
        # Only duplicate once every remaining block already has an owner.
        if duplicate is not None and len(self.owners) == self.remaining:
            self._own(peer, duplicate)
            return duplicate
        return None

    def _own(self, peer: int, block: Block) -> None:
        self.owners.setdefault(block, set()).add(peer)
        self.pending += 1
        self.peak_pending = max(self.peak_pending, self.pending)

    def accept(self, peer: int, block: Block, data: bytes):
        """Return (losing leases, complete payload, corrupt contributors)."""
        if peer not in self.owners.get(block, ()) or len(data) != block[2]:
            raise ProtocolError("Unowned or incorrectly sized block")
        losers = [(owner, block) for owner in self.owners[block] if owner != peer]
        for owner in list(self.owners[block]):
            self.release(owner, block)
        index, begin, length = block
        state = self.active[index]
        state.data[begin:begin + length] = data
        state.received.add(begin)
        state.contributors.add(peer)
        self.remaining -= 1
        if len(state.received) != (len(state.data) + BLOCK_SIZE - 1) // BLOCK_SIZE:
            return losers, None, set()
        del self.active[index]
        if hashlib.sha1(state.data).digest() != self.torrent.piece_hashes[index]:
            self.remaining += len(state.received)
            self.isolated.add(index)
            return losers, None, state.contributors
        self.isolated.discard(index)
        return losers, state.data, set()
