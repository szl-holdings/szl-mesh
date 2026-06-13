"""
szl_mesh.crdt — convergent CRDT document with two-track state.

Implements a deterministic, op-log-based Last-Writer-Wins (LWW) element map.
This is a real CRDT: merges are commutative, associative, and idempotent, so
replicas that observe the same SET of operations converge to byte-identical
state regardless of the order in which the operations arrive (spec/02).

Conflict resolution is a TOTAL ORDER over operations:
    (lamport_clock, node_id, op_id)
ascending — higher tuple wins for a given key. Because the tuple is total and
content-derived, every replica computes the same winner for every key.

Two-track state (spec/02-two-track-state.md):
  - Each op carries a `track` of AUTHORIZED or OBSERVED.
  - OBSERVED ops are NEVER dropped (forensic visibility), but the AUTHORIZED
    materialised view only considers AUTHORIZED ops. The OBSERVED view
    considers all ops. Track classification is performed by the Node runtime
    (node.py) using the DSSE Receipt Gate (receipts.py); the CRDT only stores
    the classification and materialises the two tracks deterministically.

Doctrine v11 LOCKED 749/14/163 · Kernel commit c7c0ba17 · SLSA L1.
The two-track soft-safety AP model is the real shipped one; this CRDT makes
no BFT claim (Khipu BFT unconditional = Conjecture 2).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Track labels (mirror proto TrackStatus).
AUTHORIZED = "AUTHORIZED"
OBSERVED = "OBSERVED"
REVOKED = "REVOKED"

_TOMBSTONE = "\u0000__SZL_TOMBSTONE__"  # internal sentinel for deletions


def _canonical(obj: Any) -> bytes:
    """Deterministic JSON encoding used for all content hashing."""
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def compute_op_id(
    doc_id: str,
    key: str,
    value: Any,
    lamport: int,
    node_id: str,
    deletion: bool,
) -> str:
    """
    Content-addressed operation id == the spec `change_hash`:
    SHA-256 over the canonical encoding of the op's identity-bearing fields.
    Deterministic across nodes: identical logical ops hash identically.
    """
    body = _canonical(
        {
            "doc": doc_id,
            "key": key,
            "value": value,
            "lamport": lamport,
            "node": node_id,
            "del": deletion,
        }
    )
    return hashlib.sha256(body).hexdigest()


@dataclass(frozen=True)
class Op:
    """A single CRDT operation (one map mutation)."""

    doc_id: str
    key: str
    value: Any
    lamport: int
    node_id: str
    deletion: bool = False
    track: str = OBSERVED  # set by the Node runtime after receipt validation

    @property
    def op_id(self) -> str:
        return compute_op_id(
            self.doc_id, self.key, self.value, self.lamport, self.node_id, self.deletion
        )

    @property
    def change_hash(self) -> str:
        """Alias matching spec/01 StateTransitionStatement.change_hash."""
        return self.op_id

    @property
    def order_key(self) -> Tuple[int, str, str]:
        """Total order used for LWW conflict resolution."""
        return (self.lamport, self.node_id, self.op_id)

    def raw_bytes(self) -> bytes:
        """The raw change-chunk bytes that change_hash is computed over."""
        return _canonical(
            {
                "doc": self.doc_id,
                "key": self.key,
                "value": self.value,
                "lamport": self.lamport,
                "node": self.node_id,
                "del": self.deletion,
            }
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "key": self.key,
            "value": self.value,
            "lamport": self.lamport,
            "node_id": self.node_id,
            "deletion": self.deletion,
            "track": self.track,
            "op_id": self.op_id,
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Op":
        return Op(
            doc_id=d["doc_id"],
            key=d["key"],
            value=d["value"],
            lamport=d["lamport"],
            node_id=d["node_id"],
            deletion=d.get("deletion", False),
            track=d.get("track", OBSERVED),
        )


class CRDTDocument:
    """
    An op-log LWW-map CRDT with two-track materialisation.

    The op-log is a set keyed by op_id (content hash). Adding the same op twice
    is a no-op (idempotent). Merging two documents is the set union of their
    op-logs (commutative + associative). State is materialised by folding the
    ops under the total order — so convergence is guaranteed by construction.
    """

    def __init__(self, doc_id: str) -> None:
        self.doc_id = doc_id
        self._ops: Dict[str, Op] = {}  # op_id -> Op

    # ── op ingestion ────────────────────────────────────────────────
    def add_op(self, op: Op) -> bool:
        """Insert an op into the log. Returns True if newly added (idempotent)."""
        if op.doc_id != self.doc_id:
            raise ValueError(
                f"op doc_id {op.doc_id!r} != document {self.doc_id!r}"
            )
        if op.op_id in self._ops:
            return False
        self._ops[op.op_id] = op
        return True

    def set_op_track(self, op_id: str, track: str) -> None:
        """Reclassify an op's track (e.g. AUTHORIZED -> REVOKED). Deterministic."""
        existing = self._ops.get(op_id)
        if existing is None:
            return
        self._ops[op_id] = Op(
            doc_id=existing.doc_id,
            key=existing.key,
            value=existing.value,
            lamport=existing.lamport,
            node_id=existing.node_id,
            deletion=existing.deletion,
            track=track,
        )

    def merge(self, other: "CRDTDocument") -> int:
        """
        Merge another document's op-log into this one (set union).
        Returns the number of newly added ops. Commutative, associative,
        idempotent — order of merges does not affect the final state.
        """
        if other.doc_id != self.doc_id:
            raise ValueError("cannot merge documents with different doc_id")
        added = 0
        for op in other._ops.values():
            if self.add_op(op):
                added += 1
        return added

    def merge_ops(self, ops: Iterable[Op]) -> int:
        added = 0
        for op in ops:
            if self.add_op(op):
                added += 1
        return added

    # ── materialisation ─────────────────────────────────────────────
    def _materialise(self, tracks: Tuple[str, ...]) -> Dict[str, Any]:
        """
        Fold the op-log into a key->value map, considering only ops whose
        track is in `tracks`. LWW by total order_key; tombstones delete.
        """
        winners: Dict[str, Op] = {}
        for op in self._ops.values():
            if op.track not in tracks:
                continue
            cur = winners.get(op.key)
            if cur is None or op.order_key > cur.order_key:
                winners[op.key] = op
        out: Dict[str, Any] = {}
        for key in sorted(winners):
            op = winners[key]
            if op.deletion:
                continue
            out[key] = op.value
        return out

    def authorized_view(self) -> Dict[str, Any]:
        """Materialised state considering AUTHORIZED-track ops only."""
        return self._materialise((AUTHORIZED,))

    def observed_view(self) -> Dict[str, Any]:
        """Materialised state considering all non-revoked ops (full awareness)."""
        return self._materialise((AUTHORIZED, OBSERVED))

    def view(self, track: str = OBSERVED) -> Dict[str, Any]:
        if track == AUTHORIZED:
            return self.authorized_view()
        return self.observed_view()

    # ── heads / identity ────────────────────────────────────────────
    def heads(self) -> List[str]:
        """
        Deterministic 'heads' for the current state: sorted op_ids of the
        per-key LWW winners across all non-revoked tracks. Stable across nodes
        that hold the same op set, used for from/to_state_head in receipts.
        """
        winners: Dict[str, Op] = {}
        for op in self._ops.values():
            if op.track == REVOKED:
                continue
            cur = winners.get(op.key)
            if cur is None or op.order_key > cur.order_key:
                winners[op.key] = op
        return sorted(op.op_id for op in winners.values())

    def state_digest(self, track: str = OBSERVED) -> str:
        """SHA-256 of the canonical materialised view — convergence fingerprint."""
        return hashlib.sha256(_canonical(self.view(track))).hexdigest()

    def all_ops(self) -> List[Op]:
        """All ops in deterministic order (for sync / export)."""
        return [self._ops[k] for k in sorted(self._ops)]

    def __len__(self) -> int:
        return len(self._ops)
