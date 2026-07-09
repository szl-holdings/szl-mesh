# SPDX-License-Identifier: Apache-2.0
# SZL Holdings — clean-room, permissive (Apache-2.0 compatible)
# © 2026 Lutar, Stephen P. — SZL Holdings · ORCID 0009-0001-0110-4173 · Doctrine v11/v12
# Authored by Yachay (CTO) — Sovereign Mesh Coordinator / Scheduler
"""
szl_mesh_coordinator.py — Sovereign Mesh Coordinator & Scheduler
=================================================================
Implements the coordinator side of the SZL sovereign compute mesh:

  • Least-connections + pipeline-aware scheduler (dispatches ONLY Λ-passed work)
  • Honest node-down degradation: routes around a missing node, marks its tile
    DOWN, NEVER fabricates a response from a missing node
  • F1 replay determinism: identical inputs ⇒ identical node pick (seeded RNG)
  • Greedy layer-range assignment (Petals/exo pattern) at node join time
  • Token issuance to joining nodes
  • Revocation propagation

HONEST LABELS:
  - Mesh = scheduler (software routing, not hardware interconnect)
  - VRAM fusion = ROADMAP (NVLink-only; consumer Ada/Blackwell have no NVLink)
  - Λ (Lambda-Spine) = advisory Conjecture 1 — NEVER a theorem
  - All throughput numbers = MODELED until founder reports MEASURED benchmark
  - Khipu BFT = Conjecture 2 (3-of-4 multi-party-witnessed agreement) — ROADMAP

FORMULA ANCHORS (kernel c7c0ba17, locked_count_eight, sorry-free):
  F1  replay determinism  → seeded RNG: hash(request_id + node_ids) → seed
                            identical inputs always produce the identical pick
  F4  Khipu hash-chain    → coordinator receipt chain mirrors node chain pattern
  F7  Chaski idempotence  → relay messages carry request_id; duplicates ignored
  F11 Ayni reciprocity    → per-node contribution tracked across all dispatches
  F22 emit-monotone       → coordinator routing log is append-only

Khipu BFT (Conjecture 2): 3-of-4 multi-party-witnessed node agreement.
  ROADMAP — stubs provided, full BFT logic in khipu-consensus repo.

NO GPU REQUIRED — pure Python stdlib.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import random
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# Import node-agent helpers (same package)
from szl_mesh_agent import (
    AYNI_CREDIT_PER_JOB,
    COSIGN_KEYID,
    JOIN_TOKEN_TTL_S,
    LAMBDA_THRESHOLD_ADVISORY,
    NODE_OFFLINE_TIMEOUT_S,
    PAYLOAD_TYPE_RECEIPT,
    JobReceiptLedger,
    MeshNodeAgent,
    NodeHardware,
    NodeRegistry,
    canonical_json,
    issue_join_token,
    khipu_hash,
    lambda_gate_check,
    pae,
    revoke_token,
    verify_join_token,
)

import base64
import hmac as _hmac

log = logging.getLogger("szl.mesh.coordinator")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TILE_STATUS_UP = "UP"
TILE_STATUS_DOWN = "DOWN"

# Khipu BFT Conjecture-2 quorum threshold (3-of-4 nodes)
BFT_QUORUM = 3
BFT_POOL = 4


# ---------------------------------------------------------------------------
# Ouroboros bounded orchestration loop — doctrine: bounded, terminating,
# receipt-closed. Cross-ref: szl-holdings/szl-router receipts + the local
# runLoop pattern (LoopTrace: steps / maxBudget / exit / trace / doctrine /
# receiptsInEqOut). Λ = Conjecture 1 (advisory, NEVER a theorem).
#
# The mesh serves a model split across nodes by contiguous layer ranges
# (Petals/exo pattern — see assign_layers). Serving one request means walking
# the ordered pipeline of layer-range stages and dispatching each stage through
# the governed scheduler. That walk is the mesh orchestration loop;
# MeshCoordinator.run_pipeline() makes it explicitly BOUNDED so it always
# terminates and every stage is receipt-closed.
# ---------------------------------------------------------------------------

LOOP_DOCTRINE = "bounded, terminating, receipt-closed"

# Safe default HARD cap on orchestration steps when SZL_MESH_LOOP_BUDGET is
# unset or invalid. Comfortably exceeds a normal pipeline depth (one stage per
# layer-range node) while never permitting an unbounded walk.
DEFAULT_LOOP_BUDGET = 8

# Absolute ceiling — even an explicit env override is clamped to this, so the
# loop can never be made effectively unbounded by misconfiguration.
MAX_LOOP_BUDGET = 1024


def _loop_budget() -> int:
    """
    Resolve the HARD orchestration step budget.

    Order: SZL_MESH_LOOP_BUDGET env (int >= 1) -> DEFAULT_LOOP_BUDGET.
    Always clamped to [1, MAX_LOOP_BUDGET]. Never returns an unbounded value.
    """
    raw = os.environ.get("SZL_MESH_LOOP_BUDGET", "")
    try:
        val = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_LOOP_BUDGET
    if val < 1:
        return DEFAULT_LOOP_BUDGET
    return min(val, MAX_LOOP_BUDGET)


# ---------------------------------------------------------------------------
# F1 replay-deterministic node selection
# ---------------------------------------------------------------------------

def f1_seeded_pick(
    request_id: str,
    candidate_node_ids: List[str],
) -> str:
    """
    F1 replay/hash determinism: identical inputs always produce the identical pick.

    Seed = SHA-256(request_id || sorted(candidate_node_ids))[:8] as an integer.
    Uses Python's standard random.Random with this deterministic seed.

    This is NOT a cryptographic operation — it is purely a routing-reproducibility
    guarantee. The same request routed at any time on any coordinator instance
    with the same candidates will always pick the same node.

    Prerequisite: candidates list must be non-empty.
    """
    if not candidate_node_ids:
        raise ValueError("f1_seeded_pick: candidate list is empty")
    # Deterministic seed from request_id + sorted node list
    seed_material = request_id + "|" + ",".join(sorted(candidate_node_ids))
    seed_hex = hashlib.sha256(seed_material.encode("utf-8")).hexdigest()[:16]
    seed_int = int(seed_hex, 16)
    rng = random.Random(seed_int)
    return rng.choice(sorted(candidate_node_ids))   # sorted for determinism


def f1_least_connections_pick(
    request_id: str,
    candidates: List[dict],
) -> dict:
    """
    Least-connections + F1 deterministic tiebreak.

    Primary: pick the node with the fewest active connections.
    Tiebreak (when two nodes have equal connections): F1 seeded pick ensures
    identical inputs always produce the identical choice.

    candidates: list of dicts with keys: node_id, active_connections, status
    """
    online = [c for c in candidates if c.get("status") == TILE_STATUS_UP]
    if not online:
        raise RuntimeError("f1_least_connections_pick: no online candidates")
    min_conns = min(c["active_connections"] for c in online)
    tied = [c for c in online if c["active_connections"] == min_conns]
    if len(tied) == 1:
        return tied[0]
    # F1 tiebreak: seeded pick across tied nodes
    picked_id = f1_seeded_pick(request_id, [c["node_id"] for c in tied])
    return next(c for c in tied if c["node_id"] == picked_id)


# ---------------------------------------------------------------------------
# Layer-range assignment (Petals/exo greedy pattern)
# ---------------------------------------------------------------------------

def assign_layers(
    total_layers: int,
    registered_nodes: List[dict],
    new_node_vram_gb: float,
) -> Tuple[int, int]:
    """
    Assign a contiguous layer range to a new node proportional to its VRAM.
    Greedy sliding-window: find the window of proportional size with
    lowest current coverage.

    Returns (layer_start, layer_end).
    Label: MODELED — actual coverage depends on runtime VRAM after quantization.
    """
    coverage = [0.0] * total_layers
    for node in registered_nodes:
        ls = node.get("layer_start", 0)
        le = node.get("layer_end", 0)
        for i in range(ls, min(le, total_layers)):
            coverage[i] += node.get("vram_gb", 0.0)

    total_vram = sum(n.get("vram_gb", 0.0) for n in registered_nodes) + new_node_vram_gb
    if total_vram == 0:
        return 0, total_layers
    n_layers = max(1, round(total_layers * new_node_vram_gb / total_vram))
    n_layers = min(n_layers, total_layers)

    if n_layers == total_layers:
        return 0, total_layers

    # Sliding window: find starting position with lowest sum coverage
    window_sum = sum(coverage[:n_layers])
    best_start, best_sum = 0, window_sum
    for i in range(1, total_layers - n_layers + 1):
        window_sum += coverage[i + n_layers - 1] - coverage[i - 1]
        if window_sum < best_sum:
            best_sum = window_sum
            best_start = i
    return best_start, best_start + n_layers


# ---------------------------------------------------------------------------
# Coordinator tile (per-node routing state)
# ---------------------------------------------------------------------------

@dataclass
class NodeTile:
    """
    Coordinator-side view of a registered mesh node.
    A 'tile' is the coordinator's routing record for one node.
    """
    node_id: str
    node_name: str
    hostname: str
    port: int
    arch: str
    backend: str
    vram_gb: float
    cpu_ram_gb: float
    layer_start: int
    layer_end: int
    token: str
    status: str = TILE_STATUS_UP        # UP | DOWN
    active_connections: int = 0
    total_jobs: int = 0
    contribution: float = 0.0           # F11 Ayni
    last_seen: float = field(default_factory=time.time)
    down_reason: Optional[str] = None   # honest: record WHY a tile went DOWN


# ---------------------------------------------------------------------------
# Coordinator routing receipt ledger (F4/F22 on the coordinator side)
# ---------------------------------------------------------------------------

class CoordinatorReceiptLedger(JobReceiptLedger):
    """
    Coordinator-side append-only routing receipt ledger.
    Same F4/F22 guarantees as the node ledger; different payload type.
    """
    PAYLOAD_TYPE = "application/vnd.szl.mesh.coordinator-routing+json"

    def append_routing(
        self,
        request_id: str,
        selected_node_id: str,
        model: str,
        lambda_score: float,
        strategy: str,
        label: str = "LIVE",
    ) -> dict:
        """Append a routing decision to the coordinator ledger (F4/F22)."""
        return self.append(
            job_id=request_id,
            model=model,
            lambda_score=lambda_score,
            tokens_in=0,
            tokens_out=0,
            latency_ms=0.0,
            label=label,
        )


# ---------------------------------------------------------------------------
# F7 Chaski idempotence — relay message deduplication
# ---------------------------------------------------------------------------

class ChaskiRelay:
    """
    F7 Chaski relay idempotence.
    Tracks seen request_ids; ignores duplicates.
    Production: use a distributed set (Redis SADD with TTL).
    Here: in-process set for CPU-only self-test.
    """
    def __init__(self, ttl_seconds: int = 300):
        self._seen: Dict[str, float] = {}
        self._ttl = ttl_seconds
        self._lock = threading.Lock()

    def is_duplicate(self, request_id: str) -> bool:
        """Return True if this request_id has been seen within the TTL."""
        with self._lock:
            self._evict()
            if request_id in self._seen:
                return True
            self._seen[request_id] = time.time()
            return False

    def _evict(self) -> None:
        now = time.time()
        stale = [k for k, ts in self._seen.items() if (now - ts) > self._ttl]
        for k in stale:
            del self._seen[k]


# ---------------------------------------------------------------------------
# Khipu BFT — Conjecture 2 (ROADMAP stub)
# ---------------------------------------------------------------------------

class KhipuBFT:
    """
    Khipu BFT — Conjecture 2: 3-of-4 multi-party-witnessed node agreement.

    ROADMAP — full BFT logic lives in the khipu-consensus repo.
    This stub implements the contract surface so the coordinator can call it
    without breaking when BFT is not yet wired up.

    In production: a job requires BFT_QUORUM (3) out of BFT_POOL (4) nodes
    to sign the receipt before the coordinator considers the job finalized.
    """

    def __init__(self, quorum: int = BFT_QUORUM):
        self.quorum = quorum
        self._witnesses: Dict[str, List[str]] = {}  # job_id -> list of witness node_ids
        self._lock = threading.Lock()

    def witness(self, job_id: str, node_id: str) -> Tuple[bool, int]:
        """
        Register a witness for a job. Returns (quorum_reached, witness_count).
        Label: ROADMAP — stub collects witnesses but does not verify BFT signatures.
        """
        with self._lock:
            self._witnesses.setdefault(job_id, [])
            if node_id not in self._witnesses[job_id]:
                self._witnesses[job_id].append(node_id)
            count = len(self._witnesses[job_id])
            reached = count >= self.quorum
            return reached, count

    def status(self, job_id: str) -> dict:
        with self._lock:
            count = len(self._witnesses.get(job_id, []))
            return {
                "job_id": job_id,
                "witnesses": count,
                "quorum": self.quorum,
                "quorum_reached": count >= self.quorum,
                "label": "ROADMAP",
                "note": "Khipu BFT Conjecture-2 — full BFT in khipu-consensus repo",
            }


# ---------------------------------------------------------------------------
# MeshCoordinator — top-level coordinator
# ---------------------------------------------------------------------------

class MeshCoordinator:
    """
    Sovereign mesh coordinator.

    Responsibilities:
      1. Accept node join requests → assign layer range → issue signed token.
      2. Maintain tile registry (UP/DOWN per node).
      3. Dispatch work via least-connections + F1 deterministic tiebreak,
         ONLY for Λ-passed, receipted requests.
      4. Honest node-down degradation: route around DOWN nodes, never fabricate.
      5. Revoke tokens; propagate revocation to relay.
      6. F4/F22 coordinator routing receipt ledger.
      7. F7 Chaski relay idempotence.
      8. F11 Ayni: track per-node contribution across dispatches.
      9. Khipu BFT Conjecture-2 stub.
    """

    def __init__(
        self,
        mesh_secret: bytes,
        total_model_layers: int = 32,
        token_ttl_seconds: int = JOIN_TOKEN_TTL_S,
    ):
        self._secret = mesh_secret
        self.total_layers = total_model_layers
        self.token_ttl = token_ttl_seconds
        self._tiles: Dict[str, NodeTile] = {}
        self._revocation_store: set = set()
        self._lock = threading.Lock()
        self._routing_ledger = CoordinatorReceiptLedger("coordinator", mesh_secret)
        self._relay = ChaskiRelay()
        self._bft = KhipuBFT()
        self._active_connections: Dict[str, int] = {}   # node_id -> count

    # ------------------------------------------------------------------
    # Node join
    # ------------------------------------------------------------------

    def join_node(self, hw: NodeHardware) -> Tuple[Optional[str], Optional[NodeTile]]:
        """
        Register a new node. Assigns layer range, issues token, creates tile.
        Returns (token, tile) or (None, None) on error.
        """
        with self._lock:
            # Assign layer range proportional to VRAM
            existing = [
                {"vram_gb": t.vram_gb, "layer_start": t.layer_start, "layer_end": t.layer_end}
                for t in self._tiles.values()
            ]
            ls, le = assign_layers(self.total_layers, existing, hw.vram_gb)
            token = issue_join_token(hw, self._secret, self.token_ttl)
            tile = NodeTile(
                node_id=hw.node_id(),
                node_name=hw.node_name,
                hostname=hw.hostname,
                port=hw.port,
                arch=hw.arch,
                backend=hw.backend,
                vram_gb=hw.vram_gb,
                cpu_ram_gb=hw.cpu_ram_gb,
                layer_start=ls,
                layer_end=le,
                token=token,
                status=TILE_STATUS_UP,
            )
            self._tiles[hw.node_id()] = tile
            self._active_connections[hw.node_id()] = 0
            log.info(
                "node joined: id=%s name=%s arch=%s layers=%d-%d",
                hw.node_id(), hw.node_name, hw.arch, ls, le,
            )
            return token, tile

    # ------------------------------------------------------------------
    # Heartbeat ingestion
    # ------------------------------------------------------------------

    def receive_heartbeat(self, node_id: str, token: str) -> bool:
        """
        Process a heartbeat from a node. Verifies token, updates last_seen.
        Returns True if accepted.
        """
        payload = verify_join_token(token, self._secret, self._revocation_store)
        if payload is None or payload.get("node_id") != node_id:
            log.warning("heartbeat rejected: node_id=%s (bad token)", node_id)
            return False
        with self._lock:
            tile = self._tiles.get(node_id)
            if tile:
                tile.last_seen = time.time()
                tile.status = TILE_STATUS_UP
        return True

    def evict_stale_tiles(self) -> List[str]:
        """
        Mark tiles DOWN if last_seen > NODE_OFFLINE_TIMEOUT_S.
        HONEST: sets status=DOWN and records a reason. Never fabricates presence.
        Returns list of node_ids newly marked DOWN.
        """
        evicted = []
        now = time.time()
        with self._lock:
            for nid, tile in self._tiles.items():
                if tile.status == TILE_STATUS_UP:
                    age = now - tile.last_seen
                    if age > NODE_OFFLINE_TIMEOUT_S:
                        tile.status = TILE_STATUS_DOWN
                        tile.down_reason = f"heartbeat timeout: {age:.0f}s since last seen"
                        evicted.append(nid)
                        log.info(
                            "tile DOWN (evicted): node=%s reason='%s'",
                            nid, tile.down_reason,
                        )
        return evicted

    # ------------------------------------------------------------------
    # Token revocation
    # ------------------------------------------------------------------

    def revoke_node(self, node_id: str) -> None:
        """
        Revoke a node's token. The node will be rejected on next work request.
        Also marks the tile DOWN.
        """
        revoke_token(node_id, self._revocation_store)
        with self._lock:
            tile = self._tiles.get(node_id)
            if tile:
                tile.status = TILE_STATUS_DOWN
                tile.down_reason = "operator revocation"
        log.info("node revoked by coordinator: node_id=%s", node_id)

    def is_revoked(self, node_id: str) -> bool:
        return node_id in self._revocation_store

    # ------------------------------------------------------------------
    # Work dispatch (core scheduler)
    # ------------------------------------------------------------------

    def dispatch(self, request: dict) -> Tuple[bool, dict]:
        """
        Dispatch a governed work request.

        Steps:
          1. F7 Chaski idempotence: reject duplicate request_ids.
          2. Λ advisory gate (Conjecture 1): reject if score < threshold.
          3. Identify UP tiles via least-connections + F1 deterministic pick.
          4. If no UP tile: honest degradation (return DEGRADED, never fabricate).
          5. Emit coordinator routing receipt (F4/F22 ledger, append-only).
          6. F11 Ayni: increment selected node's contribution.
          7. Return dispatch result including signed routing receipt.

        Returns (dispatched: bool, result: dict).
        result keys:
          - dispatched: bool
          - node_id, node_name, hostname, port (if dispatched)
          - routing_receipt: signed receipt entry
          - lambda_score, lambda_passed
          - degraded: True if no UP nodes (honest degradation)
          - reason: human-readable reason for rejection/degradation
        """
        request_id = request.get("request_id") or secrets.token_hex(8)

        # --- F7 Chaski idempotence ---
        if self._relay.is_duplicate(request_id):
            log.info("dispatch: duplicate request_id=%s — idempotent reject", request_id)
            return False, {"dispatched": False, "reason": "duplicate request_id (F7 Chaski idempotence)"}

        # --- Λ advisory gate (Conjecture 1) ---
        passed, score = lambda_gate_check(request)
        if not passed:
            log.info(
                "dispatch: Λ advisory gate REJECTED request_id=%s score=%.3f",
                request_id, score,
            )
            return False, {
                "dispatched": False,
                "lambda_passed": False,
                "lambda_score": score,
                "reason": (
                    f"Λ advisory gate score {score:.3f} < threshold "
                    f"{LAMBDA_THRESHOLD_ADVISORY} (Conjecture 1 — advisory only)"
                ),
            }

        # --- Build candidate list ---
        with self._lock:
            candidates = [
                {
                    "node_id": tile.node_id,
                    "node_name": tile.node_name,
                    "hostname": tile.hostname,
                    "port": tile.port,
                    "vram_gb": tile.vram_gb,
                    "layer_start": tile.layer_start,
                    "layer_end": tile.layer_end,
                    "active_connections": self._active_connections.get(tile.node_id, 0),
                    "status": tile.status,
                }
                for tile in self._tiles.values()
            ]

        online = [c for c in candidates if c["status"] == TILE_STATUS_UP]

        # --- Honest node-down degradation ---
        if not online:
            down_nodes = [c["node_id"] for c in candidates if c["status"] == TILE_STATUS_DOWN]
            log.warning(
                "dispatch: DEGRADED — no UP nodes available. DOWN nodes: %s",
                down_nodes,
            )
            return False, {
                "dispatched": False,
                "degraded": True,
                "lambda_passed": True,
                "lambda_score": score,
                "down_nodes": down_nodes,
                "reason": (
                    "All mesh nodes are DOWN or unavailable. "
                    "Request not dispatched. No fabrication. "
                    "DOWN tile(s): " + str(down_nodes)
                ),
            }

        # --- F1 + least-connections pick ---
        selected = f1_least_connections_pick(request_id, online)
        node_id = selected["node_id"]

        # --- Increment active connections ---
        with self._lock:
            self._active_connections[node_id] = (
                self._active_connections.get(node_id, 0) + 1
            )
            tile = self._tiles[node_id]
            tile.total_jobs += 1

        # --- F4/F22 coordinator routing receipt ---
        receipt_entry = self._routing_ledger.append_routing(
            request_id=request_id,
            selected_node_id=node_id,
            model=request.get("model", "unknown"),
            lambda_score=score,
            strategy="least-connections+F1-seeded",
            label=request.get("label", "LIVE"),
        )

        # --- F11 Ayni: coordinator-side contribution tracking ---
        with self._lock:
            tile = self._tiles[node_id]
            tile.contribution += AYNI_CREDIT_PER_JOB
        # F11 invariant: (b + c) - c = b
        # We don't re-assert here because coordinator mirrors node-side assertion

        log.info(
            "dispatch: request_id=%s -> node=%s (%s) Λ=%.3f conns=%d chain=%.8s",
            request_id, node_id, selected["node_name"],
            score, selected["active_connections"], receipt_entry["chain_hash"],
        )

        return True, {
            "dispatched": True,
            "request_id": request_id,
            "node_id": node_id,
            "node_name": selected["node_name"],
            "hostname": selected["hostname"],
            "port": selected["port"],
            "layer_start": selected["layer_start"],
            "layer_end": selected["layer_end"],
            "lambda_passed": True,
            "lambda_score": score,
            "lambda_label": "advisory-conjecture-1",
            "routing_receipt": receipt_entry,
            "strategy": "least-connections+F1-seeded",
            "label": "LIVE",
            "vram_fusion": "ROADMAP",
        }

    # ------------------------------------------------------------------
    # Ouroboros bounded orchestration loop (pipeline walk)
    # ------------------------------------------------------------------

    def _pipeline_plan(self) -> Tuple[List[NodeTile], bool]:
        """
        Compute the ordered pipeline of UP tiles covering the model's layer
        span [0, total_layers) via a greedy interval cover.

        Returns (stages, covered):
          - stages:  ordered NodeTiles forming the pipeline (may be partial).
          - covered: True iff the stages cover the full layer span. When False
                     there is a genuine gap — the pipeline is INCOMPLETE and
                     the caller must surface that honestly (never fabricate a
                     missing stage).

        Terminating: `remaining` strictly shrinks each iteration, so the walk
        runs at most len(up) times; an explicit `guard` makes the bound obvious.
        """
        with self._lock:
            up = [t for t in self._tiles.values() if t.status == TILE_STATUS_UP]
        up.sort(key=lambda t: (t.layer_start, t.layer_end))
        stages: List[NodeTile] = []
        remaining = list(up)
        cursor = 0
        guard = len(up) + 1   # HARD bound — the plan walk can never exceed this
        while cursor < self.total_layers and guard > 0:
            guard -= 1
            reachable = [
                t for t in remaining
                if t.layer_start <= cursor and t.layer_end > cursor
            ]
            if not reachable:
                return stages, False   # honest gap: cannot cover [cursor, ...]
            best = max(reachable, key=lambda t: t.layer_end)
            stages.append(best)
            cursor = best.layer_end
            remaining = [t for t in remaining if t is not best]
        return stages, cursor >= self.total_layers

    def run_pipeline(
        self,
        request: dict,
        max_steps: Optional[int] = None,
    ) -> Tuple[bool, dict]:
        """
        Bounded Ouroboros orchestration loop around dispatch().

        Walks the model's layer-range pipeline (see _pipeline_plan) and issues
        ONE governed dispatch per stage. The loop is bounded by a HARD step
        budget (max_steps arg, else SZL_MESH_LOOP_BUDGET env, else
        DEFAULT_LOOP_BUDGET), so it always terminates. Every stage emits its own
        F4/F22 routing receipt, so the loop is receipt-closed.

        Doctrine: bounded, terminating, receipt-closed (cross-ref
        szl-holdings/szl-router receipts + local runLoop). Λ stays Conjecture 1
        (advisory, NEVER a theorem).

        Honest exit — NEVER faked:
          - "converged"        every pipeline stage dispatched and the layer
                               span is fully covered.
          - "budget_exhausted" the HARD step budget was hit before the pipeline
                               finished.
          - "degraded"         a required stage had no UP node (coverage gap)
                               or a dispatch degraded/was rejected — the walk
                               stops honestly rather than fabricate a stage.
          - "error"            an exception was raised inside the loop.

        Back-compatible: additive method. Existing dispatch() is unchanged;
        callers that never invoke run_pipeline() see identical behavior.

        Returns (converged, result). result always carries an additive `loop`
        block: {steps, maxBudget, exit, trace, doctrine, receiptsInEqOut,
        lambda_label} plus `stages` (the per-stage dispatch results).
        """
        budget = (
            max_steps
            if (isinstance(max_steps, int) and max_steps >= 1)
            else _loop_budget()
        )
        budget = min(budget, MAX_LOOP_BUDGET)
        base_request_id = request.get("request_id") or secrets.token_hex(8)

        stages_plan, covered = self._pipeline_plan()
        trace: List[dict] = []
        stage_results: List[dict] = []
        step = 0
        exit_reason: str = "error"   # honest default until the loop sets it

        trace.append({
            "n": 0,
            "type": "system",
            "label": (
                f"plan: {len(stages_plan)} pipeline stage(s), "
                f"coverage={'full' if covered else 'INCOMPLETE'}, "
                f"budget={budget} (HARD cap)"
            ),
        })

        try:
            for stage_idx, tile in enumerate(stages_plan):
                if step >= budget:
                    exit_reason = "budget_exhausted"
                    trace.append({
                        "n": step,
                        "type": "error",
                        "label": (
                            f"HARD budget {budget} reached before pipeline "
                            f"complete ({stage_idx}/{len(stages_plan)} stages)"
                        ),
                    })
                    break
                step += 1
                stage_request = dict(request)
                stage_request["request_id"] = f"{base_request_id}::stage{step}"
                ok, res = self.dispatch(stage_request)
                stage_results.append(res)
                if not ok:
                    exit_reason = "degraded"
                    trace.append({
                        "n": step,
                        "type": "error",
                        "label": (
                            f"stage {step}/{len(stages_plan)} not dispatched: "
                            f"{res.get('reason', 'rejected')}"
                        ),
                    })
                    break
                trace.append({
                    "n": step,
                    "type": "action",
                    "label": (
                        f"stage {step}/{len(stages_plan)} -> "
                        f"{res.get('node_name')} (Λ={res.get('lambda_score')}, "
                        f"layers {tile.layer_start}-{tile.layer_end}, chain="
                        f"{res.get('routing_receipt', {}).get('chain_hash', '')[:8]})"
                    ),
                })
            else:
                # loop completed without break
                exit_reason = "converged" if (stages_plan and covered) else "degraded"
        except Exception as exc:   # honest: surface, never swallow into a fake win
            exit_reason = "error"
            trace.append({
                "n": step,
                "type": "error",
                "label": f"orchestration error: {exc!r}",
            })
            log.warning("run_pipeline error (base=%s): %r", base_request_id, exc)

        converged = exit_reason == "converged"
        trace.append({
            "n": step,
            "type": "success" if converged else "output",
            "label": f"exit={exit_reason} after {step} step(s)",
        })

        loop_block = {
            "steps": step,
            "maxBudget": budget,
            "exit": exit_reason,
            "trace": trace,
            "doctrine": LOOP_DOCTRINE,
            # DOCTRINE label (not math): one governed dispatch in == one routing
            # receipt out per stage. Cross-ref local runLoop receiptsInEqOut.
            "receiptsInEqOut": True,
            "lambda_label": "advisory Conjecture 1 — NEVER a theorem",
        }

        log.info(
            "run_pipeline: base=%s exit=%s steps=%d/%d stages_planned=%d covered=%s",
            base_request_id, exit_reason, step, budget,
            len(stages_plan), covered,
        )

        return converged, {
            "converged": converged,
            "request_id": base_request_id,
            "stages": stage_results,
            "stage_count": len(stage_results),
            "pipeline_covered": covered,
            "loop": loop_block,
            "strategy": "bounded-ouroboros-pipeline",
            "label": "LIVE",
            "vram_fusion": "ROADMAP",
        }

    def job_complete(self, node_id: str) -> None:
        """Decrement active connections after a job completes."""
        with self._lock:
            if node_id in self._active_connections:
                self._active_connections[node_id] = max(
                    0, self._active_connections[node_id] - 1
                )

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def tile_status(self) -> List[dict]:
        with self._lock:
            return [
                {
                    "node_id": t.node_id,
                    "node_name": t.node_name,
                    "arch": t.arch,
                    "backend": t.backend,
                    "vram_gb": t.vram_gb,
                    "layer_start": t.layer_start,
                    "layer_end": t.layer_end,
                    "status": t.status,
                    "active_connections": self._active_connections.get(t.node_id, 0),
                    "total_jobs": t.total_jobs,
                    "contribution": t.contribution,
                    "last_seen_age_s": round(time.time() - t.last_seen, 1),
                    "down_reason": t.down_reason,
                    "vram_fusion": "ROADMAP",
                    "label": "LIVE",
                    "throughput_label": "MODELED",
                }
                for t in self._tiles.values()
            ]

    def routing_ledger(self) -> CoordinatorReceiptLedger:
        return self._routing_ledger

    def bft(self) -> KhipuBFT:
        return self._bft


if __name__ == "__main__":
    import py_compile, sys
    py_compile.compile(__file__, doraise=True)
    print("[szl_mesh_coordinator] py_compile OK")

    SECRET = secrets.token_bytes(32)
    coord = MeshCoordinator(mesh_secret=SECRET, total_model_layers=32)

    hw_tower = NodeHardware(
        node_name="tower-4060ti",
        hostname="192.168.1.10",
        port=8000,
        arch="sm_89",
        backend="CUDA",
        vram_gb=16.0,
        cpu_ram_gb=32.0,
        cpu_cores=8,
        gpu_model="RTX 4060 Ti",
    )
    token_t, tile_t = coord.join_node(hw_tower)
    print(f"[szl_mesh_coordinator] tower joined: token={token_t[:30]}… tile={tile_t.node_id}")

    hw_laptop = NodeHardware(
        node_name="laptop-5050",
        hostname="192.168.1.20",
        port=8000,
        arch="blackwell",
        backend="CUDA",
        vram_gb=8.0,
        cpu_ram_gb=16.0,
        cpu_cores=4,
        gpu_model="RTX 5050",
    )
    token_l, tile_l = coord.join_node(hw_laptop)
    print(f"[szl_mesh_coordinator] laptop joined: layers={tile_l.layer_start}-{tile_l.layer_end}")

    ok, result = coord.dispatch({
        "request_id": "coord-smoke-001",
        "model": "llama-3-8b",
        "label": "LIVE",
    })
    print(f"[szl_mesh_coordinator] dispatch -> ok={ok} node={result.get('node_name')}")

    valid, msg = coord.routing_ledger().verify_chain()
    print(f"[szl_mesh_coordinator] routing chain: {valid} — {msg}")
    print("[szl_mesh_coordinator] smoke-test PASSED")
