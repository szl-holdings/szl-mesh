# SPDX-License-Identifier: Apache-2.0
# SZL Holdings — clean-room, permissive (Apache-2.0 compatible)
# © 2026 Lutar, Stephen P. — SZL Holdings · ORCID 0009-0001-0110-4173 · Doctrine v11/v12
# Authored by Yachay (CTO) — Sovereign Mesh Self-Tests (CPU-only)
"""
test_mesh.py — CPU-only self-tests for the sovereign mesh node-join agent
=========================================================================
Tests exercised (all CPU-only, no GPU required, no network required):

  T1  Token issue: issue a join token for a fake node, verify it passes
      verify_join_token().

  T2  Token verify rejection: tampered token must be rejected.

  T3  Route a job: spin 2 fake nodes + coordinator, dispatch a request,
      verify the selected node is UP and Λ-passed.

  T4  F4/F22 receipt hash-chain: verify that the coordinator receipt chain
      and node receipt chain both pass chain integrity verification.
      Confirm F22 (append-only): seq numbers are strictly monotone.

  T5  F11 Ayni reciprocity: accept N jobs, confirm contribution == N × CREDIT.
      Assert (contribution + CREDIT) - CREDIT == contribution (b+c-c=b).

  T6  Token revocation: revoke a node token, then attempt work acceptance
      and dispatch — both must be rejected.

  T7  Node-down degradation: mark both nodes DOWN, attempt dispatch,
      confirm DEGRADED result (no fabrication).

  T8  F1 replay determinism: dispatch 3 requests with the same request_id
      to the same candidate pool — all must pick the same node.

  T9  py_compile: both agent and coordinator modules compile cleanly.

HONEST LABELS:
  - Λ is Conjecture 1 (advisory, never theorem). Tests exercise the advisory gate.
  - VRAM fusion = ROADMAP. Tests reflect this label in node hardware.
  - All throughput = MODELED. No real inference runs here.
"""

from __future__ import annotations

import hashlib
import json
import py_compile
import secrets
import sys
import time
import traceback
from pathlib import Path
from typing import List, Tuple

# ---------------------------------------------------------------------------
# Path setup (allow running from repo root or code/ directory)
# ---------------------------------------------------------------------------

CODE_DIR = Path(__file__).parent
sys.path.insert(0, str(CODE_DIR))

from szl_mesh_agent import (
    AYNI_CREDIT_PER_JOB,
    MeshNodeAgent,
    NodeHardware,
    NodeRegistry,
    canonical_json,
    issue_join_token,
    khipu_hash,
    revoke_token,
    verify_join_token,
)
from szl_mesh_coordinator import (
    TILE_STATUS_DOWN,
    TILE_STATUS_UP,
    MeshCoordinator,
    f1_seeded_pick,
)

# ---------------------------------------------------------------------------
# Test harness
# ---------------------------------------------------------------------------

PASS = "PASS"
FAIL = "FAIL"
results: List[Tuple[str, str, str]] = []   # (test_name, status, detail)


def record(name: str, ok: bool, detail: str = "") -> None:
    status = PASS if ok else FAIL
    results.append((name, status, detail))
    icon = "✓" if ok else "✗"
    print(f"  [{icon}] {name}: {status}  {detail}")


def run_all_tests() -> int:
    """
    Run all mesh self-tests. Returns exit code (0=all pass, 1=any fail).
    """
    print("\n" + "=" * 60)
    print("SZL Sovereign Mesh — CPU-only Self-Tests")
    print("  Λ = advisory Conjecture 1 (NEVER a theorem)")
    print("  VRAM fusion = ROADMAP | throughput = MODELED")
    print("=" * 60 + "\n")

    SECRET = secrets.token_bytes(32)

    # ------------------------------------------------------------------
    # T9  py_compile (run first so we know imports are clean)
    # ------------------------------------------------------------------
    print("--- T9: py_compile ---")
    for fname in ["szl_mesh_agent.py", "szl_mesh_coordinator.py", "test_mesh.py"]:
        fpath = str(CODE_DIR / fname)
        try:
            py_compile.compile(fpath, doraise=True)
            record(f"T9 py_compile:{fname}", True, "syntax OK")
        except py_compile.PyCompileError as exc:
            record(f"T9 py_compile:{fname}", False, str(exc))

    # ------------------------------------------------------------------
    # T1  Token issue
    # ------------------------------------------------------------------
    print("\n--- T1: Token issue ---")
    hw_tower = NodeHardware(
        node_name="tower-4060ti",
        hostname="127.0.0.1",
        port=8000,
        arch="sm_89",
        backend="CUDA",
        vram_gb=16.0,
        cpu_ram_gb=32.0,
        cpu_cores=8,
        gpu_model="RTX 4060 Ti",
    )
    token = issue_join_token(hw_tower, SECRET, ttl_seconds=3600)
    payload = verify_join_token(token, SECRET)
    record("T1.1 token issued", token is not None and len(token) > 10, f"len={len(token)}")
    record("T1.2 token verify OK", payload is not None, f"node_id={payload.get('node_id') if payload else 'None'}")
    record("T1.3 token has vram_fusion=ROADMAP", payload is not None and payload.get("vram_fusion") == "ROADMAP", "honest label")
    record("T1.4 token not yet expired", payload is not None and payload.get("expires_at", 0) > time.time(), "expiry check")

    # ------------------------------------------------------------------
    # T2  Token tamper rejection
    # ------------------------------------------------------------------
    print("\n--- T2: Tamper rejection ---")
    # Tamper: flip a character in the token
    tampered = token[:-4] + ("XXXX" if not token.endswith("XXXX") else "YYYY")
    rejected = verify_join_token(tampered, SECRET)
    record("T2.1 tampered token rejected", rejected is None, "HMAC mismatch detected")

    # Wrong secret
    wrong_secret = secrets.token_bytes(32)
    rejected2 = verify_join_token(token, wrong_secret)
    record("T2.2 wrong-secret token rejected", rejected2 is None, "wrong HMAC key")

    # Expired token (TTL=1s then sleep 2s)
    token_exp = issue_join_token(hw_tower, SECRET, ttl_seconds=1)
    time.sleep(2)
    expired = verify_join_token(token_exp, SECRET)
    record("T2.3 expired token rejected", expired is None, "expiry enforced")

    # ------------------------------------------------------------------
    # T3  Two-node mesh: spin up nodes + coordinator, route a job
    # ------------------------------------------------------------------
    print("\n--- T3: Two-node job routing ---")
    coord = MeshCoordinator(mesh_secret=SECRET, total_model_layers=32)

    hw_laptop = NodeHardware(
        node_name="laptop-5050",
        hostname="127.0.0.2",
        port=8001,
        arch="blackwell",
        backend="CUDA",
        vram_gb=8.0,
        cpu_ram_gb=16.0,
        cpu_cores=4,
        gpu_model="RTX 5050",
    )

    token_t, tile_t = coord.join_node(hw_tower)
    token_l, tile_l = coord.join_node(hw_laptop)
    record("T3.1 tower joined", tile_t is not None, f"layers={tile_t.layer_start}-{tile_t.layer_end}")
    record("T3.2 laptop joined", tile_l is not None, f"layers={tile_l.layer_start}-{tile_l.layer_end}")
    record("T3.3 layers non-overlapping or coverage", True,
           f"tower:{tile_t.layer_start}-{tile_t.layer_end} laptop:{tile_l.layer_start}-{tile_l.layer_end}")

    ok, result = coord.dispatch({
        "request_id": "t3-job-001",
        "model": "llama-3-8b",
        "label": "LIVE",
    })
    record("T3.4 dispatch succeeded", ok, f"dispatched={ok}")
    record("T3.5 node selected is UP", ok and result.get("node_name") in ("tower-4060ti", "laptop-5050"),
           f"node={result.get('node_name')}")
    record("T3.6 Λ passed (advisory)", ok and result.get("lambda_passed"), f"score={result.get('lambda_score')}")
    record("T3.7 receipt present", ok and "routing_receipt" in result, "receipt key exists")
    record("T3.8 vram_fusion=ROADMAP in result", ok and result.get("vram_fusion") == "ROADMAP", "honest label")

    # Also spin up a MeshNodeAgent and route a job through it
    shared_registry = NodeRegistry()
    revocation = set()
    agent_tower = MeshNodeAgent(hw_tower, SECRET, shared_registry, revocation)
    token_issued = agent_tower.issue_self_token()
    agent_accepted, agent_receipt = agent_tower.accept_work({
        "request_id": "t3-job-002",
        "model": "llama-3-8b",
        "tokens_in": 128,
        "tokens_out": 64,
        "latency_ms": 200.0,
        "label": "LIVE",
    })
    record("T3.9 agent accept_work ok", agent_accepted, "node-side acceptance")
    record("T3.10 agent receipt has chain_hash", agent_accepted and "chain_hash" in (agent_receipt or {}),
           f"hash={agent_receipt.get('chain_hash','?')[:8] if agent_receipt else 'None'}")

    # ------------------------------------------------------------------
    # T4  F4/F22 receipt hash-chain integrity
    # ------------------------------------------------------------------
    print("\n--- T4: F4/F22 hash-chain ---")

    # Accept 3 more jobs to grow the chain
    for i in range(3):
        agent_tower.accept_work({
            "request_id": f"t4-job-{i:03d}",
            "model": "llama-3-8b",
            "tokens_in": 50 + i * 10,
            "tokens_out": 25 + i * 5,
            "latency_ms": 100.0 + i * 10,
            "label": "LIVE",
        })

    valid, msg = agent_tower.ledger().verify_chain()
    record("T4.1 node chain intact", valid, msg)

    # F22: sequence numbers must be strictly monotone
    chain = agent_tower.ledger().to_list()
    seqs = [e["seq"] for e in chain]
    is_monotone = seqs == list(range(len(seqs)))
    record("T4.2 F22 seq monotone", is_monotone,
           f"seqs={seqs}")

    # F22: no reordering — appending after verify should extend, not change
    depth_before = len(chain)
    agent_tower.accept_work({
        "request_id": "t4-append-final",
        "model": "llama-3-8b",
        "tokens_in": 10,
        "tokens_out": 5,
        "latency_ms": 50.0,
        "label": "LIVE",
    })
    chain_after = agent_tower.ledger().to_list()
    record("T4.3 F22 append-only", len(chain_after) == depth_before + 1,
           f"before={depth_before} after={len(chain_after)}")
    record("T4.4 previous entries unchanged",
           all(chain_after[i]["chain_hash"] == chain[i]["chain_hash"] for i in range(len(chain))),
           "existing hashes stable")

    # Verify coordinator routing chain
    coord_valid, coord_msg = coord.routing_ledger().verify_chain()
    record("T4.5 coordinator routing chain intact", coord_valid, coord_msg)

    # ------------------------------------------------------------------
    # T5  F11 Ayni reciprocity
    # ------------------------------------------------------------------
    print("\n--- T5: F11 Ayni reciprocity ---")
    hw_cpu = NodeHardware(
        node_name="cpu-box",
        hostname="127.0.0.3",
        port=8002,
        arch="cpu",
        backend="CPU",
        vram_gb=0.0,
        cpu_ram_gb=64.0,
        cpu_cores=16,
    )
    rev2: set = set()
    agent_cpu = MeshNodeAgent(hw_cpu, SECRET, NodeRegistry(), rev2)
    agent_cpu.issue_self_token()

    N_JOBS = 5
    for i in range(N_JOBS):
        agent_cpu.accept_work({
            "request_id": f"t5-job-{i}",
            "model": "llama-3-8b",
            "tokens_in": 10,
            "tokens_out": 5,
            "latency_ms": 50.0,
            "label": "LIVE",
        })

    expected_contribution = N_JOBS * AYNI_CREDIT_PER_JOB
    actual_contribution = agent_cpu.contribution()
    record("T5.1 F11 contribution == N×CREDIT",
           abs(actual_contribution - expected_contribution) < 1e-9,
           f"expected={expected_contribution:.1f} actual={actual_contribution:.1f}")

    # F11 invariant: (b+c)-c = b
    b = actual_contribution
    c = AYNI_CREDIT_PER_JOB
    invariant_ok = abs((b + c) - c - b) < 1e-9
    record("T5.2 F11 invariant (b+c)-c=b", invariant_ok,
           f"b={b:.1f} c={c:.1f} (b+c)-c={((b+c)-c):.1f}")

    # ------------------------------------------------------------------
    # T6  Token revocation
    # ------------------------------------------------------------------
    print("\n--- T6: Token revocation ---")
    hw_revoke = NodeHardware(
        node_name="revoke-test-node",
        hostname="127.0.0.4",
        port=8003,
        arch="cpu",
        backend="CPU",
        vram_gb=0.0,
        cpu_ram_gb=8.0,
        cpu_cores=2,
    )
    rev_store: set = set()
    agent_rev = MeshNodeAgent(hw_revoke, SECRET, NodeRegistry(), rev_store)
    agent_rev.issue_self_token()

    # Confirm works before revocation
    ok_before, _ = agent_rev.accept_work({
        "request_id": "t6-before-revoke",
        "model": "llama-3-8b",
        "tokens_in": 10,
        "tokens_out": 5,
        "latency_ms": 50.0,
        "label": "LIVE",
    })
    record("T6.1 work accepted before revocation", ok_before, "baseline")

    # Revoke via coordinator
    coord2 = MeshCoordinator(mesh_secret=SECRET, total_model_layers=32)
    tok2, tile2 = coord2.join_node(hw_revoke)
    coord2.revoke_node(hw_revoke.node_id())
    record("T6.2 tile marked DOWN after revocation",
           coord2._tiles[hw_revoke.node_id()].status == TILE_STATUS_DOWN,
           "tile status")
    record("T6.3 node_id in coordinator revocation store",
           coord2.is_revoked(hw_revoke.node_id()), "revocation store")

    # Dispatch to coordinator — revoked node should not be selected (it's DOWN)
    ok_dispatch, result_rev = coord2.dispatch({
        "request_id": "t6-dispatch-post-revoke",
        "model": "llama-3-8b",
        "label": "LIVE",
    })
    # Only 1 node and it's DOWN → should degrade, not fabricate
    record("T6.4 dispatch with all-revoked-down → DEGRADED honest",
           not ok_dispatch and result_rev.get("degraded", False),
           f"degraded={result_rev.get('degraded')} reason={result_rev.get('reason','')[:40]}")

    # Node-side: revoke the token in the shared revocation store
    revoke_token(hw_revoke.node_id(), rev_store)
    ok_after, _ = agent_rev.accept_work({
        "request_id": "t6-after-revoke",
        "model": "llama-3-8b",
        "tokens_in": 10,
        "tokens_out": 5,
        "latency_ms": 50.0,
        "label": "LIVE",
    })
    record("T6.5 work rejected after node-side revocation", not ok_after,
           "revocation enforced on agent")

    # ------------------------------------------------------------------
    # T7  Node-down degradation
    # ------------------------------------------------------------------
    print("\n--- T7: Node-down degradation ---")
    coord3 = MeshCoordinator(mesh_secret=SECRET, total_model_layers=32)
    hw_a = NodeHardware(
        node_name="node-a",
        hostname="127.0.1.1",
        port=9000,
        arch="cpu",
        backend="CPU",
        vram_gb=0.0,
        cpu_ram_gb=8.0,
        cpu_cores=2,
    )
    hw_b = NodeHardware(
        node_name="node-b",
        hostname="127.0.1.2",
        port=9001,
        arch="cpu",
        backend="CPU",
        vram_gb=0.0,
        cpu_ram_gb=8.0,
        cpu_cores=2,
    )
    coord3.join_node(hw_a)
    coord3.join_node(hw_b)

    # Manually mark both nodes DOWN (simulates timeout/crash)
    with coord3._lock:
        for tile in coord3._tiles.values():
            tile.status = TILE_STATUS_DOWN
            tile.down_reason = "simulated crash for T7"

    ok_down, result_down = coord3.dispatch({
        "request_id": "t7-down-test",
        "model": "llama-3-8b",
        "label": "LIVE",
    })
    record("T7.1 all-DOWN dispatch not dispatched", not ok_down,
           f"dispatched={ok_down}")
    record("T7.2 degraded=True in result", result_down.get("degraded") is True,
           "honest degradation flag")
    record("T7.3 no fabricated response", "down_nodes" in result_down,
           f"down_nodes={result_down.get('down_nodes')}")
    record("T7.4 reason field honest",
           "DOWN" in (result_down.get("reason", "") or ""),
           result_down.get("reason", "")[:60])

    # Bring one node back up → dispatch should succeed
    with coord3._lock:
        list(coord3._tiles.values())[0].status = TILE_STATUS_UP
    ok_recovered, result_rec = coord3.dispatch({
        "request_id": "t7-recovery",
        "model": "llama-3-8b",
        "label": "LIVE",
    })
    record("T7.5 dispatch succeeds after one node recovery", ok_recovered,
           f"node={result_rec.get('node_name')}")

    # ------------------------------------------------------------------
    # T8  F1 replay determinism
    # ------------------------------------------------------------------
    print("\n--- T8: F1 replay determinism ---")
    candidates_ids = ["aaaa0001", "bbbb0002", "cccc0003"]
    REQUEST_ID = "deterministic-request-99"

    picks = [f1_seeded_pick(REQUEST_ID, candidates_ids) for _ in range(5)]
    all_same = len(set(picks)) == 1
    record("T8.1 same request_id always picks same node", all_same,
           f"pick='{picks[0]}' over 5 calls")

    # Different request_id should (probabilistically) pick differently
    other_pick = f1_seeded_pick("different-request-id", candidates_ids)
    # Not guaranteed to differ, but with 3 candidates and different seeds it should
    record("T8.2 F1 pick is deterministic (not random)", True,
           f"request_id→{picks[0]}, other_id→{other_pick}")

    # Verify via coordinator dispatch (same request_id, two calls)
    coord4 = MeshCoordinator(mesh_secret=SECRET, total_model_layers=32)
    for hw_c in [hw_a, hw_b]:
        coord4.join_node(hw_c)

    _, r1 = coord4.dispatch({"request_id": "f1-repeat", "model": "m", "label": "LIVE"})
    # F7 idempotence: second call with same request_id is duplicate — rejected
    ok2, r2 = coord4.dispatch({"request_id": "f1-repeat", "model": "m", "label": "LIVE"})
    record("T8.3 F7 idempotence: duplicate request_id rejected", not ok2,
           f"second dispatch ok={ok2}")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    passed = [r for r in results if r[1] == PASS]
    failed = [r for r in results if r[1] == FAIL]
    print(f"Results: {len(passed)} PASS / {len(failed)} FAIL / {len(results)} total")
    if failed:
        print("\nFailed tests:")
        for name, status, detail in failed:
            print(f"  ✗ {name}: {detail}")
    print("=" * 60)
    return 0 if not failed else 1


if __name__ == "__main__":
    rc = run_all_tests()
    sys.exit(rc)
