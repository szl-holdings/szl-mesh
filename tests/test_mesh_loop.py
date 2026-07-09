# SPDX-License-Identifier: Apache-2.0
# SZL Holdings — clean-room, permissive (Apache-2.0 compatible)
# © 2026 Lutar, Stephen P. — SZL Holdings · ORCID 0009-0001-0110-4173 · Doctrine v11/v12
# Authored by Yachay (CTO) — Ouroboros bounded orchestration-loop self-tests (CPU-only)
"""
test_mesh_loop.py — CPU-only self-tests for the Ouroboros bounded loop
======================================================================
Exercises MeshCoordinator.run_pipeline() — the bounded, terminating,
receipt-closed orchestration loop that walks the model's layer-range pipeline
and dispatches each stage through the governed scheduler.

Tests (all CPU-only, no GPU, no network):

  L1  py_compile: coordinator module compiles cleanly.
  L2  _loop_budget: env parsing + safe default + clamp (no unbounded value).
  L3  converged: a fully-covered 3-stage pipeline runs to "converged" and
      emits one routing receipt per stage (receipt-closed).
  L4  budget_exhausted: max_steps below the pipeline depth exits honestly as
      "budget_exhausted" — NEVER a faked convergence.
  L5  degraded: a coverage gap (DOWN stage) exits honestly as "degraded" with
      no fabricated stage.
  L6  loop block shape: steps/maxBudget/exit/trace/doctrine/receiptsInEqOut
      present; doctrine == "bounded, terminating, receipt-closed"; every trace
      entry carries {n, type, label}.
  L7  back-compat: plain dispatch() is unchanged (still succeeds, no `loop`
      key injected into the single-dispatch result).

HONEST LABELS:
  - Λ is Conjecture 1 (advisory, never a theorem).
  - VRAM fusion = ROADMAP. throughput = MODELED. No real inference runs here.
"""

from __future__ import annotations

import os
import py_compile
import secrets
import sys
from pathlib import Path
from typing import List, Tuple

CODE_DIR = Path(__file__).parent.parent / "src" / "sovereign"
sys.path.insert(0, str(CODE_DIR))

from szl_mesh_agent import NodeHardware  # noqa: E402
from szl_mesh_coordinator import (  # noqa: E402
    DEFAULT_LOOP_BUDGET,
    LOOP_DOCTRINE,
    MAX_LOOP_BUDGET,
    TILE_STATUS_DOWN,
    TILE_STATUS_UP,
    MeshCoordinator,
    _loop_budget,
)

PASS = "PASS"
FAIL = "FAIL"
results: List[Tuple[str, str, str]] = []


def record(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, PASS if ok else FAIL, detail))
    print(f"  [{'✓' if ok else '✗'}] {name}: {PASS if ok else FAIL}  {detail}")


def _hw(name: str, host: str, port: int) -> NodeHardware:
    return NodeHardware(
        node_name=name, hostname=host, port=port, arch="cpu", backend="CPU",
        vram_gb=0.0, cpu_ram_gb=8.0, cpu_cores=2,
    )


def _staged_coordinator(secret: bytes) -> MeshCoordinator:
    """Build a coordinator whose 3 nodes form a contiguous 0-30 pipeline."""
    coord = MeshCoordinator(mesh_secret=secret, total_model_layers=30)
    specs = [("node-a", "127.0.2.1", 0, 10), ("node-b", "127.0.2.2", 10, 20),
             ("node-c", "127.0.2.3", 20, 30)]
    for nm, host, ls, le in specs:
        hw = _hw(nm, host, 9000)
        coord.join_node(hw)
        # Deterministically pin layer ranges so the pipeline has 3 real stages.
        with coord._lock:
            tile = coord._tiles[hw.node_id()]
            tile.layer_start, tile.layer_end = ls, le
    return coord


def run_all_tests() -> int:
    print("\n" + "=" * 60)
    print("SZL Sovereign Mesh — Ouroboros bounded-loop self-tests")
    print("  doctrine: bounded, terminating, receipt-closed")
    print("  Λ = advisory Conjecture 1 (NEVER a theorem)")
    print("=" * 60 + "\n")

    SECRET = secrets.token_bytes(32)

    # --- L1 py_compile ---
    print("--- L1: py_compile ---")
    try:
        py_compile.compile(str(CODE_DIR / "szl_mesh_coordinator.py"), doraise=True)
        record("L1 py_compile coordinator", True, "syntax OK")
    except py_compile.PyCompileError as exc:
        record("L1 py_compile coordinator", False, str(exc))

    # --- L2 _loop_budget ---
    print("\n--- L2: _loop_budget env/default/clamp ---")
    saved = os.environ.pop("SZL_MESH_LOOP_BUDGET", None)
    try:
        record("L2.1 default when unset", _loop_budget() == DEFAULT_LOOP_BUDGET,
               f"={_loop_budget()}")
        os.environ["SZL_MESH_LOOP_BUDGET"] = "3"
        record("L2.2 env override honored", _loop_budget() == 3, "=3")
        os.environ["SZL_MESH_LOOP_BUDGET"] = "0"
        record("L2.3 invalid (<1) -> default", _loop_budget() == DEFAULT_LOOP_BUDGET,
               f"={_loop_budget()}")
        os.environ["SZL_MESH_LOOP_BUDGET"] = "notanint"
        record("L2.4 non-int -> default", _loop_budget() == DEFAULT_LOOP_BUDGET,
               f"={_loop_budget()}")
        os.environ["SZL_MESH_LOOP_BUDGET"] = str(MAX_LOOP_BUDGET * 10)
        record("L2.5 huge value clamped to MAX", _loop_budget() == MAX_LOOP_BUDGET,
               f"={_loop_budget()}")
    finally:
        os.environ.pop("SZL_MESH_LOOP_BUDGET", None)
        if saved is not None:
            os.environ["SZL_MESH_LOOP_BUDGET"] = saved

    # --- L3 converged ---
    print("\n--- L3: converged pipeline ---")
    coord = _staged_coordinator(SECRET)
    converged, res = coord.run_pipeline({"request_id": "L3", "model": "m", "label": "LIVE"})
    record("L3.1 converged True", converged, f"exit={res['loop']['exit']}")
    record("L3.2 exit == converged", res["loop"]["exit"] == "converged", "")
    record("L3.3 three stages dispatched", res["stage_count"] == 3,
           f"stage_count={res['stage_count']}")
    record("L3.4 pipeline covered", res["pipeline_covered"] is True, "")
    # receipt-closed: one routing receipt per stage
    receipts = [s.get("routing_receipt") for s in res["stages"] if s.get("dispatched")]
    record("L3.5 receipt-closed (1 receipt/stage)",
           len(receipts) == 3 and all(r and "chain_hash" in r for r in receipts),
           f"receipts={len(receipts)}")
    ledger_ok, ledger_msg = coord.routing_ledger().verify_chain()
    record("L3.6 routing chain intact after loop", ledger_ok, ledger_msg)

    # --- L4 budget_exhausted ---
    print("\n--- L4: budget_exhausted (honest, never faked) ---")
    coord2 = _staged_coordinator(SECRET)
    conv2, res2 = coord2.run_pipeline({"request_id": "L4", "model": "m", "label": "LIVE"},
                                      max_steps=2)
    record("L4.1 not converged", conv2 is False, f"exit={res2['loop']['exit']}")
    record("L4.2 exit == budget_exhausted", res2["loop"]["exit"] == "budget_exhausted", "")
    record("L4.3 maxBudget honored", res2["loop"]["maxBudget"] == 2,
           f"maxBudget={res2['loop']['maxBudget']}")
    record("L4.4 steps <= budget (bounded)", res2["loop"]["steps"] <= 2,
           f"steps={res2['loop']['steps']}")

    # --- L5 degraded (coverage gap, no fabrication) ---
    print("\n--- L5: degraded coverage gap ---")
    coord3 = _staged_coordinator(SECRET)
    # Take the MIDDLE stage (layers 10-20) DOWN -> genuine gap in the pipeline.
    with coord3._lock:
        for tile in coord3._tiles.values():
            if tile.layer_start == 10:
                tile.status = TILE_STATUS_DOWN
                tile.down_reason = "simulated crash for L5"
    conv3, res3 = coord3.run_pipeline({"request_id": "L5", "model": "m", "label": "LIVE"})
    record("L5.1 not converged", conv3 is False, f"exit={res3['loop']['exit']}")
    record("L5.2 exit == degraded", res3["loop"]["exit"] == "degraded", "")
    record("L5.3 pipeline not covered (honest gap)", res3["pipeline_covered"] is False, "")

    # --- L6 loop block shape ---
    print("\n--- L6: loop block shape ---")
    lb = res["loop"]
    required = {"steps", "maxBudget", "exit", "trace", "doctrine", "receiptsInEqOut"}
    record("L6.1 all LoopTrace fields present", required.issubset(lb.keys()),
           f"keys={sorted(lb.keys())}")
    record("L6.2 doctrine string exact", lb["doctrine"] == LOOP_DOCTRINE
           == "bounded, terminating, receipt-closed", lb["doctrine"])
    record("L6.3 every trace entry has n/type/label",
           all({"n", "type", "label"}.issubset(e.keys()) for e in lb["trace"]),
           f"trace_len={len(lb['trace'])}")
    record("L6.4 receiptsInEqOut labelled True", lb["receiptsInEqOut"] is True, "doctrine-not-math")
    record("L6.5 exit is an honest enum value",
           res2["loop"]["exit"] in ("converged", "budget_exhausted", "degraded", "error"), "")

    # --- L7 back-compat: dispatch unchanged ---
    print("\n--- L7: back-compat dispatch() ---")
    coord4 = _staged_coordinator(SECRET)
    ok4, dres = coord4.dispatch({"request_id": "L7", "model": "m", "label": "LIVE"})
    record("L7.1 plain dispatch still succeeds", ok4, f"node={dres.get('node_name')}")
    record("L7.2 no `loop` key injected into dispatch result", "loop" not in dres,
           "single-dispatch result unchanged")

    print("\n" + "=" * 60)
    passed = [r for r in results if r[1] == PASS]
    failed = [r for r in results if r[1] == FAIL]
    print(f"Results: {len(passed)} PASS / {len(failed)} FAIL / {len(results)} total")
    if failed:
        print("\nFailed tests:")
        for name, _s, detail in failed:
            print(f"  ✗ {name}: {detail}")
    print("=" * 60)
    return 0 if not failed else 1


# --- pytest-discoverable entrypoint (works under pytest AND standalone) ---
def test_ouroboros_bounded_loop() -> None:
    assert run_all_tests() == 0


if __name__ == "__main__":
    sys.exit(run_all_tests())
