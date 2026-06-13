"""
szl_mesh.demo — runnable proof the mesh works.

    python -m szl_mesh.demo

Spins up 4 in-process nodes, enrolls them (doctrine-gated; one rejected node
demonstrates the gate), each writes receipted CRDT state transitions, gossips
all ops+receipts in RANDOMISED order, and prints:
  - the convergence proof (identical state digests across all nodes)
  - a sample DSSE receipt (re-verified live)
  - the two-track (AUTHORIZED vs OBSERVED) views

Doctrine v11 LOCKED 749/14/163 · Kernel commit c7c0ba17 · SLSA L1.
Two-track soft-safety AP model (the real shipped one). No unconditional BFT
claim (Khipu BFT unconditional = Conjecture 2).
"""

from __future__ import annotations

import json
import sys

from . import receipts as rcpt
from .crdt import AUTHORIZED, OBSERVED
from .harness import MeshHarness

FORMATION_KEY = b"demo-formation-key-not-a-secret-in-repo"
DOC_ID = "demo-formation-001/platforms"


def _hr(title: str) -> None:
    print("=" * 64)
    print(title)
    print("=" * 64)


def main() -> int:
    _hr("SZL-MESH live multi-node mesh demo")
    print(f"  Doctrine: {rcpt.DOCTRINE_VERSION}  Kernel: {rcpt.KERNEL_COMMIT}  "
          f"SLSA: {rcpt.SLSA_LEVEL}")
    print(f"  Section 889 vendors (exactly 5): {rcpt.SECTION_889_VENDORS}")
    print(f"  CRDT doc: {DOC_ID}")
    print()

    harness = MeshHarness("demo-formation-001", DOC_ID, FORMATION_KEY, seed=42)

    # ── Enrollment (spec/05): 3 valid nodes + 1 doctrine-rejected node ──
    print("[1] Doctrine-gated enrollment (spec/05)")
    for nm in ("alpha", "bravo", "charlie"):
        node, res = harness.add_node(nm)
        print(f"    + {nm:8s} node_id={node.node_id[:16]}…  "
              f"enrolled={res.success}")

    # Rejected: a node attesting a Section 889 vendor.
    bad_node, bad_res = harness.add_node("delta-889", hardware_vendor="Huawei")
    print(f"    - delta-889 enrolled={bad_res.success} "
          f"reason={bad_res.failure_reason}  (REJECTED, as designed)")
    print(f"    enrolled nodes in mesh: {[n.name for n in harness.nodes]}")
    print()

    # ── Receipted writes (spec/01 + spec/02) ────────────────────────
    print("[2] Receipted CRDT state transitions (spec/01)")
    alpha, bravo, charlie = harness.nodes
    sample_receipt = None
    writes = [
        (alpha, "platform.alpha.status", "ONLINE", "PLATFORM_STATUS"),
        (bravo, "platform.bravo.status", "ONLINE", "PLATFORM_STATUS"),
        (charlie, "deployment.pkg-7", "v1.4.2", "DEPLOYMENT"),
        (alpha, "command.move-north", "ISSUED", "COMMAND"),
        (bravo, "platform.alpha.status", "DEGRADED", "PLATFORM_STATUS"),  # LWW
    ]
    for node, key, val, cls in writes:
        rec = harness.write(node, key, val, transition_class=cls)
        if sample_receipt is None:
            sample_receipt = rec["receipt"]
        print(f"    {node.name:8s} {cls:15s} {key} = {val!r}  "
              f"track={rec['track']}  change_hash={rec['change_hash'][:12]}…")
    print()

    # ── Gossip in randomised order ──────────────────────────────────
    print("[3] Gossip ops + receipts to all peers (RANDOMISED delivery order)")
    harness.gossip(shuffle=True)
    print("    delivery complete.")
    print()

    # ── Convergence proof ───────────────────────────────────────────
    _hr("[4] CONVERGENCE PROOF")
    for track in (AUTHORIZED, OBSERVED):
        digests = harness.digests(track)
        ok = harness.converged(track)
        print(f"  {track} track  converged={ok}")
        for name, dig in digests.items():
            print(f"      {name:8s} digest={dig}")
        print()

    print("  AUTHORIZED materialised view (alpha):")
    print("   ", json.dumps(alpha.authorized_state(), indent=6, sort_keys=True))
    print()
    print("  OBSERVED materialised view (alpha):")
    print("   ", json.dumps(alpha.observed_state(), indent=6, sort_keys=True))
    print()

    # ── Receipt re-verification ─────────────────────────────────────
    _hr("[5] DSSE RECEIPT (re-verified live)")
    print(json.dumps(sample_receipt, indent=2)[:1400])
    print("    …")
    verified = rcpt.verify_receipt_signature(sample_receipt)
    print(f"\n  verify_receipt_signature(sample) = {verified}")
    for n in harness.nodes:
        v, t = n.verify_ledger()
        print(f"  {n.name:8s} ledger receipts re-verified: {v}/{t}")
    print()

    all_ok = (
        harness.converged(AUTHORIZED)
        and harness.converged(OBSERVED)
        and verified
        and not bad_res.success
    )
    _hr("RESULT: " + ("MESH CONVERGED + RECEIPTS VALID ✓" if all_ok else "FAILED ✗"))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
