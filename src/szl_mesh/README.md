# szl_mesh — node runtime (Dev 1 lane)

A **real, runnable** SZL-MESH node runtime implementing the design specs:

| Module | Spec | What it does |
|--------|------|--------------|
| `crdt.py` | 02 | Op-log LWW-map CRDT with **two-track state** (AUTHORIZED / OBSERVED). Convergent merge: commutative, associative, idempotent. |
| `receipts.py` | 01 | Doctrine-pinned `StateTransitionStatement` + DSSE envelope signed with **ECDSA-P256-SHA256 over the PAE**. Re-verifiable. Receipt Gate → AUTHORIZED/OBSERVED. |
| `enrollment.py` | 05 | **Doctrine-gated enrollment**: HMAC formation-key proof binding doctrine+kernel; rejects bad proof / wrong doctrine / Section 889 vendor / replay. |
| `node.py` | 01+02+05 | `MeshNode`: keypair, CRDT doc, receipt ledger, enroll, `write()` (receipted transition), `apply_remote()`. |
| `harness.py` | — | `MeshHarness`: in-process N-node mesh, randomised gossip, convergence check. |
| `demo.py` | — | `python -m szl_mesh.demo` — live convergence proof + re-verified receipts. |

## Run

```bash
PYTHONPATH=src python3 -m szl_mesh.demo
PYTHONPATH=src python3 tests/test_runtime.py
```

## Doctrine

v11 LOCKED `749/14/163` @ `c7c0ba17`, SLSA L1. Section 889 vendors exactly 5.
The **two-track soft-safety AP model is the real shipped one**. This runtime
makes **no unconditional BFT claim** (Khipu BFT unconditional = Conjecture 2;
quorum certification is Dev 2's lane, layered on these ECDSA-P256 receipts).
Receipts are real (never fabricated); no keys are committed.
