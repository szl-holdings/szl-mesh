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

## Enrollment and receipt trust

Origin: OpenAI Codex, implementing the owner's repository audit.

`MeshNode` authorizes a received operation only against its enrolled formation's
public-key registry. Before enrollment, or after a failed first enrollment,
valid self-signed receipts remain `OBSERVED`; their signatures can still be
checked and their operations remain available for forensic inspection.
Reapplying a receipt after successful enrollment checks the new registry.

The gateway accepts only canonical P-256 SubjectPublicKeyInfo DER whose SHA-256
identity matches `node_id`. The formation proof binds that identity. Invalid,
missing or substituted key material is rejected before the certificate store
changes, so a captured proof cannot reserve the identity with a different key.

`verify_receipt_signature()` establishes signature/identity self-consistency.
The lower-level `validate_receipt(..., pubkey_registry=None)` mode does not
establish membership in a trusted formation. Runtime callers always supply a
registry, including an empty registry before enrollment.

`MeshNode` also binds the signed document and signer to the operation's
`doc_id` and `node_id`. This runtime has no delegated-signing mechanism:
an enrolled peer cannot authorize an operation attributed to another node.
Validly signed statements with a different document or author remain
`OBSERVED` with `CONTEXT_MISMATCH`; malformed type, document ID, transition
class, head lists or SLSA level remain `OBSERVED` with `BAD_STATEMENT`.
The operation and its signature remain available for inspection.

Direct callers of `validate_receipt` can supply `expected_document_id` and
`expected_node_id` as keyword arguments. Those expectations must come from
the operation or the caller's trusted context, not from the receipt itself.
Omitting them preserves byte-level validation without application-context
binding. Head-list validation checks strings and list shape only; it does
not prove causal history or require sender and receiver heads to match.

This remains an in-process reference runtime: the certificate store and
revocations are held in memory, and this change does not implement the planned
Formation CA, durable enrollment, proof of key possession or transport security.

## Doctrine

v11 LOCKED `749/14/163` @ `c7c0ba17`, SLSA L1. Section 889 vendors exactly 5.
The **two-track soft-safety AP model is the real shipped one**. This runtime
makes **no unconditional BFT claim** (Khipu BFT unconditional = Conjecture 2;
quorum certification is Dev 2's lane, layered on these ECDSA-P256 receipts).
Receipts are real (never fabricated); no keys are committed.
