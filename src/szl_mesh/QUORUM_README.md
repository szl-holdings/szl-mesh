# szl_mesh.quorum — Khipu 3-of-4 quorum wiring (Mesh Dev 2)

Wires the **REAL** `khipu-consensus` BFT engine into SZL-MESH, layered on Dev 1's
ECDSA-P256 DSSE receipt runtime. This module does **not** reimplement consensus or
cryptography — it imports the reference engine (`khipu_consensus`: `sign_verdict`,
`verify_verdict`, `tally`, `OrganVerdict`, `canonical_json`, `pae`) and uses its
real **ECDSA-P256-SHA256 DSSE** signatures.

## API

| Function / class | Purpose |
|---|---|
| `propose_action(action, witness_keys, …) -> QuorumCertificate` | Each of 4 organ witnesses signs the SAME action hash; collect the ≥3-of-4 `allow` sigs. `canonical` iff ≥ threshold distinct valid allow-sigs. |
| `verify_quorum(qc, pubkeys) -> QuorumVerification` | Independently re-verify EVERY witness ECDSA-P256 sig over the DSSE PAE; confirm ≥3 distinct valid `allow` sigs over the SAME hash ⇒ `canonical: True`. |
| `action_hash(action) -> str` | Deterministic action hash (engine `canonical_json` + SHA-256), or pass Dev 1's `change_hash` directly. |
| `CorroborationLedger` / `combined_classification` | spec/04 **soft-safety AP** corroboration annotation. Runs ALONGSIDE the AP CRDT; **NEVER blocks writes**. |

## Corroboration implementation boundary

CorroborationLedger counts distinct **claimed node IDs**, not independently
authenticated peer identities. The AUTHORIZED string given to
combined_classification is not verified by that helper. CORROBORATED does
not mean command permit, receipt verification or a BFT certificate. Effects
remain under the separate signed receipt and governance controller gates.

The local collector binds the first transition class and policy to one
content SHA-256. Its deadline begins at collection time; an external expiry
may shorten but not extend it. Stale, reclassified, and replayed observations
cannot gain confidence. Read-time expiry evaluation does not mutate state.
No network transport or replicated CRDT merge is performed here.

The conditional mathematical claim k > f presumes authenticated independent
identities. This string-ID API cannot establish that premise. Cryptographic
Khipu quorum verification is a separate interface, with unconditional
safety still marked Conjecture 2.

Primary references (not dependencies, integrations, or benchmark results):

- Castro and Liskov, Practical Byzantine Fault Tolerance, OSDI 1999:
  https://www.usenix.org/conference/osdi-99/practical-byzantine-fault-tolerance
- Shapiro et al., convergent and commutative replicated data types, 2011:
  https://www.lip6.fr/Marc.Shapiro/papers/2011/Comprehensive-CRDTs-RR7506-2011-01.pdf
- Defense Unicorns Peat, CRDT and enrollment source:
  https://github.com/defenseunicorns/peat
- Anduril Lattice, entity provenance/expiry:
  https://developer.anduril.com/guides/entities/overview
- Palantir Ontology, typed actions and governed object access:
  https://www.palantir.com/docs/foundry/object-backend/overview
- Anthropic, outcome-oriented agent evaluations, 2026:
  https://www.anthropic.com/research/demystifying-evals-for-ai-agents

## Interop with Dev 1 runtime
`propose_action` accepts Dev 1's `StateTransitionStatement` dict directly (hashed via
the engine's `canonical_json`), or Dev 1's 64-hex `change_hash` string as-is. The
returned `QuorumCertificate.action_hash` is what all 4 witnesses signed.

## Quorum facts
- `n = 4`, `threshold = 3` ⇒ tolerates `f = 1`.
- A **bad/missing 4th** witness still yields **canonical** (3-of-4).
- **Two bad** witnesses ⇒ **NOT canonical** (2-of-4 < 3).
- Wrong-hash, forged, `block`, and duplicate-organ sigs never count.

## Honesty (Doctrine v11)
The 3-of-4 Khipu quorum is **REAL** (per-witness ECDSA-P256 DSSE, `cosign verify-blob`-compatible).
Khipu BFT **unconditional** safety is **Conjecture 2 — NOT a theorem, never claimed proven**.
The **soft-safety AP** corroboration model (spec/04) is the real, shipped behaviour.
**Never fabricate a quorum. Never commit a key** (witness keys are in-memory/local only).

## Proof
`PYTHONPATH=src python3 tests/test_quorum.py` — byte-exact match against all 5
`khipu-consensus/testdata/vectors.json` cases, plus 3-of-4 / 2-bad / wrong-hash /
forged-sig / corroboration cases (10/10). Engine `__init__.py` sha256
`7b33c053bed58a94ecb8d83b33295ff0a067fc20645e5e72bc4da6eca1980a77`,
vectors sha256 `86236cdde8f9ccb2d64f5d9011dcb4db141575b7bfd54ae24985bbeeb3587270`.

Verification uses a caller-owned 3-of-4 policy by default. Certificate `threshold` and `n` fields must match that policy; changing unsigned metadata cannot lower the required number of signatures. Callers using a different policy must explicitly pass `verify_quorum(qc, pubkeys, threshold=..., n=...)`. Policies require integer `1 <= threshold <= n`.
