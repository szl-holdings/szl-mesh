# szl-mesh domain leader study r1 (propose-only)

Date: 2026-11-23. Method: web-verified leader landscape + governing-seat synthesis (Kimi nonce T3-SZL-MESH-BRIEF). This card is documentation only; it changes no code, CI, config, or existing PR status. All absorb actions are FUTURE PROPOSALS (non-authorizing); implementation and merges remain separately reviewed and gated.

## Domain: doctrine-pinned CRDT coordination mesh for air-gapped or offline fleets

## Leaders studied (web-verified 2026-11-23)

1. peat (https://github.com/defenseunicorns/peat) — CRDT mesh protocol with Ed25519-signed operations and formation-key enrollment over Automerge + Iroh QUIC; moat is the underlying mesh substrate szl-mesh layers on without forking.
2. Automerge (https://github.com/automerge/automerge) — mature JSON-like CRDT library with a documented sync protocol and broad language bindings; moat is convergence semantics and interoperability rather than doctrine or authorization policy.
3. DSSE specification (https://github.com/secure-systems-lab/dsse) — standard envelope format for signing methods used by in-toto/Sigstore ecosystems; moat is a shared signature-envelope convention, not proof that a signed transition is authorized or true.

## Absorb actions (FUTURE PROPOSALS, non-authorizing)

1. (peat) Propose a compatibility and conformance study for signed operations, formation-key enrollment, and transport behavior while preserving szl-mesh as a layer rather than a fork. Any doctrine-gated enrollment, DSSE receipt, AUTHORIZED/OBSERVED split, or Byzantine soft-voting change would require separate review; protocol compatibility would not establish authorization, availability, or measured performance.
2. (Automerge) Propose documenting sync and convergence test vectors for offline partitions, concurrent transitions, revocation-set growth, and chronicle projections, using the documented sync protocol as the reference. This would not make the skip-layer O(n) claim proven: it remains Conjecture 1 OPEN and advisory, and throughput remains MODELED until MEASURED in a live run.
3. (DSSE specification) Propose an interoperability review of receipt envelopes, payload typing, signature verification, and doctrine/kernel binding for doctrine version 749/14/163 and kernel commit c7c0ba17. DSSE standardizes an envelope, not trust; k-of-n corroboration (default k=2, 30s window) remains soft-voting, and independent key management, verification, and third-party monitoring would still be required.
4. (baseline) Propose an evidence matrix covering the exactly five Section 889 vendor checks, HMAC-SHA256 API proofs, honest_labels on every response, no-OCSP revocation behavior, and opt-in SQLite WAL chronicle projections. The repository remains a design skeleton with implementation in progress; VRAM fusion remains ROADMAP only, and this study proposes no speedup, energy, security, or live-throughput claim.

## Do not do (per governing seat)

Do not merge, bypass the signature wall, or claim implementation beyond this card.
