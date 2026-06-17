# Architecture — szl-mesh

> Doctrine v11 LOCKED `749/14/163` · Kernel commit `c7c0ba17` · locked-proven = 8
> `{F1,F4,F7,F11,F12,F18,F19,F22}` · Λ = **Conjecture 1** (NOT theorem) · SLSA L1
> honest · L2 verified-provenance on roadmap (NOT L3).

`szl-mesh` is a **doctrine-pinned CRDT coordination layer** layered on peat. It keeps
SZL's governance services in sync across an air-gapped fleet — including when nodes go
offline — and brings always-converging shared state plus Byzantine-fault-tolerant
agreement to edge / disconnected deployments.

## Where this sits in the deployment chain

```
szl-fleet-overlay   ← UDS Operator packages
uds-bundles         ← bundle manifests
szl-mesh            ← CRDT coordination layer (THIS repo)
szl-uds-deployment  ← live air-gap deploy
```

## Repository layout

```
szl-mesh/
├── src/             CRDT mesh implementation (BFT wiring, 3-of-4 Khipu quorum).
├── proto/           Protocol buffer definitions for cross-node spans/messages.
├── spec/            Protocol + invariant specifications.
├── examples/        Runnable usage examples.
├── tests/           Self-tests.
├── pyproject.toml   Python packaging / pins.
└── CITATION.cff     Citation metadata.
```

## What it provides

- **CRDT shared state** — convergent, conflict-free replication so disconnected nodes
  reconcile deterministically on reconnect.
- **3-of-4 Khipu quorum** — Byzantine-fault-tolerant agreement; each witness signs an
  action hash, consistent with the **khipu-consensus** model. Khipu BFT is tracked as
  **Conjecture 2** (Wave23 conditional), not a closed theorem.
- **Signed, replayable audit receipts** — every governance action emits a signed,
  verifiable receipt onto the Khipu DAG (`receipts.in ≡ receipts.out`).
- **Seven inventions beyond UDS Fleet** — documented in the README technical section.

## CI gates (required on `main`)

`DCO` · `Scorecard analysis workflow`. Doctrine + overclaim guards and pin-check also
run. PRs are required to `main`.

Public product walkthrough: [docs.szlholdings.com](https://szl-holdings.github.io/docs-site).

---

© 2026 Lutar, Stephen P. — SZL Holdings · Apache-2.0
