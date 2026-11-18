# Mesh Chronicle — node-local proof database (v1)

**Status:** implemented and locally tested in `szl-mesh`. This is a **node-local
SQLite WAL evidence engine**, not a hosted distributed database or production
release. Source CI is independent of fleet deployment.

## Design: two-track causal evidence, not a mutable "current truth" table

A node's CRDT operation is stored once by its SHA-256 content-derived `op_id`.
Each exact DSSE envelope is stored independently by its own SHA-256 digest.
A local append-only event chain records each insertion. The public-key
registry, revocation set and execution authority are **not** stored as facts
by this database.

The query engine replays the existing `CRDTDocument` total-order LWW fold.
Its **OBSERVED** view includes records for situational awareness even if an
envelope is absent or invalid. Its **AUTHORIZED** view requires an **explicit,
independently supplied public-key registry and revocation set**, rechecking
the original doctrine-pinned DSSE receipt at the time of each read. The
database never accepts a sender-supplied `track: AUTHORIZED` as authority.

This produces useful *multidimensional* queries: the same immutable history
has an observed state, a current-authority state, a local ingest-sequence
time-travel read, value-free candidate explanations, an optional bounded
`causal_graph()` of **signer-asserted predecessor claims**, and offline
convergent replication. Graph edges distinguish currently validated signer
claims from unverified claims and never assert global causality, consensus,
signed database checkpoints or deployment parity. Local event-order hashes
are intentionally not convergence
identities; the CRDT state digest is.

## How it fits the existing SZL-MESH runtime

The persistence layer is opt-in. Existing `MeshNode` callers are unchanged.
When a store is passed to a node, local and remote state transitions commit
an operation plus the exact original receipt atomically *before* in-memory
mutation. A database failure prevents a new state transition and does not
advance its Lamport clock. No private key is persisted.

```python
from szl_mesh import MeshNode, FormationGateway, MeshChronicle, AUTHORIZED
from pathlib import Path
import secrets

key = secrets.token_bytes(32)  # demo-only ephemeral key, never print/store
gateway = FormationGateway("local-demo", key)
with MeshChronicle(Path("private-node.sqlite")) as db:
    node = MeshNode("local", "demo/state", chronicle=db)
    assert node.enroll(gateway, key).success
    node.write("model.status", {"evidence": "SIMULATED"})
    # Independent trust and revocation evidence are both required.
    assert db.state(
        "demo/state", track=AUTHORIZED,
        registry=gateway.pubkey_registry(), revoked=gateway.revoked,
    )["model.status"]["evidence"] == "SIMULATED"
    assert db.verify_integrity()["status"] == "LOCAL_INTEGRITY_VERIFIED"
```

**The example is not production enrollment.** The existing receipt verifier
permits only a five-second UTC timestamp window for current authorization.
Reopening an old file **does not** renew that window, restore node signing
keys or enroll a new node. On recovery, use `replay_to(MeshNode(...))` only
with an empty and unenrolled node: it restores **OBSERVED** evidence while
refusing to reconstruct an authority identity.

## Local smoke (no network and no deployment)

Install the source package in a Python 3.11/3.12 environment, then run:

```bash
python -m pip install -e .
python -m szl_mesh.chronicle_demo --demo
```

It returns `SIMULATED_LOCAL_PASS` when synthetic enrollment, two-node
in-memory state, SQLite ingestion, integrity and current readback succeed.
It never opens a provider connection. With `--db path/to/test.sqlite`,
the demo writes *synthetic* evidence into a local file. To verify an existing
file without adding events:

```bash
python -m szl_mesh.chronicle_demo --verify-only --db path/to/test.sqlite
```

The CLI returns sanitized errors; the local database may contain sensitive
operational state, and the engine **does not encrypt data at rest**. Restrict
file-system permissions, keep the database on a local disk (not a shared
network filesystem), and use approved encrypted backup infrastructure.
Backups must include SQLite's WAL state via a consistent backup/snapshot
method; blindly copying only the primary file while it is open is unsafe.
Do not commit `*.sqlite` / `*.db` into Git or publish as Hugging Face data.

## Explicit v1 invariants

- SQLite foreign keys, WAL, FULL synchronous mode, bounded writes, validated
  SQL parameters, and transaction rollback on a rejected sync batch.
- Content-derived operation hashes rechecked before replay; duplicate
  operations/receipts are idempotent.
- Rejected or missing receipts can be kept for awareness but never confer
  authority. A later valid receipt cannot be erased by an invalid replay.
- Up to 256 records per atomic ingest batch and eight distinct envelopes per
  operation. Larger workloads need reviewed pagination and back-pressure.
- Every replay requires a fresh independent trust/revocation snapshot to
  construct the authorized view. Missing/stale trust is an operational hold.
- SQL triggers block ordinary updates/deletes. The local SHA-256 event chain
  detects accidental or simple record changes but is **not an externally
  anchored, tamper-proof, signed, Byzantine or consensus ledger**.
- Audit time-travel selects a historical *local ingestion boundary*, while
  authorized receipt status is always evaluated at the **current** supplied
  time. No historical admission or legal proof is invented.
- No WAN replication, cross-region quorum, clock synchronization, key
  management, production backups, GPU inference, HF publishing, Replit,
  Cloudflare routing, or payment settlement is established by this module.

## Production architecture and admission criteria

The next architecture milestone is an independently secured PostgreSQL
projection (with exact data provenance and row-level controls), a signed
checkpoint/restore contract, and a zero-trust fleet sync adapter. The
PostgreSQL side must be a **derived read model**, not a second owner of
CRDT transitions. No existing Neon project is repurposed without review.

Before releasing to a fleet, require signed artifact provenance, backup +
restore under power-loss simulation, SQLite size/latency budgets, correct
revocation propagation during partitions, durable idempotent sync, encryption
and access controls, supervised service startup, live ingress validation,
and exact deployment readback. Maintain Doctrine v11 `749/14/163` and
kernel `c7c0ba17`; Λ remains Conjecture 1, and no unconditional BFT,
production or energy-efficiency proof is claimed.
