# SZL Mesh Convergence Lab

A finite, deterministic inspection surface over the repository's existing `CRDTDocument` and `Op` implementation.

## Run

```bash
python -m pip install --constraint lab/constraints.txt \
  --editable . \
  --requirement lab/requirements.txt \
  --requirement lab/requirements-dev.txt
pytest -q lab/tests
uvicorn lab.app:app --host 127.0.0.1 --port 7860
```

## API

```text
GET  /healthz
GET  /readyz
GET  /api/source
GET  /api/scenarios
GET  /api/scenarios/{slug}
POST /api/simulate
```

`POST /api/simulate` accepts no more than eight replicas and 64 operations. The runner distributes input operations into finite partitions, reconciles every replica with the same operation set under different deterministic arrival orders, and records scenario-specific convergence, replay idempotence, and sampled commutativity and associativity checks.

## Evidence boundary

The lab does not start the Mesh transport, enroll peers, validate DSSE signatures, contact a remote service, mutate a repository, or claim Byzantine fault tolerance. `AUTHORIZED`, `OBSERVED`, and `REVOKED` are explicit scenario inputs. A converged receipt is evidence for the submitted finite scenario—not a proof about an unbounded deployment.
