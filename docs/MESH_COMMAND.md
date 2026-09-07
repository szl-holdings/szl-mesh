# SZL Mesh Command

## Purpose

SZL Mesh Command is a deterministic convergence observatory for disconnected state. It lets operators inspect vector-clock relationships and simulate an arrival-order-independent last-writer-wins register merge without opening a live networking or execution path.

The service is source owned by `szl-holdings/szl-mesh`. SZL Atelier and SZL Constellation may present its metadata and evidence, but they do not become the mesh code owner.

## Runtime

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-mesh-command.txt
SOURCE_REVISION="$(git rev-parse HEAD)" uvicorn mesh_command.app:app --host 127.0.0.1 --port 7860
```

## API

| Route | Result |
|---|---|
| `GET /healthz` | process liveness |
| `GET /readyz` | static and algorithm readiness |
| `GET /api/source` | exact controlled-file hashes and source revision |
| `GET /api/topology` | explicitly declared demonstration topology |
| `POST /api/simulate/merge` | bounded deterministic convergence receipt |
| `GET /deployment.json` | runtime identity without a Hub publication claim |

## Merge contract

Each snapshot contains:

- an exact `node_id`;
- a bounded vector clock;
- at most one register per key;
- bounded JSON-compatible values;
- logical time, writer identity, and tombstone state.

For each key, the selected register is ordered by:

```text
(logical_time, writer, sha256(canonical_value), tombstone)
```

The content digest removes arrival-order dependence from otherwise equal candidates. The receipt commits both normalized input and output. This is a deterministic simulation primitive, not a claim of live radio or transport convergence.

## Authority boundary

There is no code path for:

- peer discovery;
- socket, WebSocket, radio, or message-bus connection;
- remote state transmission;
- command execution;
- shell or subprocess invocation;
- cluster mutation or deployment;
- credential handling;
- arbitrary URL retrieval;
- Hugging Face or GitHub mutation.

`DECLARED_DEMO_TOPOLOGY` is not a live network measurement. `UNAVAILABLE_NOT_ATTEMPTED` is used wherever provider or network evidence does not exist.

## Publication truth

GitHub source merge, Hub publication, Space readiness, and runtime source matching remain separate states. A publisher must verify the exact Hub commit, controlled bytes, runtime readiness, and `/deployment.json` revision before claiming exact convergence.
