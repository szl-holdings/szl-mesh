# hello-mesh — unsigned offline preview

**Doctrine:** v11 LOCKED `749/14/163` · Kernel commit `c7c0ba17` · SLSA L1

`hello_mesh.py` constructs a simulated state-transition statement and an unsigned DSSE-shaped envelope. It makes no network calls, uses no credentials and writes no artifacts.
It does not enroll a node, write to a live CRDT, issue a valid receipt, query a Receipt Gate, publish telemetry or authorize a command.

## Run the preview

Python 3.10 or later and the standard library are sufficient:

```bash
cd examples/hello-mesh
python3 hello_mesh.py
```

The envelope has `signatures: []`. The descriptive node ID is explicitly unenrolled; it is not derived from a public key.
The printed event uses the existing `RECEIPT_MISSING`, `OBSERVED` and `CORROBORATION_STATUS_UNSPECIFIED` enum names.
Its existing `labels` map records `simulated: "true"`, `published: "false"`, `receipt_evaluated: "false"`,
`corroboration_evaluated: "false"` and `latency_status: "UNAVAILABLE"`. The unmeasured `latency_ms` integer is omitted.
These are explicit example labels, not observations returned by a running gateway. An unsigned envelope is not a valid receipt,
and the script does not infer authorization from a hypothetical signature.

For the implemented local runtime and real ECDSA-P256 receipt primitives, see the [repository README](../../README.md),
[`szl_mesh.receipts`](../../src/szl_mesh/receipts.py) and the [runtime demo](../../src/szl_mesh/demo.py).
A valid signature alone does not establish enrollment, policy admission, corroboration or deployed readiness; use the appropriate runtime gates and retained evidence.

## Files and limits

- `hello_mesh.py`: executable, keyless offline preview.
- `enroll.py`: legacy enrollment sketch. Its gRPC call remains commented out and it cannot enroll a node or obtain a certificate. It is not needed for the preview.
- `requirements.txt`: dependencies retained for future enrollment/transport work; they are not needed to run `hello_mesh.py`.

There is no `verify_authorized.py` or `watch_sentra.py` in this example. No live AUTHORIZED-track or Sentra verification procedure is implemented here.
Do not provide formation keys or generate signing credentials merely to run this unsigned preview.

## Regression checks

From the repository root:

```bash
python3 -m unittest discover -s tests -p test_hello_mesh_example.py -v
```

The checks require an empty signature list, preserved doctrine/payload data, an OBSERVED and unpublished simulated event, no fabricated latency, and a CLI run without credentials or file writes.
The `hello-mesh Smoke Test` CI job executes these checks.

Example repair provenance: OpenAI Codex, implementing the owner's repository audit request. No independent review or live service qualification is claimed.
