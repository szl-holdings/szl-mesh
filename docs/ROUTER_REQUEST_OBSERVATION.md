# Source-only Router → Mesh request observation

`szl_mesh.agentic_fabric.observe_router_request()` compares a caller-provided
Router receipt body with caller-provided `model` and `messages`, using the
same sorted, compact, finite JSON SHA-256 used by `szl_router.receipts.request_digest`.

It rejects non-JSON/non-finite values and injected authority fields and
checks explicit 40-hex Router source SHA claims. Matching inputs yield
`OBSERVED_ONLY`; mismatches yield `HOLD`. It never returns `AUTHORIZED`,
never executes a tool or SQL write, never reaches a provider and never
claims a trusted signature, current source, served model or production readiness.

This is an **advisory evidence bridge**, not a new Chronicle database,
distributed consensus, or runtime release admission. Mesh Chronicle remains
the owner of durable node-local storage and replay. Any production use still
requires independent source readback, signer enrollment/revocation, tenant
authorization, crash/restore proofs and operator-governed release admission
(see szl-mesh issue #93).

Focused test: `python -m pytest tests/test_router_request_observation.py`.
