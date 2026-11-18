# Proof-carrying Python organ junction (source candidate)

**Stage: SOURCE-ONLY / PROPOSAL-ONLY.** Owner: `szl-holdings/szl-mesh`, building on [issue #95](https://github.com/szl-holdings/szl-mesh/issues/95). The Python implementation is `src/szl_mesh/agentic_fabric.py` with stdlib-only `tests/test_agentic_fabric.py`. It does **not** deploy any service, sign authority, call tools, read credentials, train, mutate datasets, write SQL, or authorize third-party effects. An all-green synthetic packet still yields only `PROPOSAL_READY_FOR_OWNER_REVIEW`.

## Exact canonical owners (at implementation review)

| Organ / contract | Owned source | Role in Python junction |
|---|---|---|
| Second Brain | [`szl-second-brain`](https://github.com/szl-holdings/szl-second-brain) | Public handle + digest references; do not import private 9,464-node graph or hydrate contents. Review candidates are not training data or effects. |
| Living Anatomy | [`anatomy`](https://github.com/szl-holdings/anatomy) | Five named organ observations (`YUYAY`, `YAWAR`, `YACHAY`, `OTEL`, `KHIPU`) and zero fake healthy defaults; atlas is visualization, not authority. |
| Muyu / ORO | [`szl-ouroboros`](https://github.com/szl-holdings/szl-ouroboros) | Fixed maximum 12 source-declared steps, explicit termination; never silently self-modifies, calls a model, or trains. |
| Canonical formulas | [`szl-formulas`](https://github.com/szl-holdings/szl-formulas) | Validate 21 exact formula identifiers only, as **proposals**. No imported `trust_remote_code`, weights, GPU or evaluation claim. |
| Falsifiable invariants | [`szl-invariants`](https://github.com/szl-holdings/szl-invariants) | Require all eight source-declared check names. `HOLDS`, `VIOLATED`, `KEY_ROTATED`, `NO_DATA`, `UNAVAILABLE` remain separate; all are **supplied**, not re-executed. |
| Hatun | [`hatun-mcp`](https://github.com/szl-holdings/hatun-mcp) | Fixed small catalog of named *read-only proposal* tools, no MCP invocation; owner verifies actual tool and signing readiness later. |
| Formal corpus | [`lutar-lean`](https://github.com/szl-holdings/lutar-lean) | Exactly eight locked historical F identifiers; no claim that these map to the 21 formula API functions. Λ uniqueness is **Conjecture 1**, not a theorem. Python **does not replace Lean 4** verification. |
| Organ-integrity kernel | [`szl-khipu`](https://github.com/szl-holdings/szl-khipu) | Exact source reference; kernel must be called and independently witnessed by its own owner before any authorization. |

`SOURCE_PINS` contains full 40-hex Git revisions observed from those owners. They are immutable GitHub source references **only**, not a Hub deployment, signed artifact, or proof of contemporaneous runtime. The code rejects changed/revoked/unknown sources and unbounded inputs. A caller-supplied SHA and digest remain **untrusted claims**; even if every claim agrees with the pin, the output says `source_witness_independently_authenticated=false`.

## Typed proposal boundary

Input: versioned dict with an opaque tenant/event, eight canonical source metadata records, 0–16 **digest-only reviewed public memory handles**, five organ statuses, 0–4 known formula names, all eight invariant statuses, one fixed Hatun read-only tool name, bounded Muyu steps, locked F labels and optional fixed-node evidence DAG edges. No free-form prompts, URLs, model outputs, signing keys, permissions, private graph rows, tool arguments or arbitrary provider identities are accepted.

Output: deterministic, JSON-canonical **unsigned SHA-256** record containing evidence denominators and `HOLD`/`PROPOSAL_READY_FOR_OWNER_REVIEW` only, plus explicit `agent_actions_executed=0`, `authorized_effects=0`, `receipt_signed=false`, `training_dispatched=false`, `production_ready=false`. `verify_advisory()` recomputes unsigned bytes and rigid status flags; **it cannot authenticate an origin, prove effect integrity, or elevate an action**.

A hard error is a parse/contract refusal; a result `HOLD` is a complete source-only evaluation that retained explicit reasons (stale or missing source, wrong tenant, unreviewed memory, a down organ, unqualified invariants, forbidden tool, unclosed loop, or graph cycle). Both outcomes prohibit provider operations.

The optional directed edges use a finite Kahn acyclicity check inspired by the **shape** of locked F4; this check is software validation, **not** a Lean proof of arbitrary runtime behavior. A high Λ is never included as authority. The exact `F1/F4/F7/F11/F12/F18/F19/F22` set is orthogonal to the 21 named Python formula functions.

## Reproduction

```bash
python -B -m unittest discover -s tests -p test_agentic_fabric.py -v
```

The 29 offline tests include corrupted unsigned records, attacker-rehashed authorization, every source SHA drift, stale evidence, cross-tenant taint, private memory text rejection, incomplete/revoked invariants, five-organ failure, unbounded Ouroboros loop, unauthorized Hatun tools, false Lean theorem, unknown formulas, source injection, and graph cycles. `test-chronicle` CI must run them alongside existing Mesh Chronicle checks in both Python 3.11 and 3.12; no existing test or protection is disabled.

## Next real integration gates (NOT executed in this PR)

1. Obtain **real** Second Brain `/api/v1/query` digest-only handles, keep any private hydration inside that repository's trusted controller, and verify exact deployed source independently.
2. Read the Anatomy and Khipu organ kernel's actual `/readyz`/integrity contracts with timestamps; never substitute the visual atlas's `RUNNING` stage for five healthy organs.
3. Bind the **existing** Muyu loop receipt, formula-kernel source/release revision and invariants export through approved, independently signed evidence APIs. Do not load quarantined `joblib` or unreviewed Kernel Hub code.
4. Use Hatun's existing authenticated, policy-gated MCP transport and signed receipt verifier for one **approved** reversible task. A model's proposal or this unsigned packet can never grant `tools/call` permission.
5. Persist authoritative intent/effect dedupe in the approved transactional outbox and external idempotency ledger; Mesh Chronicle remains **OBSERVED** unless independently revalidated. SZL Lake remains the evidence owner. Add crash, concurrency, replay, tenant isolation, revocation, stale evidence and external effect-readback tests.
6. Qualify protected GitHub checks, immutable builds and deployment windows; separately verify Hugging Face runtime, A11oy product, Cloudflare paid settlement and PyPI OIDC. The current BETTERWITHAGE storage and dispatch-owner **HOLD** is unchanged.

No competing database, backend, frontend, signing key, model-serving process or authority owner is created by this Python-only source candidate.