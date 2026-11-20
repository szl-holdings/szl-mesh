# Yuyay Triad — Kimi × Mistral × GPT-6 coordination research

**Status: source-only, advisory, not a new trained foundation model.**

This is an original SZL evidence compiler for a three-role review: Kimi proposes,
Mistral challenges, and GPT-6 (in ChatGPT) independently adjudicates. Roles are
**declared metadata, not cryptographically authenticated model provenance**. A
single operator can forge all three matrices. The module never calls a model,
opens a provider connection, performs a tool action, trains weights, or gains
permission to merge, deploy or charge customers.

The name denotes a virtual coordination mechanism, **not a fourth model** or a
claim that proprietary Kimi/Mistral/GPT-6 weights have been merged. No external
model weights, code, datasets or proprietary text are copied into this module.

## Design after real Kimi/Mistral adversarial review

- **Kimi proposal:** bind each reviewer to an exact source Git SHA, patch
  SHA-256, frozen task plan digest, typed role and complete task population.
  Treat missing evidence, replayed submissions and conflicting verdicts as
  explicit refusal states rather than majority agreement.
- **Mistral challenge:** matching model names, roles and hashes do *not*
  authenticate a model. One operator can paraphrase the same answer across
  three aliases. No signature/independence claim is admitted until a trusted
  verifier with pre-pinned identities independently validates them.
- **Kimi revision and Mistral follow-up:** keep a useful offline advisory
  compiler, but **all outputs remain HOLD** for the source owner's independent
  admission. A missing role is displayed as HOLD while a dissent from another
  role is preserved. Never turn declared agreement into automatic tool access.
- **GPT-6 implementation:** standard-library-only deterministic compiler,
  exact-plan and full-matrix case accounting, 1–10 bounded cycle lineage,
  conservative denial of model/owner authentication and of all effectful
  authority. The output excludes raw prompts, completions, case digests and
  private sources.

This is a **real multi-model design dialogue**, but the two cloud model replies
are advisory observations. The compiler is the implementation being reviewed;
not a new runtime or independently signed ensemble.

## Protocol and limits

`src/szl_mesh/triad_research.py` exports `plan_digest` and `compile_triad`.

`plan`: exact `szl.mesh.yuyay-plan/v1` keys for repository, 40-character Git
source SHA, 64-character patch and rubric SHA-256, ordered case SHA-256 list,
cycle 1..10 and predecessor digest (required after cycle 1). `plan_digest`
uses SHA-256 with explicit schema domain separation. An owner must independently
freeze that digest **before** collecting reviews; the compiler cannot prove it.

`submissions`: zero to three `szl.mesh.yuyay-review/v1` matrices in any order,
with one role each: `KIMI_PROPOSER` (MOONSHOT), `MISTRAL_CRITIC` (MISTRAL),
`GPT6_REFEREE` (OPENAI). Each declares a model identifier, operator handle
hash, response/submission hashes, evidence time and the **exact same case set**.
Each case declares APPROVE/NO_FINDINGS, REJECT with a fixed reason, ABSTAIN,
or UNAVAILABLE. All those are *reported*, not authenticated, outcomes.

Cases: 1..256 per plan; reviewer submissions: 0..3; input canonicalized size:
512 KiB; observed timestamps: at most 15 minutes old or 5 seconds ahead of
provided trusted clock. One declared ten-cycle lineage is supported, but no
cycle is executed automatically and earlier cycle hash is **not independently
verified** by this module. No scheduled watcher or controller is created.

The compiled report contains only ordinal case totals (not case IDs), explicit
missing roles, dissent/abstention/unavailable counts, suspicious repeated
response/declared operator IDs, a domain-separated **unsigned** result digest,
and *false* values for all signing, independence, source authenticity,
execution, merge, training, deployment and production-admission authority.
**Even declared unanimous approval leaves `state=HOLD` and
`reason=OWNER_GATE_ALWAYS_REQUIRED`.**

## Distinct upstream inspirations (no code imported)

Microsoft AutoGen's group-chat and bounded-termination designs show how to
coordinate roles without unbounded model turns. LangGraph's durable interrupts
show that missing approval must pause work without losing its checkpoint.
Google's Agent2Agent task lifecycle explicitly distinguishes working,
authentication-required and input-required states. MCP security guidance warns
against treating tool outputs and state handles as automatically trusted.

SZL's original addition is the exact-case, source-pinned, **non-voting**
three-reviewer evidence boundary that retains dissent and explicitly refuses
model identity/authority claims. None of the research establishes an SZL
benchmark improvement, formal mathematical theorem, or sovereign production
readiness.

Upstream references:
- https://microsoft.github.io/autogen/stable/user-guide/agentchat-user-guide/tutorial/termination.html
- https://microsoft.github.io/autogen/stable/user-guide/core-user-guide/design-patterns/group-chat.html
- https://langchain-ai.github.io/langgraph/concepts/human_in_the_loop/
- https://docs.cloud.google.com/agent-registry/a2a-protocol
- https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization

## Offline test and admission

`python -B -m unittest discover -s tests -p 'test_triad_research.py' -v`

Tests prove *only* synthetic source behavior: 2-approve/1-dissent,
missing-role preservation, duplicate submissions, spoofed role, swapped tasks,
unbound cycle lineage, stale metadata, malformed results and pure imports.
The test fixture's `GPT-6-CHATGPT` string is a **declared synthetic role**, not
an authenticated API invocation.

Source-owner review, independent identity attestation, complete evidence,
protected CI, correct permissions and validated consumer boundaries remain
required before any future authorized integration. No live A11oy/Hatun/Killinchu
routes, Cloudflare, PyPI, GPU training, model cards, billing, branch protections
or client data were changed.
