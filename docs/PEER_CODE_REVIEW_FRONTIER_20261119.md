# SZL Kimi × Mistral peer-code-review advisory

**Source owner:** `szl-holdings/szl-mesh`  
**Module:** `src/szl_mesh/peer_code_review.py`  
**State:** offline, source-only, **not deployed or wired to production**.

## Research basis and SZL adaptation

- [Adversarial Review: Structured Disagreement for Grounded Agentic Code Review](https://arxiv.org/abs/2608.18167) studies a coding agent, reviewer and critic. Its reported false-consensus hazard motivates making a conflicting decision visible rather than voting it away.
- [Mistral Devstral](https://mistral.ai/news/devstral/) and [OpenHands](https://github.com/All-Hands-AI/OpenHands) provide the repository-level agent scaffolding and test-grounded coding context, not security authority.
- [SWE-bench Verified](https://www.swebench.com/) motivates evaluated executable patches rather than unverified reviewer agreement.
- Existing [SZL Mesh agentic fabric](https://github.com/szl-holdings/szl-mesh) already has eight source-owner proposals and a separate `quorum.py` using real signature verification. This module **does not create another quorum or copy external code**.

The original SZL adaptation is a **two-model dissent latch**: explicit proposal/critic roles, named Moonshot/Mistral provider families, exact source and patch digests, fixed-labeled refusal reasons, freshness windows, and a separate test-result veto. It is small, transparent and source-only; it neither runs code nor asserts reviewer independence.

## How to read the certificate

The compiler takes one bounded JSON-compatible packet with exactly the named
`schema`, `repository`, `source_sha`, `patch_sha256`, `reviewers`, `tests`
fields. It accepts exactly two reviewer records:

- `PROPOSER` / `MOONSHOT` — an observed review attributed to the Kimi model family.
- `CRITIC` / `MISTRAL` — a separately observed review attributed to a Mistral model.
- Both records carry the same 40-hex source revision and 64-hex proposed patch digest, a distinct response digest, timestamp, verdict `APPROVE` / `REJECT` / `ABSTAIN`, and **only fixed reason codes**.
- `tests` carries an independently *reported* `PASS` / `FAIL` / `UNAVAILABLE`, its exact source+patch identity, timestamp, counts and structural evidence digest.

Swapping the Moonshot proposer and Mistral critic labels is also an explicit HOLD.

A reported test failure, missing test, dissent, abstention, duplicated reviewer family,
source drift, patch mismatch or stale evidence yields `HOLD`. A correctly shaped
all-approve / PASS packet yields **only** `READY_FOR_OWNER_REVIEW`.
The module does **not** verify the models, their independence, test execution, source
checkout, signer keys, or the factual truth of reported evidence. Never turn this
advisory into an autonomous GitHub approval or machine-authorized deployment.

The result's domain-separated SHA-256 is an **unsigned structural checksum** and
can be recomputed by anyone; it is not a signature or identity proof.
`verify_peer_review` checks structural consistency and the permanent
`merge_authorized=false`, `execution_authorized=false` and
`deployment_authorized=false` denial flags. A forged packet can still be built;
only external protected-main CI, independently verified source/image identity and
the appropriate real signature/protection machinery can admit a release.

## Model and privacy boundaries

The local workstation has `ministral-3:3b` under Ollama (Mistral-family
local quantized model) and `kimi-k3.1-pro:cloud` (cloud-hosted Kimi through
Ollama). **Kimi prompts leave the workstation**. Only public source excerpts
should be submitted; neither model receives Windows secrets, Snowflake or
Cloudflare tokens, customer data, private chat content or automatic tool authority.
Two brands are not two independent security principals.

The operational premise differs from source quality: A11oy Second Brain
memory can be built while its hosted `khipu:latest` inference identity is
unavailable. This module **cannot** configure an authenticated GPU gateway,
restart services, mint model weight attestations or make the estate operational.

## Joint model review and independent verification

The initial real Kimi and local Ministral review both returned **REJECT**.
Kimi identified a structural replay gap: a self-rehashed record could
retain an inconsistent `READY_FOR_OWNER_REVIEW` state after tests were
changed to FAIL. The decoder now checks the exact output shape and the
internal relation between reviewer decisions, declared test counts, reasons
and advisory status; duplicate exact model IDs are also held.

Mistral raised model URL injection and SHA whitespace concerns. Direct
source inspection showed that URL/traversal strings were already explicitly
rejected, and Python `fullmatch` plus lower-hex patterns reject whitespace.
Adversarial tests now exercise both cases instead of treating an LLM claim
as a demonstrated vulnerability. A correctly shaped *forged* set of model
reviews can still be constructed because review-origin authentication is
intentionally absent; the certificate therefore never authorizes a merge.

## Checks and replay

```powershell
python -B -m unittest discover -s tests -p test_peer_code_review.py -v
python -B -m unittest discover -s tests -p test_agentic_fabric.py -q
```

Fixtures cover dissent, failing tests, missing tests, wrong source or patch,
duplicate model family, duplicated role, repeated response digest, clock skew,
unknown reason codes, unsafe model URLs, prompt-injection-shaped fields, and
forged authority rehashing. Source and tests should be run from the exact PR
head on Linux CI before any merge.

## Frontier extension (not implemented)

Once independent public source/build/test verification is available, add a
separate, externally authorized reviewer-evidence witness referencing exact
GitHub job IDs and immutable model metadata. **Do not** allow this module
to self-certify independent tests, grant merge permissions or dispatch
paid inference. Record review disagreement and counterexamples before
accepting new benchmark claims.
