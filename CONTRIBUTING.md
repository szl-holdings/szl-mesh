# Contributing to szl-mesh

Thank you for contributing to the SZL mesh CRDT layer.

## Prerequisites

- Node 20+ and pnpm 8+
- Familiarity with Automerge CRDTs and DSSE signing
- Read [`SZL_FLEET_OVERLAY_DESIGN.md`](https://github.com/szl-holdings/szl-fleet-overlay/blob/main/SZL_FLEET_OVERLAY_DESIGN.md) for mesh architecture context

## DCO Sign-off (Required)

Every commit requires a Developer Certificate of Origin sign-off:

```bash
git commit -s -m "your message"
# Adds: Signed-off-by: Your Name <you@example.com>
```

Commits without a DCO trailer will be rejected by CI.

**Remediation if a commit lands without a sign-off:** the DCO gate checks the
commits in the current push (`HEAD~1..HEAD` on a push, the PR range on a PR), so
an accidentally-unsigned commit on `main` is cleared by the **next signed-off
commit** — no force-push or history rewrite is needed. Bot authors (Dependabot,
`github-actions`, `[bot]`) are exempt by standard DCO practice; human and agent
commits are always enforced.

## Development workflow

```bash
pnpm install
pnpm test
pnpm build
```

## Doctrine constraints (NEVER violate)

- Doctrine v11 LOCKED 749/14/163 at kernel commit `c7c0ba17` — do NOT bump
- Λ = Conjecture 1 (NOT a closed theorem)
- SLSA L1 honest — do not claim L2 or L3
- Section 889 = exactly 5 vendors (Huawei, ZTE, Hytera, Hikvision, Dahua)
- NO Iron Bank, NO FedRAMP, NO CMMC, NO SWFT, NO Mission Owner references

## Code style

- TypeScript for all mesh logic; Python for backend services
- All CRDT state transitions must emit a DSSE receipt (see `spec/01-dsse-receipts.md`)
- No `COPY . .` in Dockerfiles — per-file COPY only
- Tag every AI-generated content with provenance

## Security

See [SECURITY.md](SECURITY.md) for vulnerability disclosure.

## License

Apache-2.0. All contributions accepted under the same license.

---

Signed-off-by: Yachay <yachay@szlholdings.ai>  
Co-Authored-By: Perplexity Computer Agent <agent@perplexity.ai>
