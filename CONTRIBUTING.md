# Contributing to szl-mesh

Thank you for contributing to the SZL mesh CRDT layer.

## Prerequisites

- Node 20+ and pnpm 8+
- Familiarity with Automerge CRDTs and DSSE signing
- Read [`SZL_FLEET_OVERLAY_DESIGN.md`](https://github.com/szl-holdings/szl-fleet-overlay/blob/main/SZL_FLEET_OVERLAY_DESIGN.md) for mesh architecture context

## Solo-maintainer provenance policy

Developer Certificate of Origin trailers are **not required**. SZL-MESH is operated as a solo-maintainer repository, so redundant `Signed-off-by:` enforcement has been removed from CI.

Every change still follows the auditable repository path:

1. Create a focused branch.
2. Open a pull request against `main`.
3. Pass the repository's tests, security analysis, doctrine, dependency, and container gates.
4. Resolve review findings and merge through GitHub so the author, exact head, checks, and resulting commit remain recorded.

By submitting a contribution, the contributor confirms that they have the right to provide it under this repository's Apache-2.0 license. A `git commit -s` trailer is optional and is not used as a merge gate.

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

Apache-2.0. All contributions are accepted under the same license.
