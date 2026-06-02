# Security Policy

**SZL-MESH** · Doctrine v11 LOCKED `749/14/163` · SLSA L1

---

## Honest Security Posture

SZL-MESH is an **early-stage protocol skeleton**. The following is our honest, unvarnished security posture. We do not make claims we cannot substantiate.

### What We Have

| Property | Status | Notes |
|----------|--------|-------|
| SLSA Level | **L1** | Provenance assertions generated at build time. NOT L3. |
| Ed25519 signatures | Design-complete | Node identity and CRDT op signing — not yet implemented |
| DSSE receipt spec | Design-complete | See `spec/01-dsse-receipts.md` — not yet implemented |
| DCO sign-off | Active | Every commit carries `Signed-off-by` trailer |
| Transport encryption | TLS 1.3 via QUIC | Inherited from peat / Iroh QUIC |

### What We Do NOT Have

- **No public cryptographic audit** — The DSSE receipt scheme and Byzantine corroboration protocol have not been reviewed by an independent cryptographer or security firm. Do not rely on these for production security decisions.
- **Not FIPS 140-3 validated** — Ed25519 is FIPS 186-5 approved, but the implementation (once built) will not carry FIPS 140-3 module validation.
- **Not Iron Bank** — We make no Iron Bank claim and do not pursue it.
- **Not FedRAMP** — We make no FedRAMP claim.
- **Not CMMC certified** — We make no CMMC claim.
- **Not SWFT** — We make no SWFT claim.
- **No OCSP infrastructure** — By design; CRDT-native revocation (see `spec/06-crdt-revocation.md`) is the air-gap-compatible alternative.

### Section 889 Compliance

SZL-MESH enrolls only nodes that do not present hardware attestations from the following Section 889 covered vendors (exactly 5):

1. Huawei Technologies Co., Ltd.
2. ZTE Corporation
3. Hytera Communications Corporation Limited
4. Hangzhou Hikvision Digital Technology Co., Ltd.
5. Dahua Technology Co., Ltd.

Hardware attestation checks are best-effort during enrollment; physical deployment-layer enforcement is the primary control.

---

## Responsible Disclosure

SZL-MESH is a private-source protocol. If you discover a security vulnerability:

1. **Do not open a public GitHub issue.**
2. Email `security@szlholdings.ai` with:
   - Subject: `[SZL-MESH] Security Disclosure`
   - Description of the vulnerability
   - Steps to reproduce (if applicable)
   - Affected component (receipt gate, enrollment ceremony, corroboration, etc.)
3. We will acknowledge within 5 business days and respond with a remediation timeline within 14 business days.

---

## Threat Model Summary

| Threat | Mitigation | Residual Risk |
|--------|------------|---------------|
| Byzantine state injection | Receipt Gate (B1) + k-of-n corroboration (B3) + write quotas (B2) | Byzantine noise in OBSERVED track |
| Unauthorized enrollment | Formation key HMAC + doctrine version check | Physical formation key compromise |
| Certificate replay | Timestamp window (5 min) + per-NodeID uniqueness | Clock manipulation |
| CA impersonation | Root CA offline; Formation CA in Zarf component | Physical Root CA compromise |
| Certificate replay post-revocation | CRDT grow-only revocation set | Revocation propagation delay during partition |
| Formation key compromise | Per-mission rotation | Simultaneous formation key + CA key compromise |

See `spec/04-byzantine-corroboration.md` and the BYZANTINE_HANDLING design document for full analysis.

---

## Formal Properties (Design-Time)

- **Safety:** Byzantine nodes cannot produce AUTHORIZED receipts without Formation CA private key.
- **Corroboration safety:** For document types with k-of-n policy, if `k > f` Byzantine nodes in cell, corroboration correctly classifies state.
- **CRDT convergence:** Automerge merge is deterministic regardless of Byzantine input.
- **AP liveness:** Every read/write at any honest node is served locally; never blocks on partition.

These are design-time properties. **Formal verification is pending.** Λ = Conjecture 1 (NOT theorem).

---

*Doctrine v11 LOCKED 749/14/163 · Kernel commit c7c0ba17 · SLSA L1 honest*
