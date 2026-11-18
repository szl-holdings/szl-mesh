# SPDX-License-Identifier: Apache-2.0
# © 2026 Lutar, Stephen P. — SZL Holdings · ORCID 0009-0001-0110-4173
#
# DCO:
#   Signed-off-by: Yachay <yachay@szlholdings.ai>
#   Co-Authored-By: Perplexity Computer Agent <agent@perplexity.ai>
"""
szl_mesh.quorum — wire the REAL khipu-consensus BFT engine into szl-mesh.

This module does NOT reimplement consensus or cryptography. It IMPORTS the
reference engine (``khipu_consensus``) and uses its real ECDSA-P256-SHA256
DSSE signing/verification primitives:

    - ``sign_verdict``     : produce one organ's DSSE-signed verdict (wire shape)
    - ``verify_verdict``   : verify one organ's ECDSA-P256 sig over the PAE
    - ``tally``            : count distinct valid ``allow`` sigs over the SAME
                             action hash; apply the n=4, threshold=3 BFT rule
    - ``OrganVerdict``     : the per-witness wire record
    - ``canonical_json`` / ``pae`` : the exact bytes signed

What this module adds (Mesh Dev 2 lane):

1. ``propose_action(action, ...)`` — take a mesh canonical action (a CRDT state
   transition Dev 1's runtime wants to mark canonical), derive its action hash,
   have the 4 organ witnesses sign that hash with their own cosign keys, and
   collect a QUORUM CERTIFICATE: the >=3-of-4 ``allow`` signatures over the same
   hash. ``canonical`` is True iff >= threshold distinct valid allow-sigs.

2. ``verify_quorum(qc, pubkeys)`` — re-check EVERY witness ECDSA-P256 signature
   over the PAE via the real engine and confirm >= threshold distinct valid
   ``allow`` sigs over the SAME action hash => ``canonical: True``. A bad or
   missing 4th witness still yields canonical (3-of-4); two bad witnesses do
   NOT (2-of-4 < threshold).

3. ``CorroborationLedger`` — the spec/04 SOFT-SAFETY AP
   annotation that runs ALONGSIDE the AP CRDT and NEVER blocks writes. This is
   the real, shipped Byzantine-corroboration model. It is **soft-safety AP, NOT
   blocking BFT consensus**.

DOCTRINE v11 honesty (NEVER violate):
    - The 3-of-4 Khipu quorum is REAL (per-witness ECDSA-P256 DSSE).
    - Khipu BFT *unconditional* safety is **Conjecture 2 — NOT a theorem, never
      claimed proven**. The soft-safety / AP corroboration behaviour is the real
      shipped model.
    - Never fabricate a quorum. Never commit a key.
"""
from __future__ import annotations

import hashlib
import re
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from typing import Iterable, Optional

# ── Import the REAL engine. Do not reimplement. ──────────────────────────────
# Prefer the installed `khipu-consensus` package (source of truth). Fall back to
# the READ-ONLY byte-identical vendored mirror in ._vendor so tests run
# hermetically. Either way these are the engine's real ECDSA-P256 DSSE prims.
try:  # pragma: no cover - import resolution
    from khipu_consensus import (  # noqa: F401  (re-exported for callers)
        ORGAN_VERDICT_PAYLOAD_TYPE,
        OrganVerdict,
        ConsensusResult,
        canonical_json,
        pae,
        sign_verdict,
        verify_verdict,
        tally,
    )
except ImportError:  # pragma: no cover
    import os as _os
    import sys as _sys

    _sys.path.insert(0, _os.path.join(_os.path.dirname(__file__), "_vendor"))
    from khipu_consensus import (  # noqa: F401
        ORGAN_VERDICT_PAYLOAD_TYPE,
        OrganVerdict,
        ConsensusResult,
        canonical_json,
        pae,
        sign_verdict,
        verify_verdict,
        tally,
    )

# ── Locked doctrine constants (informational; mirror hello_mesh) ─────────────
DOCTRINE_VERSION = "749/14/163"
KERNEL_COMMIT = "c7c0ba17"

# Default n=4 / threshold=3 Khipu quorum (tolerates f = n - threshold = 1).
DEFAULT_N = 4
DEFAULT_THRESHOLD = 3

# The four organ witnesses (internal package aliases; never user-visible).
DEFAULT_ORGANS = ("sentra", "amaru", "a11oy", "killinchu")


# ─────────────────────────────────────────────────────────────────────────────
# Action hashing
# ─────────────────────────────────────────────────────────────────────────────
def action_hash(action) -> str:
    """Derive the canonical action hash for a mesh action.

    A mesh "canonical action" is a CRDT state transition (see Dev 1's runtime /
    hello_mesh ``StateTransitionStatement``). We accept:

      * a 64-hex string  -> already a hash (e.g. Dev 1's ``change_hash``); used as-is
      * a dict           -> hashed deterministically via the engine's
                            ``canonical_json`` (sorted keys, compact) + SHA-256
      * bytes/str        -> SHA-256 of the raw bytes

    Using the engine's ``canonical_json`` guarantees the SAME action produces the
    SAME hash across Python/Go/TS and matches what every witness signs.
    """
    if isinstance(action, str):
        s = action.strip().lower()
        if len(s) == 64 and all(c in "0123456789abcdef" for c in s):
            return s
        return hashlib.sha256(action.encode("utf-8")).hexdigest()
    if isinstance(action, (bytes, bytearray)):
        return hashlib.sha256(bytes(action)).hexdigest()
    if isinstance(action, dict):
        return hashlib.sha256(canonical_json(action)).hexdigest()
    raise TypeError(f"unsupported action type: {type(action).__name__}")


# ─────────────────────────────────────────────────────────────────────────────
# Quorum certificate
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class QuorumCertificate:
    """A 3-of-4 Khipu quorum certificate over a single mesh action hash.

    ``witnesses`` is the list of per-organ DSSE records actually collected
    (organ, keyid, sig, payload, ...). ``canonical`` is True iff the tally of
    distinct valid ``allow`` signatures over ``action_hash`` >= ``threshold``.
    """
    action_hash: str
    witnesses: list
    threshold: int = DEFAULT_THRESHOLD
    n: int = DEFAULT_N
    canonical: bool = False
    consensus_count: int = 0

    def to_dict(self) -> dict:
        return {
            "schema": "szl.mesh.quorum_certificate/v1",
            "action_hash": self.action_hash,
            "threshold": self.threshold,
            "n": self.n,
            "canonical": self.canonical,
            "consensus_count": self.consensus_count,
            "khipu_consensus": f"{self.consensus_count}-of-{self.n}",
            "witnesses": [
                {
                    "organ": w.get("organ"),
                    "keyid": w.get("keyid"),
                    "sig": w.get("signature") or w.get("sig"),
                    "payloadType": w.get("payloadType", ORGAN_VERDICT_PAYLOAD_TYPE),
                    "payload": w.get("payload"),
                    "verdict": w.get("verdict", "allow"),
                }
                for w in self.witnesses
                if w is not None
            ],
            # Honest labeling — never claim unconditional BFT.
            "safety_model": f"khipu-{self.threshold}of{self.n}-quorum (real ECDSA-P256 DSSE); "
            "unconditional BFT safety = Conjecture 2 (NOT proven)",
            "doctrine_version": DOCTRINE_VERSION,
            "kernel_commit": KERNEL_COMMIT,
        }


def _validate_quorum_policy(threshold: int, n: int) -> None:
    if type(threshold) is not int or type(n) is not int or not 1 <= threshold <= n:
        raise ValueError("quorum policy requires integer 1 <= threshold <= n")


def propose_action(
    action,
    witness_keys: dict,
    organs: Iterable[str] = DEFAULT_ORGANS,
    threshold: int = DEFAULT_THRESHOLD,
    n: int = DEFAULT_N,
    verdicts: Optional[dict] = None,
    reason: str = "ok",
    lean_sha: str = "",
    ts: str = "",
) -> QuorumCertificate:
    """Run a mesh canonical action through khipu-consensus and collect a QC.

    Each of the (up to ``n``) organ witnesses signs the SAME action hash with its
    own ECDSA-P256 cosign key via the REAL engine's ``sign_verdict``. We then
    tally with the real engine to set ``canonical``.

    Parameters
    ----------
    action        : mesh action (dict / hex change_hash / bytes) — see ``action_hash``.
    witness_keys  : {organ: private_key_pem}. A witness with no key here is treated
                    as missing/abstaining (contributes no signature) — this models a
                    dropped 4th witness; 3-of-4 still yields canonical.
    verdicts      : optional {organ: "allow"|"block"} to model Byzantine/dissent
                    witnesses. Default: every present witness signs "allow".

    A QC is NEVER fabricated: every signature in the returned certificate is a real
    ECDSA-P256-SHA256 signature produced by the witness's own private key.
    """
    _validate_quorum_policy(threshold, n)
    ah = action_hash(action)
    verdicts = verdicts or {}
    witnesses = []
    pubkeys = {}

    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key,
        Encoding,
        PublicFormat,
    )

    for organ in organs:
        pem = witness_keys.get(organ)
        if not pem:
            # Missing witness (e.g. dropped/offline). No signature collected.
            continue
        verdict = verdicts.get(organ, "allow")
        rec = sign_verdict(
            organ=organ,
            action_hash=ah,
            verdict=verdict,
            private_key_pem=pem,
            reason=reason if verdict == "allow" else (verdicts.get(organ + ":reason", "dissent")),
            lean_sha=lean_sha,
            ts=ts,
        )
        witnesses.append(rec)
        # Derive the matching public PEM so the QC is self-verifiable.
        priv = load_pem_private_key(pem.encode(), password=None)
        pub_pem = priv.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode()
        pubkeys[organ] = pub_pem

    result: ConsensusResult = tally(ah, witnesses, pubkeys, threshold=threshold, n=n)
    return QuorumCertificate(
        action_hash=ah,
        witnesses=witnesses,
        threshold=threshold,
        n=n,
        canonical=(result.decision == "canonical"),
        consensus_count=result.consensus_count,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Verification (independent re-check)
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class QuorumVerification:
    action_hash: str
    threshold: int
    n: int
    consensus_count: int
    canonical: bool
    checks: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "action_hash": self.action_hash,
            "threshold": self.threshold,
            "n": self.n,
            "consensus_count": self.consensus_count,
            "khipu_consensus": f"{self.consensus_count}-of-{self.n}",
            "canonical": self.canonical,
            "checks": [
                {
                    "organ": c.organ,
                    "keyid": c.keyid,
                    "valid_sig": c.valid,
                    "verdict": c.verdict,
                    "action_hash_match": c.action_hash_match,
                    "counts": c.counts,
                    "reason": c.reason,
                }
                for c in self.checks
            ],
            "safety_model": f"khipu-{self.threshold}of{self.n}-quorum (real ECDSA-P256 DSSE); "
            "unconditional BFT safety = Conjecture 2 (NOT proven)",
        }


def verify_quorum(
    qc, pubkeys: dict, *, threshold: int = DEFAULT_THRESHOLD, n: int = DEFAULT_N,
) -> QuorumVerification:
    """Independently re-verify a quorum certificate using the REAL engine.

    Re-checks EVERY witness ECDSA-P256 signature over the DSSE PAE (via the
    engine's ``tally`` -> ``verify_verdict``) and confirms that >= ``threshold``
    DISTINCT organs each contributed a valid ``allow`` signature over the SAME
    ``action_hash``. Forged sigs, wrong-hash sigs, and ``block`` verdicts never
    count.

    Quorum is counted by DISTINCT witness organ, not by raw signature, which is
    robust in BOTH directions against a peer that submits duplicate organ
    entries over the wire:

      * inflation — the same organ's valid signature replayed twice cannot
        count twice, so a Byzantine peer holding one key cannot manufacture a
        quorum;
      * deflation — a forged / non-counting duplicate of an organ cannot cancel
        that organ's genuine counting signature, so an adversary cannot demote a
        legitimate 3-of-4 quorum by front-running junk duplicate entries.

    Malformed input is FAIL-CLOSED: a certificate that is not a
    :class:`QuorumCertificate` / dict, or that lacks a usable string
    ``action_hash``, returns ``canonical: False`` with ``consensus_count: 0`` —
    never an exception and never a fabricated quorum. Witness entries that are
    not dicts are ignored.

    ``qc`` may be a :class:`QuorumCertificate` or its ``to_dict()`` form.
    The caller owns the trusted ``threshold`` and ``n`` policy (3-of-4 by
    default). Certificate policy fields must match it exactly; signatures bind
    the action, not these fields. Custom policies require explicit keyword
    arguments. Invalid caller policies raise ValueError.
    """
    _validate_quorum_policy(threshold, n)
    if isinstance(qc, QuorumCertificate):
        qcd = qc.to_dict()
    elif isinstance(qc, dict):
        qcd = qc
    else:
        # Not a certificate at all — never fabricate a quorum; fail closed.
        return QuorumVerification(
            action_hash="", threshold=threshold, n=n,
            consensus_count=0, canonical=False, checks=[],
        )

    declared_threshold = qcd.get("threshold", threshold)
    declared_n = qcd.get("n", n)
    if (type(declared_threshold) is not int or type(declared_n) is not int
            or declared_threshold != threshold or declared_n != n):
        return QuorumVerification(
            action_hash="", threshold=threshold, n=n,
            consensus_count=0, canonical=False, checks=[],
        )

    ah = qcd.get("action_hash")
    if not isinstance(ah, str) or not ah:
        # No action hash to bind witnesses to — cannot verify; fail closed.
        return QuorumVerification(
            action_hash="", threshold=threshold, n=n,
            consensus_count=0, canonical=False, checks=[],
        )

    raw = qcd.get("witnesses")
    if not isinstance(raw, list):
        raw = []

    # Present EVERY witness record to the REAL engine (including any duplicate
    # organs). We intentionally do NOT drop entries before verification: doing so
    # is exactly what would let a forged duplicate deflate an honest organ. The
    # engine verifies each signature independently; we reduce to distinct
    # counting organs afterwards.
    verdicts = []
    for w in raw:
        if not isinstance(w, dict):
            continue
        verdicts.append(
            {
                "organ": w.get("organ"),
                "keyid": w.get("keyid"),
                "payloadType": w.get("payloadType", ORGAN_VERDICT_PAYLOAD_TYPE),
                "payload": w.get("payload"),
                "signature": w.get("sig") or w.get("signature"),
                "verdict": w.get("verdict", "allow"),
            }
        )

    result: ConsensusResult = tally(ah, verdicts, pubkeys, threshold=threshold, n=n)

    # Count DISTINCT organs that contributed a valid, counting (allow +
    # same-hash) signature. Distinct-organ counting is what makes verification
    # robust against both the inflation and deflation duplicate-organ cases.
    counting_organs = {
        c.organ for c in result.checks if c.counts and c.organ is not None
    }
    consensus_count = len(counting_organs)

    return QuorumVerification(
        action_hash=ah,
        threshold=threshold,
        n=n,
        consensus_count=consensus_count,
        canonical=consensus_count >= threshold,
        checks=result.checks,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Spec 04 — Byzantine corroboration (SOFT-SAFETY AP, NOT blocking BFT consensus)
# ─────────────────────────────────────────────────────────────────────────────
#
# This is a local claimed-reporter annotation, NOT authenticated peer voting.
# ANNOTATION that runs ALONGSIDE the AP CRDT and NEVER blocks writes. Writes are
# always immediate (AP); corroboration is eventual / best-effort.
#
# It is explicitly NOT BFT consensus and NOT the cryptographic 3-of-4 quorum
# above. Khipu BFT *unconditional* safety remains Conjecture 2 (never proven).
#
# Soft-safety property (spec/04 §4.1): with policy threshold k and f Byzantine
# nodes, if k > f then Byzantine nodes alone cannot drive a value to CORROBORATED
# that no honest node observed. Weaker than PBFT; preserves full AP availability.

# Default per-transition_class corroboration policies (spec/04 §3.2).
DEFAULT_CORROBORATION_POLICIES = {
    "COMMAND": {"k": 2, "window_seconds": 30},
    "PLATFORM_STATUS": {"k": 2, "window_seconds": 30},
    "DEPLOYMENT": {"k": 1, "window_seconds": 60},
    "PACKAGE": {"k": 1, "window_seconds": 120},
    "CELL_FORMATION": {"k": 2, "window_seconds": 10},
}

# This annotation layer is soft-safety AP — it never blocks a CRDT write.
SOFT_SAFETY_AP = True
BLOCKS_WRITES = False


_HEX_256 = re.compile(r"[0-9a-f]{64}\Z")
_NODE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")


def _collector_now(now: datetime | None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("clock must be an aware datetime")
    return now.astimezone(timezone.utc)


def _bound_expiry(text: str) -> datetime:
    if not isinstance(text, str) or not text:
        raise ValueError("window_expires_at must be a nonempty ISO datetime")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("window_expires_at must be an ISO datetime") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("window_expires_at must include an offset")
    return parsed.astimezone(timezone.utc)


@dataclass
class CorroborationLedger:
    """Advisory-only multi-reporter observations; not authenticated peer consensus.

    This is a bounded, in-process record, not a mergeable replicated CRDT object.
    It does NOT validate enrollment, transport identity, independently signed node
    assertions, or signatures. Multiple claimed node IDs never grant action
    authority. All policy/class and collector-window changes fail closed.
    """

    policies: dict = field(default_factory=lambda: deepcopy(DEFAULT_CORROBORATION_POLICIES))
    entries: dict = field(default_factory=dict)
    soft_safety_ap: bool = SOFT_SAFETY_AP
    blocks_writes: bool = BLOCKS_WRITES

    def __post_init__(self) -> None:
        if not isinstance(self.policies, dict) or not isinstance(self.entries, dict):
            raise ValueError("corroboration configuration requires dictionaries")
        self.policies = deepcopy(self.policies)
        self.entries = deepcopy(self.entries)

    def policy_for(self, transition_class: str) -> dict:
        if not isinstance(transition_class, str) or transition_class not in self.policies:
            raise ValueError("transition_class has no admitted corroboration policy")
        policy = self.policies[transition_class]
        if not isinstance(policy, dict):
            raise ValueError("corroboration policy must be an object")
        k, seconds = policy.get("k"), policy.get("window_seconds")
        if (type(k) is not int or not 1 <= k <= 128
                or type(seconds) is not int or not 1 <= seconds <= 86400):
            raise ValueError("corroboration policy requires positive bounded integers")
        return {"k": k, "window_seconds": seconds}

    def observe(
        self,
        change_hash: str,
        node_id: str,
        transition_class: str = "PLATFORM_STATUS",
        window_expires_at: str = "",
        *,
        now: datetime | None = None,
    ) -> dict:
        """Record one CLAIMED reporter, never authorize an effect.

        Window T begins with the first collector observation. Caller expiry may
        shorten but never extend it. Time is local collector time, not signed
        global time. Replays, class/policy switches and expired observations never
        increase confidence. No network or CRDT state mutation occurs here.
        """
        if not isinstance(change_hash, str) or not _HEX_256.fullmatch(change_hash):
            raise ValueError("change_hash must be lowercase SHA-256 hex")
        if not isinstance(node_id, str) or not _NODE_NAME.fullmatch(node_id):
            raise ValueError("node_id must be a bounded nonempty token")
        policy = self.policy_for(transition_class)
        clock = _collector_now(now)
        requested = _bound_expiry(window_expires_at) if window_expires_at else None
        e = self.entries.get(change_hash)
        if e is None:
            expiry = clock + timedelta(seconds=policy["window_seconds"])
            if requested is not None:
                if not clock < requested <= expiry:
                    raise ValueError("window_expires_at cannot extend or expire the policy window")
                expiry = requested
            e = {
                "status": "PENDING",
                "corroborating_nodes": [],
                "policy_k": policy["k"],
                "policy_window_seconds": policy["window_seconds"],
                "transition_class": transition_class,
                "first_observed_at": clock.isoformat(),
                "window_expires_at": expiry.isoformat(),
                "corroborated_at": None,
                "identity_verification": "UNVERIFIED_NODE_ASSERTIONS",
                "operational_authority": False,
            }
            self.entries[change_hash] = e
        else:
            if e["transition_class"] != transition_class:
                raise ValueError("transition_class differs from original observation")
            if (e["policy_k"] != policy["k"]
                    or e["policy_window_seconds"] != policy["window_seconds"]):
                raise ValueError("policy changed during active corroboration window")
            if requested is not None and requested != _bound_expiry(e["window_expires_at"]):
                raise ValueError("window_expires_at differs from original observation")
            if clock < _bound_expiry(e["first_observed_at"]):
                raise ValueError("clock moved backwards relative to first observation")
        if clock >= _bound_expiry(e["window_expires_at"]):
            e["status"] = "FAILED"
            e["corroborated_at"] = None
        if e["status"] == "FAILED":
            return deepcopy(e)
        # CRDT-like set-union is an analogy: this local list is not a replicated,
        # authenticated grow-only set and cannot establish independence of peers.
        if node_id not in e["corroborating_nodes"]:
            e["corroborating_nodes"].append(node_id)
        if len(e["corroborating_nodes"]) >= e["policy_k"]:
            e["status"] = "CORROBORATED"
            if e["corroborated_at"] is None:
                e["corroborated_at"] = clock.isoformat()
        return deepcopy(e)

    def status(self, change_hash: str, *, now: datetime | None = None) -> str:
        """Read-time expiry check WITHOUT mutating state or signing a receipt."""
        e = self.entries.get(change_hash)
        if e is None:
            return "PENDING"
        if e["status"] == "FAILED" or _collector_now(now) >= _bound_expiry(e["window_expires_at"]):
            return "FAILED"
        return e["status"]

    def mark_failed(self, change_hash: str) -> None:
        """Terminal failure is sticky. The application CRDT is never changed."""
        e = self.entries.get(change_hash)
        if e is not None:
            e["status"] = "FAILED"
            e["corroborated_at"] = None


def combined_classification(receipt_status: str, corroboration_status: str) -> str:
    """spec/04 §6 — receipt + corroboration are INDEPENDENT checks.

    Corroboration never blocks; it only annotates confidence.
    """
    table = {
        ("AUTHORIZED", "CORROBORATED"): "Reported AUTHORIZED + peer assertions — verify receipt, independent identities, and separate action gate",
        ("AUTHORIZED", "PENDING"): "Reported AUTHORIZED + pending peer assertions — separate action gate required",
        ("OBSERVED", "CORROBORATED"): "Multiple claimed node IDs — unverified identities and no doctrine proof",
        ("OBSERVED", "PENDING"): "Low confidence — situational awareness only",
        ("AUTHORIZED", "FAILED"): "Alert — node signed receipt but peers don't corroborate the value",
    }
    return table.get((receipt_status, corroboration_status), "Unknown")
