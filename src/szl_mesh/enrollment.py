"""
szl_mesh.enrollment — Doctrine-Gated Certificate Enrollment (spec/05).

A node enrolls into a formation only if it presents a valid, doctrine-bound
formation-key proof. The HMAC proof binds doctrine_version + kernel_commit, so
a node cannot claim one doctrine and operate under another. Any failure (bad
proof, wrong doctrine/kernel/slsa, replayed timestamp, Section 889 vendor hit,
already-revoked node) REJECTS enrollment.

Doctrine v11 LOCKED 749/14/163 · Kernel commit c7c0ba17 · SLSA L1.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .receipts import (
    DOCTRINE_VERSION,
    KERNEL_COMMIT,
    SECTION_889_VENDORS,
    SLSA_LEVEL,
)

# Section 889 covered vendors with full legal names (for attestation matching).
_SECTION_889_MATCH = {v.lower() for v in SECTION_889_VENDORS} | {
    "huawei technologies",
    "zte corporation",
    "hytera communications",
    "hangzhou hikvision",
    "hikvision digital",
    "dahua technology",
}


def compute_formation_key_proof(
    formation_key: bytes,
    node_id: str,
    timestamp_utc: str,
    doctrine_version: str = DOCTRINE_VERSION,
    kernel_commit: str = KERNEL_COMMIT,
) -> str:
    """
    HMAC-SHA256(formation_key,
                node_id || timestamp_utc || doctrine_version || kernel_commit)
    See spec/05 §2. Doctrine + kernel are inside the HMAC message.
    """
    message = (node_id + timestamp_utc + doctrine_version + kernel_commit).encode(
        "utf-8"
    )
    return hmac.new(formation_key, message, hashlib.sha256).hexdigest()


def build_enrollment_request(
    formation_key: bytes,
    node_id: str,
    public_key_der: bytes,
    timestamp_utc: str,
    doctrine_version: str = DOCTRINE_VERSION,
    kernel_commit: str = KERNEL_COMMIT,
    slsa_level: str = SLSA_LEVEL,
    hardware_vendor: str = "",
    attestation_method: str = "self_report",
) -> Dict[str, Any]:
    """Construct an EnrollNodeRequest-shaped dict (spec/05 §2, proto)."""
    proof = compute_formation_key_proof(
        formation_key, node_id, timestamp_utc, doctrine_version, kernel_commit
    )
    return {
        "node_id": node_id,
        "public_key_der": public_key_der,
        "formation_key_proof": proof,
        "timestamp_utc": timestamp_utc,
        "doctrine_claim": {
            "doctrine_version": doctrine_version,
            "kernel_commit": kernel_commit,
            "slsa_level": slsa_level,
        },
        "section_889_attestation": {
            "vendor_exclusion_confirmed": True,
            "hardware_vendor": hardware_vendor,
            "attestation_method": attestation_method,
        },
    }


@dataclass
class EnrollmentResult:
    success: bool
    node_id: str
    failure_reason: Optional[str] = None
    enrolled_at: Optional[str] = None
    expires_at: Optional[str] = None


class FormationGateway:
    """
    Doctrine-gated enrollment gateway (spec/05 §3). Validates an enrollment
    request against the locked doctrine and the formation key. Maintains the
    CertificateStore (node_id -> public_key_der) so receipts can be bound to
    enrolled keys, and consults a revocation set.
    """

    def __init__(
        self,
        formation_id: str,
        formation_key: bytes,
        timestamp_skew_seconds: int = 300,
    ) -> None:
        self.formation_id = formation_id
        self._formation_key = formation_key
        self._skew = timestamp_skew_seconds
        self.cert_store: Dict[str, Dict[str, Any]] = {}  # node_id -> entry
        self.revoked: set = set()

    def pubkey_registry(self) -> Dict[str, bytes]:
        """Map node_id -> public_key_der for enrolled, non-revoked nodes."""
        return {
            nid: e["public_key_der"]
            for nid, e in self.cert_store.items()
            if nid not in self.revoked
        }

    def revoke(self, node_id: str) -> None:
        self.revoked.add(node_id)

    def enroll(
        self, req: Dict[str, Any], now_utc: Optional[datetime] = None
    ) -> EnrollmentResult:
        now_utc = now_utc or datetime.now(timezone.utc)
        node_id = req.get("node_id", "")

        # Step 1: verify formation_key_proof (constant-time compare).
        expected = compute_formation_key_proof(
            self._formation_key,
            node_id,
            req.get("timestamp_utc", ""),
            req.get("doctrine_claim", {}).get("doctrine_version", ""),
            req.get("doctrine_claim", {}).get("kernel_commit", ""),
        )
        if not hmac.compare_digest(expected, req.get("formation_key_proof", "")):
            return EnrollmentResult(False, node_id, "BAD_FORMATION_PROOF")

        # Step 2: timestamp window (anti-replay).
        try:
            ts = datetime.strptime(
                req["timestamp_utc"], "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=timezone.utc)
        except (ValueError, KeyError):
            return EnrollmentResult(False, node_id, "BAD_TIMESTAMP")
        if abs((now_utc - ts).total_seconds()) > self._skew:
            return EnrollmentResult(False, node_id, "TIMESTAMP_OUT_OF_WINDOW")

        claim = req.get("doctrine_claim", {})
        # Steps 3-5: doctrine / kernel / slsa.
        if claim.get("doctrine_version") != DOCTRINE_VERSION:
            return EnrollmentResult(False, node_id, "WRONG_DOCTRINE")
        if claim.get("kernel_commit") != KERNEL_COMMIT:
            return EnrollmentResult(False, node_id, "WRONG_KERNEL")
        if claim.get("slsa_level") != SLSA_LEVEL:
            return EnrollmentResult(False, node_id, "WRONG_SLSA")

        # Step 6: revocation check.
        if node_id in self.revoked:
            return EnrollmentResult(False, node_id, "REVOKED")

        # Step 7: Section 889 attestation.
        att = req.get("section_889_attestation", {})
        if not att.get("vendor_exclusion_confirmed", False):
            return EnrollmentResult(False, node_id, "SECTION_889_NOT_CONFIRMED")
        vendor = (att.get("hardware_vendor") or "").strip().lower()
        if vendor and any(m in vendor or vendor in m for m in _SECTION_889_MATCH):
            return EnrollmentResult(False, node_id, "SECTION_889_VIOLATION")

        # Duplicate NodeID guard.
        if node_id in self.cert_store:
            return EnrollmentResult(False, node_id, "DUPLICATE_NODE_ID")

        # Bind node_id to the presented public key (used by the Receipt Gate).
        enrolled_at = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        self.cert_store[node_id] = {
            "node_id": node_id,
            "public_key_der": req["public_key_der"],
            "enrolled_at": enrolled_at,
            "doctrine_version": DOCTRINE_VERSION,
            "kernel_commit": KERNEL_COMMIT,
        }
        return EnrollmentResult(True, node_id, None, enrolled_at)
