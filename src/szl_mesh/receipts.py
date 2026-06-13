"""
szl_mesh.receipts — Doctrine-Pinned DSSE Receipts on CRDT state transitions.

Implements spec/01-dsse-receipts.md with REAL cryptography:
  - StateTransitionStatement (doctrine-pinned, Section 889 vendors exactly 5)
  - DSSE Pre-Authentication Encoding (PAE), DSSE §3
  - DSSE envelope signed with ECDSA-P256-SHA256 over the PAE
    (matches the khipu-consensus engine's ECDSA-P256-SHA256 cosign scheme;
     receipts are therefore re-verifiable with the same primitive the quorum
     engine uses — Dev 2 wires khipu quorum on top of these signatures).
  - Receipt Gate validation -> AUTHORIZED / OBSERVED with a failure reason.

Doctrine v11 LOCKED 749/14/163 · Kernel commit c7c0ba17 · SLSA L1.
This module never claims unconditional BFT (Conjecture 2); it provides
re-verifiable per-node receipts only. NEVER fabricate a signature.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

# ── Locked doctrine constants — NEVER MODIFY without a new doctrine release ──
DOCTRINE_VERSION = "749/14/163"
KERNEL_COMMIT = "c7c0ba17"
SLSA_LEVEL = "L1"
# Section 889 (FY2019 NDAA) covered vendors — EXACTLY 5.
SECTION_889_VENDORS = ["Huawei", "ZTE", "Hytera", "Hikvision", "Dahua"]

PAYLOAD_TYPE = "application/vnd.szl.mesh.state-transition+json"
STATEMENT_TYPE = "szl-mesh/state-transition/v1"

TRANSITION_CLASSES = {
    "PLATFORM_STATUS",
    "DEPLOYMENT",
    "PACKAGE",
    "COMMAND",
    "CELL_FORMATION",
}

# Validation outcomes (mirror proto ReceiptStatus).
RECEIPT_VALID = "RECEIPT_VALID"
RECEIPT_MISSING = "MISSING_RECEIPT"
RECEIPT_BAD_SIGNATURE = "BAD_SIGNATURE"
RECEIPT_WRONG_DOCTRINE = "WRONG_DOCTRINE"
RECEIPT_WRONG_KERNEL = "WRONG_KERNEL"
RECEIPT_REVOKED = "REVOKED"
RECEIPT_CLOCK_SKEW = "CLOCK_SKEW"
RECEIPT_HASH_MISMATCH = "HASH_MISMATCH"
RECEIPT_BAD_VENDORS = "SECTION_889_VENDOR_COUNT"

_B64 = "base64url"


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def node_id_from_pubkey(pubkey: ec.EllipticCurvePublicKey) -> str:
    """NodeID = SHA-256(DER SubjectPublicKeyInfo of the P-256 pubkey), hex."""
    der = pubkey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def generate_node_keypair() -> Tuple[ec.EllipticCurvePrivateKey, str]:
    """Generate an ECDSA P-256 keypair; return (private_key, node_id)."""
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv, node_id_from_pubkey(priv.public_key())


def pae(payload_type: str, payload: bytes) -> bytes:
    """
    DSSE Pre-Authentication Encoding (DSSE §3).
    PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
    """
    t = payload_type.encode("utf-8")
    return b" ".join(
        [b"DSSEv1", str(len(t)).encode(), t, str(len(payload)).encode(), payload]
    )


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_state_transition_statement(
    crdt_doc_id: str,
    change_hash: str,
    from_heads: List[str],
    to_heads: List[str],
    node_id: str,
    transition_class: str = "PLATFORM_STATUS",
    timestamp_utc: Optional[str] = None,
) -> Dict[str, Any]:
    """Construct the StateTransitionStatement (spec/01 §3)."""
    if transition_class not in TRANSITION_CLASSES:
        raise ValueError(f"invalid transition_class: {transition_class!r}")
    return {
        "type": STATEMENT_TYPE,
        "doctrine_version": DOCTRINE_VERSION,  # LOCKED
        "kernel_commit": KERNEL_COMMIT,        # LOCKED
        "crdt_document_id": crdt_doc_id,
        "change_hash": change_hash,
        "from_state_head": list(from_heads),
        "to_state_head": list(to_heads),
        "transition_class": transition_class,
        "node_id": node_id,
        "timestamp_utc": timestamp_utc or utc_now_iso(),
        "policy_context": {
            "section_889_vendors": list(SECTION_889_VENDORS),  # exactly 5
            "slsa_level": SLSA_LEVEL,
        },
    }


def build_dsse_receipt(
    stmt: Dict[str, Any], private_key: ec.EllipticCurvePrivateKey
) -> Dict[str, Any]:
    """
    Wrap a StateTransitionStatement in a DSSE envelope and sign the PAE
    with ECDSA-P256-SHA256. Produces a REAL, re-verifiable signature.
    """
    stmt_json = json.dumps(stmt, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_b64 = _b64url_encode(stmt_json)
    signing_input = pae(PAYLOAD_TYPE, stmt_json)

    # ECDSA-P256 over SHA-256(signing_input) — DER-encoded signature.
    sig = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))

    pub_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": payload_b64,
        "signatures": [
            {
                "keyid": stmt["node_id"],
                "sig": _b64url_encode(sig),
                "sig_alg": "ECDSA-P256-SHA256",
                "sig_encoding": _B64,
                "public_key_der": _b64url_encode(pub_der),
            }
        ],
    }


def decode_statement(receipt: Dict[str, Any]) -> Dict[str, Any]:
    return json.loads(_b64url_decode(receipt["payload"]).decode("utf-8"))


def verify_receipt_signature(receipt: Dict[str, Any]) -> bool:
    """
    Re-verify the ECDSA-P256-SHA256 signature over the PAE using the public
    key embedded in the envelope. Returns True iff the signature is valid.
    """
    try:
        sig_entry = receipt["signatures"][0]
        if sig_entry.get("sig_alg") != "ECDSA-P256-SHA256":
            return False
        payload_b64 = receipt["payload"]
        stmt_json = _b64url_decode(payload_b64)
        signing_input = pae(receipt["payloadType"], stmt_json)
        pub_der = _b64url_decode(sig_entry["public_key_der"])
        pub = serialization.load_der_public_key(pub_der)
        if not isinstance(pub, ec.EllipticCurvePublicKey):
            return False
        sig = _b64url_decode(sig_entry["sig"])
        pub.verify(sig, signing_input, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, KeyError, ValueError, TypeError):
        return False


@dataclass
class GateResult:
    track: str  # AUTHORIZED or OBSERVED
    receipt_status: str
    statement: Optional[Dict[str, Any]]


def validate_receipt(
    receipt: Optional[Dict[str, Any]],
    change_raw_bytes: bytes,
    now_utc: Optional[datetime] = None,
    revoked_node_ids: Optional[set] = None,
    clock_skew_seconds: int = 5,
    pubkey_registry: Optional[Dict[str, bytes]] = None,
) -> GateResult:
    """
    Doctrine Receipt Gate (spec/01 §5 + spec/02 §3).
    Returns AUTHORIZED only if EVERY check passes; otherwise OBSERVED with a
    reason. The CRDT change is never dropped — track is advisory.
    """
    from .crdt import AUTHORIZED, OBSERVED  # local import to avoid cycle

    revoked_node_ids = revoked_node_ids or set()
    now_utc = now_utc or datetime.now(timezone.utc)

    if receipt is None:
        return GateResult(OBSERVED, RECEIPT_MISSING, None)

    # 1-2. payloadType
    if receipt.get("payloadType") != PAYLOAD_TYPE:
        return GateResult(OBSERVED, RECEIPT_MISSING, None)

    try:
        stmt = decode_statement(receipt)
    except (ValueError, KeyError):
        return GateResult(OBSERVED, RECEIPT_MISSING, None)

    # 4. doctrine
    if stmt.get("doctrine_version") != DOCTRINE_VERSION:
        return GateResult(OBSERVED, RECEIPT_WRONG_DOCTRINE, stmt)
    # 5. kernel
    if stmt.get("kernel_commit") != KERNEL_COMMIT:
        return GateResult(OBSERVED, RECEIPT_WRONG_KERNEL, stmt)

    # Section 889 invariant: exactly 5 vendors.
    vendors = stmt.get("policy_context", {}).get("section_889_vendors", [])
    if list(vendors) != list(SECTION_889_VENDORS):
        return GateResult(OBSERVED, RECEIPT_BAD_VENDORS, stmt)

    # 6-7. signature
    if not verify_receipt_signature(receipt):
        return GateResult(OBSERVED, RECEIPT_BAD_SIGNATURE, stmt)

    # If a pubkey registry is supplied, ensure keyid/node_id binds to a known
    # enrolled key (prevents using a self-supplied key for AUTHORIZED state).
    node_id = stmt.get("node_id")
    if pubkey_registry is not None:
        known = pubkey_registry.get(node_id)
        sig_pub = _b64url_decode(receipt["signatures"][0]["public_key_der"])
        if known is None or known != sig_pub:
            return GateResult(OBSERVED, RECEIPT_BAD_SIGNATURE, stmt)

    # 8. revocation
    if node_id in revoked_node_ids:
        return GateResult(OBSERVED, RECEIPT_REVOKED, stmt)

    # 9. change_hash matches the raw change chunk
    if hashlib.sha256(change_raw_bytes).hexdigest() != stmt.get("change_hash"):
        return GateResult(OBSERVED, RECEIPT_HASH_MISMATCH, stmt)

    # 10. timestamp within skew window
    try:
        ts = datetime.strptime(stmt["timestamp_utc"], "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except (ValueError, KeyError):
        return GateResult(OBSERVED, RECEIPT_CLOCK_SKEW, stmt)
    if abs((now_utc - ts).total_seconds()) > clock_skew_seconds:
        return GateResult(OBSERVED, RECEIPT_CLOCK_SKEW, stmt)

    return GateResult(AUTHORIZED, RECEIPT_VALID, stmt)
