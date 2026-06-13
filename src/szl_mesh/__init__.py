"""
szl_mesh — SZL-MESH node runtime (Dev 1 lane).

A real, runnable mesh: convergent CRDT documents with two-track state,
doctrine-pinned DSSE receipts (ECDSA-P256-SHA256), and doctrine-gated
enrollment.

Doctrine v11 LOCKED 749/14/163 · Kernel commit c7c0ba17 · SLSA L1.
Two-track soft-safety AP model is the real shipped one
(Khipu BFT unconditional = Conjecture 2; never claimed proven here).
"""

from .crdt import AUTHORIZED, OBSERVED, REVOKED, CRDTDocument, Op
from .enrollment import FormationGateway, build_enrollment_request
from .node import MeshNode
from .receipts import (
    DOCTRINE_VERSION,
    KERNEL_COMMIT,
    SECTION_889_VENDORS,
    SLSA_LEVEL,
    build_dsse_receipt,
    build_state_transition_statement,
    validate_receipt,
    verify_receipt_signature,
)

__all__ = [
    "AUTHORIZED",
    "OBSERVED",
    "REVOKED",
    "CRDTDocument",
    "Op",
    "MeshNode",
    "FormationGateway",
    "build_enrollment_request",
    "build_dsse_receipt",
    "build_state_transition_statement",
    "validate_receipt",
    "verify_receipt_signature",
    "DOCTRINE_VERSION",
    "KERNEL_COMMIT",
    "SLSA_LEVEL",
    "SECTION_889_VENDORS",
]

__version__ = "0.1.0"
