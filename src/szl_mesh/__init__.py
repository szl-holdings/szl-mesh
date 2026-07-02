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

# ── Dev 2 lane: Khipu 3-of-4 quorum wiring (layered on Dev 1's ECDSA-P256 receipts).
# Additive re-export; does not alter Dev 1's runtime surface above.
from .quorum import (  # noqa: E402
    propose_action,
    verify_quorum,
    action_hash,
    QuorumCertificate,
    QuorumVerification,
    CorroborationLedger,
    combined_classification,
)

__all__ += [
    "propose_action",
    "verify_quorum",
    "action_hash",
    "QuorumCertificate",
    "QuorumVerification",
    "CorroborationLedger",
    "combined_classification",
]

# ── PCGI spine (T302): fold mesh state transitions onto the org-canonical
# szl-receipt emit_receipt binding. Additive re-export; the spine module imports
# szl_receipt lazily, so importing szl_mesh never requires the optional lib.
from .spine import (  # noqa: E402
    SpineUnavailable,
    build_mesh_receipt_body,
    emit_mesh_receipt,
    emit_mesh_receipt_from_dsse,
    mesh_receipt_body_digest,
    transition_input_digest,
    transition_output_digest,
    verify_mesh_receipt,
)

__all__ += [
    "SpineUnavailable",
    "build_mesh_receipt_body",
    "emit_mesh_receipt",
    "emit_mesh_receipt_from_dsse",
    "mesh_receipt_body_digest",
    "transition_input_digest",
    "transition_output_digest",
    "verify_mesh_receipt",
]
