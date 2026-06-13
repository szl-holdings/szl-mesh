"""
szl_mesh.node — the SZL-MESH node runtime.

A MeshNode holds:
  - an ECDSA P-256 keypair (node identity; node_id = SHA-256(SPKI-DER))
  - a CRDTDocument with two-track state (spec/02)
  - a local receipt ledger (change_hash -> DSSE envelope) (spec/01)
  - an enrollment status against a FormationGateway (spec/05)

A node writes a receipted CRDT state transition with `write()`: it appends a
CRDT op, builds a StateTransitionStatement + DSSE receipt (ECDSA-P256-SHA256
over the PAE), and classifies the op via the Receipt Gate into AUTHORIZED or
OBSERVED. Nodes exchange ops + receipts with `apply_remote()`; the CRDT merge
is convergent, so all nodes that see the same ops converge to identical state.

Doctrine v11 LOCKED 749/14/163 · Kernel commit c7c0ba17 · SLSA L1.
Soft-safety AP two-track model (the real shipped one). No unconditional BFT
claim here (Khipu BFT unconditional = Conjecture 2); quorum is Dev 2's lane.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import receipts as rcpt
from .crdt import AUTHORIZED, OBSERVED, REVOKED, CRDTDocument, Op
from .enrollment import FormationGateway, build_enrollment_request


class MeshNode:
    """A single in-process SZL-MESH node."""

    def __init__(self, name: str, doc_id: str) -> None:
        self.name = name
        self.doc_id = doc_id
        self._priv, self.node_id = rcpt.generate_node_keypair()
        self.doc = CRDTDocument(doc_id)
        self.receipt_ledger: Dict[str, Dict[str, Any]] = {}  # change_hash -> envelope
        self.enrolled = False
        self._gateway: Optional[FormationGateway] = None
        self._lamport = 0  # Lamport clock for CRDT op ordering

    # ── identity ────────────────────────────────────────────────────
    def public_key_der(self) -> bytes:
        return self._priv.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    # ── enrollment (spec/05) ─────────────────────────────────────────
    def enroll(
        self,
        gateway: FormationGateway,
        formation_key: bytes,
        hardware_vendor: str = "",
        doctrine_version: str = rcpt.DOCTRINE_VERSION,
        kernel_commit: str = rcpt.KERNEL_COMMIT,
        slsa_level: str = rcpt.SLSA_LEVEL,
    ):
        """Attempt doctrine-gated enrollment. Returns the EnrollmentResult."""
        req = build_enrollment_request(
            formation_key=formation_key,
            node_id=self.node_id,
            public_key_der=self.public_key_der(),
            timestamp_utc=rcpt.utc_now_iso(),
            doctrine_version=doctrine_version,
            kernel_commit=kernel_commit,
            slsa_level=slsa_level,
            hardware_vendor=hardware_vendor,
        )
        result = gateway.enroll(req)
        if result.success:
            self.enrolled = True
            self._gateway = gateway
        return result

    def _tick(self, observed_lamport: Optional[int] = None) -> int:
        """Advance the Lamport clock (max(local, observed) + 1)."""
        base = self._lamport
        if observed_lamport is not None:
            base = max(base, observed_lamport)
        self._lamport = base + 1
        return self._lamport

    # ── write a receipted state transition (spec/01 + spec/02) ───────
    def write(
        self,
        key: str,
        value: Any,
        transition_class: str = "PLATFORM_STATUS",
        deletion: bool = False,
    ) -> Dict[str, Any]:
        """
        Append a CRDT op, build + sign a DSSE receipt, classify the op via the
        Receipt Gate, and store the receipt in the ledger. Returns a record
        {op, receipt, gate_result} ready to broadcast to peers.
        """
        if not self.enrolled:
            raise RuntimeError(f"node {self.name} must enroll before writing")

        from_heads = self.doc.heads()
        lamport = self._tick()
        op = Op(
            doc_id=self.doc_id,
            key=key,
            value=value,
            lamport=lamport,
            node_id=self.node_id,
            deletion=deletion,
        )
        change_hash = op.op_id
        self.doc.add_op(op)  # added as OBSERVED first; gate may upgrade
        to_heads = self.doc.heads()

        stmt = rcpt.build_state_transition_statement(
            crdt_doc_id=self.doc_id,
            change_hash=change_hash,
            from_heads=from_heads,
            to_heads=to_heads,
            node_id=self.node_id,
            transition_class=transition_class,
        )
        envelope = rcpt.build_dsse_receipt(stmt, self._priv)
        self.receipt_ledger[change_hash] = envelope

        gate = self._classify(op, envelope)
        self.doc.set_op_track(change_hash, gate.track)
        return {
            "op": op.to_dict(),
            "op_obj": op,
            "receipt": envelope,
            "change_hash": change_hash,
            "track": gate.track,
            "receipt_status": gate.receipt_status,
        }

    def _classify(self, op: Op, envelope: Optional[Dict[str, Any]]):
        """Run the Receipt Gate for an op against this node's known state."""
        registry = self._gateway.pubkey_registry() if self._gateway else None
        revoked = self._gateway.revoked if self._gateway else set()
        return rcpt.validate_receipt(
            receipt=envelope,
            change_raw_bytes=op.raw_bytes(),
            now_utc=datetime.now(timezone.utc),
            revoked_node_ids=revoked,
            pubkey_registry=registry,
        )

    # ── receive a remote op + receipt ────────────────────────────────
    def apply_remote(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply a peer's broadcast record: merge the op (CRDT union), store the
        receipt, and independently re-classify via this node's Receipt Gate.
        Returns this node's local classification (may match or differ on skew).
        """
        op: Op = record["op_obj"]
        envelope = record.get("receipt")
        # Advance Lamport clock to preserve causal ordering across the mesh.
        self._tick(op.lamport)
        newly = self.doc.add_op(
            Op(
                doc_id=op.doc_id,
                key=op.key,
                value=op.value,
                lamport=op.lamport,
                node_id=op.node_id,
                deletion=op.deletion,
            )
        )
        if envelope is not None:
            self.receipt_ledger[op.op_id] = envelope
        gate = self._classify(op, envelope)
        self.doc.set_op_track(op.op_id, gate.track)
        return {
            "newly_added": newly,
            "track": gate.track,
            "receipt_status": gate.receipt_status,
        }

    # ── views ────────────────────────────────────────────────────────
    def authorized_state(self) -> Dict[str, Any]:
        return self.doc.authorized_view()

    def observed_state(self) -> Dict[str, Any]:
        return self.doc.observed_view()

    def state_digest(self, track: str = OBSERVED) -> str:
        return self.doc.state_digest(track)

    def verify_ledger(self) -> Tuple[int, int]:
        """Re-verify every receipt in the ledger. Returns (valid, total)."""
        valid = 0
        for env in self.receipt_ledger.values():
            if rcpt.verify_receipt_signature(env):
                valid += 1
        return valid, len(self.receipt_ledger)
