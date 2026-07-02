# Copyright 2026 SZL Holdings
# SPDX-License-Identifier: Apache-2.0
"""szl_mesh.spine — fold mesh state transitions onto the canonical szl-receipt.

The mesh already emits doctrine-pinned DSSE receipts over CRDT state
transitions (see :mod:`szl_mesh.receipts`). That path is untouched. This module
ADDS, alongside it, an ``emit_receipt``-style binding on the org-canonical
``szl-receipt`` (v0.2.0) shape so a mesh state transition becomes a first-class
*Proof-Carrying Governed Intelligence* (PCGI) receipt on the same spine every
other decision producer uses (a11oy, yarqa, killinchu, governed-inference-meter).

A canonical mesh receipt binds, in ONE record:

  * ``subject``       — the node id (and optional quorum id) that produced it,
  * ``input_digest``  — SHA-256 over the canonical pre-state + applied change,
  * ``output_digest`` — SHA-256 over the canonical resulting state head,
  * ``policy_id``     — the governing (doctrine-gate) policy id,
  * ``energy``        — the literal ``"UNAVAILABLE"`` (the mesh measures no
    joules — a joule figure is NEVER fabricated).

It does NOT invent a new receipt shape or re-implement digests/signing: it uses
``szl_receipt.Receipt`` + ``szl_receipt.sign_receipt`` for the canonical body +
DSSE signing, and ``szl_receipt.verify_receipt`` for verification. The shared
library is the ONE source of truth for canonicalization and signing.

Honesty (doctrine v11 · 749/14/163 @ c7c0ba17)
----------------------------------------------
* The receipt is EVIDENCE binding a decision (subject+input+output+policy+
  energy), NOT a proof the transition is correct and NOT a claim of
  unconditional BFT (that stays Conjecture 2, never asserted here).
* ``energy`` is the literal ``"UNAVAILABLE"`` sentinel with ``measured=False``;
  the mesh has no energy meter, so no joule is ever fabricated.
* Keyless => UNSIGNED-honest (``signed=False``); a signature is never faked.
* The canonical body is deterministic: a fixed transition serializes to
  byte-identical canonical JSON (no timestamps / nonces in the body), so the
  same transition always yields the same receipt digest.

Import stays additive: ``szl_receipt`` is imported lazily, so importing
``szl_mesh`` never requires it — the cryptography-only DSSE path in
:mod:`szl_mesh.receipts` keeps working without it. Producing a canonical
receipt requires the optional ``[spine]`` extra (``szl-receipt>=0.2.0``); its
absence raises a clear :class:`SpineUnavailable` rather than a fabricated
receipt.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .receipts import (
    DOCTRINE_VERSION,
    KERNEL_COMMIT,
    SLSA_LEVEL,
    decode_statement,
)

# --- Canonical PCGI spine constants -------------------------------------------
PCGI_RECEIPT_SCHEMA = "szl.pcgi.receipt/szl-mesh-state-transition/v1"
RECEIPT_KIND = "szl-mesh-state-transition"
# The mesh's governing policy is its doctrine-pinned Receipt Gate; this id names
# that governing policy for the canonical binding (override per formation/quorum).
DEFAULT_POLICY_ID = "szl.pcgi.policy/szl-mesh-doctrine-gate/v1"
DEFAULT_ORGAN = "szl-mesh"
# The mesh measures no joules -> the literal UNAVAILABLE sentinel, never a number.
ENERGY_UNAVAILABLE = "UNAVAILABLE"


class SpineUnavailable(RuntimeError):
    """Raised when the shared ``szl_receipt`` library is not importable.

    Callers MUST treat this as "no canonical receipt here", never as a reason to
    fabricate a receipt or duplicate the shared shapes locally. The existing
    DSSE path in :mod:`szl_mesh.receipts` remains available without the library.
    """


def _require_szl_receipt():
    """Lazily import the shared library; fail honestly if it is absent."""
    try:
        import szl_receipt  # type: ignore
    except Exception as exc:  # pragma: no cover - exercised only without the lib
        raise SpineUnavailable(
            "szl_receipt (v0.2.0) is not installed; install the optional extra "
            "`pip install 'szl-mesh[spine]'` (or "
            "`pip install szl-receipt>=0.2.0`) to emit canonical mesh receipts. "
            "Refusing to duplicate the shared receipt shapes."
        ) from exc
    return szl_receipt


def _digest(body: Dict[str, Any]) -> str:
    """SHA-256 hex over the shared canonical JSON of ``body``.

    Uses ``szl_receipt.Receipt.digest`` (SHA-256 over the library's canonical
    JSON) so the digest is byte-for-byte the same primitive that binds every
    other SZL receipt — nothing is re-implemented here.
    """
    szl_receipt = _require_szl_receipt()
    return szl_receipt.Receipt(kind="_digest", body=dict(body)).digest()


def transition_input(stmt: Dict[str, Any]) -> Dict[str, Any]:
    """The canonical INPUT that determines a transition (digested into a receipt).

    Binds the pre-state and the change being applied: the CRDT document, the
    ``from`` state head, the applied ``change_hash``, and the transition class.
    Deriving this independently reproduces ``input_digest``.
    """
    return {
        "crdt_document_id": stmt.get("crdt_document_id"),
        "from_state_head": list(stmt.get("from_state_head", [])),
        "change_hash": stmt.get("change_hash"),
        "transition_class": stmt.get("transition_class"),
    }


def transition_output(stmt: Dict[str, Any]) -> Dict[str, Any]:
    """The canonical OUTPUT of a transition (the resulting state head)."""
    return {
        "crdt_document_id": stmt.get("crdt_document_id"),
        "to_state_head": list(stmt.get("to_state_head", [])),
    }


def transition_input_digest(stmt: Dict[str, Any]) -> str:
    """SHA-256 hex over :func:`transition_input`."""
    return _digest(transition_input(stmt))


def transition_output_digest(stmt: Dict[str, Any]) -> str:
    """SHA-256 hex over :func:`transition_output`."""
    return _digest(transition_output(stmt))


def build_mesh_receipt_body(
    stmt: Dict[str, Any],
    *,
    policy_id: str = DEFAULT_POLICY_ID,
    quorum_id: Optional[str] = None,
    witnesses: Optional[List[Any]] = None,
) -> Dict[str, Any]:
    """Assemble the canonical PCGI receipt body for one state transition.

    Binds the spine tuple — subject (node id + optional quorum id), input
    digest, output digest, governing policy id, energy (the literal
    ``UNAVAILABLE`` — the mesh measures no joules), and optional BFT witnesses.
    The body is deterministic for a fixed transition (no timestamps / nonces),
    so the same transition always yields byte-identical canonical JSON.
    """
    return {
        "schema": PCGI_RECEIPT_SCHEMA,
        "kind": RECEIPT_KIND,
        "subject": {
            "node_id": stmt.get("node_id"),
            "quorum_id": quorum_id,
        },
        "doctrine_version": DOCTRINE_VERSION,
        "kernel_commit": KERNEL_COMMIT,
        "slsa_level": SLSA_LEVEL,
        "input_digest": transition_input_digest(stmt),
        "output_digest": transition_output_digest(stmt),
        "policy_id": policy_id,
        "energy": {
            "measured": False,
            "joules": ENERGY_UNAVAILABLE,  # literal sentinel — no fabricated joule
            "reason": (
                "szl-mesh measures no joules; energy reported UNAVAILABLE, "
                "never fabricated."
            ),
        },
        "witnesses": list(witnesses or []),
        "transition": {
            "crdt_document_id": stmt.get("crdt_document_id"),
            "transition_class": stmt.get("transition_class"),
            "change_hash": stmt.get("change_hash"),
        },
        "honesty": {
            "asserts": "integrity/reproducibility, NOT correctness",
            "receipt_is": (
                "evidence trail binding this decision (subject+input+output+"
                "policy+energy), NOT a proof the transition is correct"
            ),
            "bft": "no unconditional BFT is claimed here (Conjecture 2)",
        },
    }


def mesh_receipt_body_digest(
    stmt: Dict[str, Any],
    *,
    policy_id: str = DEFAULT_POLICY_ID,
    quorum_id: Optional[str] = None,
    witnesses: Optional[List[Any]] = None,
) -> str:
    """Independently (re-)derive the canonical receipt's content digest."""
    return _digest(
        build_mesh_receipt_body(
            stmt, policy_id=policy_id, quorum_id=quorum_id, witnesses=witnesses
        )
    )


def emit_mesh_receipt(
    stmt: Dict[str, Any],
    *,
    private_key_pem: Optional[str | bytes] = None,
    policy_id: str = DEFAULT_POLICY_ID,
    quorum_id: Optional[str] = None,
    organ: str = DEFAULT_ORGAN,
    keyid: str = "",
    witnesses: Optional[List[Any]] = None,
) -> Dict[str, Any]:
    """Emit ONE canonical szl-receipt for a mesh state transition (the spine).

    ``stmt`` is a StateTransitionStatement (as produced by
    :func:`szl_mesh.receipts.build_state_transition_statement`). Its content is
    folded into a shared :class:`szl_receipt.Receipt` and signed via
    :func:`szl_receipt.sign_receipt` (DSSE/ECDSA-P256-SHA256, cosign-compatible)
    — the SAME primitive the existing mesh DSSE path and khipu quorum use.

    When ``private_key_pem`` is ``None``/empty the shared library returns an
    UNSIGNED-honest envelope (``signed=False``) — never a fabricated signature.

    The returned DSSE envelope binds subject (node/quorum id) + input digest +
    output/state digest + governing policy id + honest ``UNAVAILABLE`` energy.
    It is an EVIDENCE trail for the decision, not a proof the transition is
    correct.
    """
    szl_receipt = _require_szl_receipt()
    body = build_mesh_receipt_body(
        stmt, policy_id=policy_id, quorum_id=quorum_id, witnesses=witnesses
    )
    receipt = szl_receipt.Receipt(kind=RECEIPT_KIND, body=body)
    return szl_receipt.sign_receipt(
        receipt, private_key_pem, organ=organ, keyid=keyid
    )


def emit_mesh_receipt_from_dsse(
    dsse_receipt: Dict[str, Any],
    *,
    private_key_pem: Optional[str | bytes] = None,
    policy_id: str = DEFAULT_POLICY_ID,
    quorum_id: Optional[str] = None,
    organ: str = DEFAULT_ORGAN,
    keyid: str = "",
    witnesses: Optional[List[Any]] = None,
) -> Dict[str, Any]:
    """Fold an existing mesh DSSE receipt onto a canonical szl-receipt.

    Decodes the embedded StateTransitionStatement from the existing DSSE
    envelope (:func:`szl_mesh.receipts.build_dsse_receipt`) and emits the
    canonical binding for it. Additive: the original DSSE receipt is untouched.
    """
    stmt = decode_statement(dsse_receipt)
    return emit_mesh_receipt(
        stmt,
        private_key_pem=private_key_pem,
        policy_id=policy_id,
        quorum_id=quorum_id,
        organ=organ,
        keyid=keyid,
        witnesses=witnesses,
    )


def verify_mesh_receipt(
    envelope: Dict[str, Any],
    *,
    public_key_pem: Optional[str | bytes] = None,
    stmt: Optional[Dict[str, Any]] = None,
    policy_id: str = DEFAULT_POLICY_ID,
    quorum_id: Optional[str] = None,
    witnesses: Optional[List[Any]] = None,
) -> Tuple[bool, str]:
    """Verify a canonical mesh receipt (and optionally rebind it).

    Delegates the cryptographic check to :func:`szl_receipt.verify_receipt`
    (keyless envelopes honestly return ``(False, "unsigned-honest")``). When
    ``stmt`` is supplied, additionally confirms the signed body's
    ``input_digest`` / ``output_digest`` re-derive from that statement — so any
    post-hoc edit to the transition flips a digest and fails the rebind.
    """
    szl_receipt = _require_szl_receipt()
    ok, detail = szl_receipt.verify_receipt(envelope, public_key_pem=public_key_pem)
    if not ok:
        return ok, detail

    if stmt is not None:
        import base64
        import json

        try:
            body = json.loads(base64.b64decode(envelope["payload"]).decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            return False, f"payload decode error: {exc}"
        if body.get("input_digest") != transition_input_digest(stmt):
            return False, "input-digest-rebind-mismatch"
        if body.get("output_digest") != transition_output_digest(stmt):
            return False, "output-digest-rebind-mismatch"

    return True, "ok"
