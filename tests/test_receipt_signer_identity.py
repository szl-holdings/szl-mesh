"""Fail-closed signer identity contracts for DSSE receipts."""

from __future__ import annotations

import copy
import hashlib

import pytest

from szl_mesh import receipts as rcpt
from szl_mesh.crdt import OBSERVED


RAW = b'{"mesh":"identity-binding"}'
DOC = "test-doc/identity-binding"


def _valid_receipt():
    priv, node_id = rcpt.generate_node_keypair()
    change_hash = hashlib.sha256(RAW).hexdigest()
    stmt = rcpt.build_state_transition_statement(
        DOC,
        change_hash,
        [],
        [change_hash],
        node_id,
        "PLATFORM_STATUS",
    )
    return priv, stmt, rcpt.build_dsse_receipt(stmt, priv)


def test_builder_rejects_statement_node_id_not_owned_by_signing_key():
    priv, stmt, _ = _valid_receipt()
    stmt["node_id"] = "f" * 64

    with pytest.raises(ValueError, match="statement node_id"):
        rcpt.build_dsse_receipt(stmt, priv)


def test_keyid_cannot_claim_an_identity_other_than_embedded_signing_key():
    _, _, receipt = _valid_receipt()
    receipt["signatures"][0]["keyid"] = "f" * 64

    assert rcpt.verify_receipt_signature(receipt) is False
    gate = rcpt.validate_receipt(receipt, RAW)
    assert gate.track == OBSERVED
    assert gate.receipt_status == rcpt.RECEIPT_BAD_SIGNATURE


def test_v1_receipt_rejects_ambiguous_multiple_signatures():
    _, _, receipt = _valid_receipt()
    receipt["signatures"].append(copy.deepcopy(receipt["signatures"][0]))

    assert rcpt.verify_receipt_signature(receipt) is False
    gate = rcpt.validate_receipt(receipt, RAW)
    assert gate.track == OBSERVED
    assert gate.receipt_status == rcpt.RECEIPT_BAD_SIGNATURE
