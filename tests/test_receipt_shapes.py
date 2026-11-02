"""Untrusted receipt containers fail the gate without crashing peer ingestion."""
import hashlib

import pytest

from szl_mesh import receipts as rcpt
from szl_mesh.crdt import AUTHORIZED, OBSERVED

RAW = b'{"mesh":"shape-boundary"}'


def valid_receipt():
    key, node_id = rcpt.generate_node_keypair()
    stmt = rcpt.build_state_transition_statement(
        "shape-doc", hashlib.sha256(RAW).hexdigest(), [], [], node_id)
    return key, stmt, rcpt.build_dsse_receipt(stmt, key)


@pytest.mark.parametrize("value", [[], 1, True, "receipt"])
def test_nonobject_envelope_fails_closed(value):
    assert rcpt.verify_receipt_signature(value) is False
    assert rcpt.validate_receipt(value, RAW).track == OBSERVED


@pytest.mark.parametrize("value", [None, [], 1, "signature"])
def test_nonobject_signature_fails_closed(value):
    _, _, env = valid_receipt()
    env["signatures"] = [value]
    assert rcpt.verify_receipt_signature(env) is False
    assert rcpt.validate_receipt(env, RAW).track == OBSERVED


@pytest.mark.parametrize("payload", [b"null", b"[]", b"1", b'"statement"', b"[" * 1100])
def test_nonobject_or_excessively_nested_statement_fails_closed(payload):
    _, _, env = valid_receipt()
    env["payload"] = rcpt._b64url_encode(payload)
    assert rcpt.verify_receipt_signature(env) is False
    assert rcpt.validate_receipt(env, RAW).track == OBSERVED


@pytest.mark.parametrize("field,value", [
    ("policy_context", None), ("policy_context", []),
    ("policy_context", {"section_889_vendors": None}),
    ("timestamp_utc", []), ("timestamp_utc", None),
])
def test_signed_malformed_statement_fails_closed(field, value):
    key, stmt, _ = valid_receipt()
    stmt[field] = value
    env = rcpt.build_dsse_receipt(stmt, key)
    assert rcpt.verify_receipt_signature(env) is True
    assert rcpt.validate_receipt(env, RAW).track == OBSERVED


def test_valid_receipt_retains_authorized_gate_result():
    _, _, env = valid_receipt()
    assert rcpt.verify_receipt_signature(env) is True
    result = rcpt.validate_receipt(env, RAW)
    assert result.track == AUTHORIZED
    assert result.receipt_status == rcpt.RECEIPT_VALID
