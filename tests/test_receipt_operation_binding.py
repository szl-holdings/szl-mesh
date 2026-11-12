"""A valid signature must bind the statement to the operation being classified.

Origin: OpenAI Codex, implementing the owner's repository audit.
All signers and formation state are ephemeral local fixtures.
"""

import pytest

from szl_mesh import receipts as rcpt
from szl_mesh.crdt import AUTHORIZED, OBSERVED, Op
from szl_mesh.enrollment import FormationGateway
from szl_mesh.node import MeshNode

DOC = "test/receipt-operation-binding"
FK = b"local-synthetic-binding-fixture"


def _fixture():
    gateway = FormationGateway("test", FK)
    sender, receiver, other = [
        MeshNode(name, DOC) for name in ("sender", "receiver", "other")
    ]
    for node in (sender, receiver, other):
        assert node.enroll(gateway, FK).success
    op = Op(DOC, "state", "ready", 1, sender.node_id)
    statement = rcpt.build_state_transition_statement(
        DOC, op.op_id, [], [op.op_id], sender.node_id,
    )
    return sender, receiver, other, op, statement


def _signed(sender, op, statement):
    envelope = rcpt.build_dsse_receipt(statement, sender._priv)
    # Every negative case has a real, self-consistent signature.
    assert rcpt.verify_receipt_signature(envelope) is True
    return {"op_obj": op, "receipt": envelope}


def _assert_observed(receiver, record, status):
    result = receiver.apply_remote(record)
    assert result["track"] == OBSERVED
    assert result["receipt_status"] == status
    assert receiver.authorized_state() == {}
    assert receiver.observed_state() == {"state": "ready"}
    assert receiver.verify_ledger() == (1, 1)


def test_signed_statement_for_another_document_does_not_authorize():
    sender, receiver, _, op, statement = _fixture()
    statement["crdt_document_id"] = "other/document"
    _assert_observed(receiver, _signed(sender, op, statement), "CONTEXT_MISMATCH")


def test_enrolled_signer_cannot_attribute_operation_to_another_node():
    sender, receiver, other, _, statement = _fixture()
    op = Op(DOC, "state", "ready", 1, other.node_id)
    statement["change_hash"] = op.op_id
    statement["to_state_head"] = [op.op_id]
    _assert_observed(receiver, _signed(sender, op, statement), "CONTEXT_MISMATCH")


@pytest.mark.parametrize(("field", "value"), [
    ("type", "other-statement"),
    ("type", None),
    ("crdt_document_id", None),
    ("crdt_document_id", ""),
    ("transition_class", "OTHER"),
    ("transition_class", []),
    ("transition_class", None),
    ("from_state_head", None),
    ("from_state_head", "heads"),
    ("from_state_head", [None]),
    ("to_state_head", {}),
    ("to_state_head", [""]),
])
def test_signed_invalid_statement_remains_observed(field, value):
    sender, receiver, _, op, statement = _fixture()
    statement[field] = value
    _assert_observed(receiver, _signed(sender, op, statement), "BAD_STATEMENT")


@pytest.mark.parametrize("level", [None, "L2", True])
def test_signed_slsa_claim_must_match_runtime_contract(level):
    sender, receiver, _, op, statement = _fixture()
    statement["policy_context"]["slsa_level"] = level
    _assert_observed(receiver, _signed(sender, op, statement), "BAD_STATEMENT")


def test_signed_statement_requires_type():
    sender, receiver, _, op, statement = _fixture()
    del statement["type"]
    _assert_observed(receiver, _signed(sender, op, statement), "BAD_STATEMENT")


def test_valid_statement_for_operation_remains_authorized():
    sender, receiver, _, op, statement = _fixture()
    result = receiver.apply_remote(_signed(sender, op, statement))
    assert result["track"] == AUTHORIZED
    assert result["receipt_status"] == rcpt.RECEIPT_VALID
    assert receiver.authorized_state() == {"state": "ready"}


def test_concurrent_receiver_heads_need_not_match_sender_heads():
    sender, receiver, _, op, statement = _fixture()
    receiver.write("concurrent", "local")
    assert receiver.doc.heads() != statement["from_state_head"]
    result = receiver.apply_remote(_signed(sender, op, statement))
    assert result["track"] == AUTHORIZED
    assert receiver.authorized_state() == {"concurrent": "local", "state": "ready"}
