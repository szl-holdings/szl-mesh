"""Nested values must not change a receipted state outside a new operation."""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from szl_mesh.crdt import AUTHORIZED, CRDTDocument, Op
from szl_mesh.enrollment import FormationGateway
from szl_mesh.node import MeshNode


def nested_value():
    return {"routes": [{"enabled": False}], "owners": ["original"]}


def change(value):
    value["routes"][0]["enabled"] = True
    value["owners"].append("unreceipted")


def test_operation_snapshots_nested_constructor_input():
    value = nested_value()
    op = Op("doc", "policy", value, 1, "node", track=AUTHORIZED)
    original_bytes, original_id = op.raw_bytes(), op.op_id
    change(value)
    assert op.value == nested_value()
    assert op.raw_bytes() == original_bytes
    assert op.op_id == original_id


@pytest.mark.parametrize("boundary", ["input_op", "authorized_view", "observed_view", "all_ops"])
def test_document_isolates_mutable_value_boundaries(boundary):
    doc = CRDTDocument("doc")
    op = Op("doc", "policy", nested_value(), 1, "node", track=AUTHORIZED)
    doc.add_op(op)
    original_digest, original_heads = doc.state_digest(), doc.heads()
    values = {
        "input_op": lambda: op.value,
        "authorized_view": lambda: doc.authorized_view()["policy"],
        "observed_view": lambda: doc.observed_view()["policy"],
        "all_ops": lambda: doc.all_ops()[0].value,
    }
    change(values[boundary]())
    assert doc.authorized_view() == {"policy": nested_value()}
    assert doc.state_digest() == original_digest
    assert doc.heads() == original_heads
    assert len(doc) == 1


def test_dictionary_export_does_not_alias_operation():
    op = Op("doc", "policy", nested_value(), 1, "node")
    original_id = op.op_id
    change(op.to_dict()["value"])
    assert op.value == nested_value()
    assert op.op_id == original_id


@pytest.mark.parametrize("value, expected_id", [
    (None, "3cd6a327188ec44e612be8a0c83b57e27f9f447fd0acd17c51a7d4cce2bbd978"),
    (True, "38f54d276e3e76f4e8cea36edd4738cafac381d77371514c267ae44523d38dfa"),
    (3.5, "75045fe5483da2582a67f542a000aadb157d0c78294380958dd09a313eabf349"),
    ({"unicode": "λ café", "nested": [1, {"flags": (True, False, None)}]},
     "a5e0c224d623918acae16a97d3d926f760b185872e72efbcfdb08036c918bca4"),
])
def test_existing_value_encoding_and_identity_are_preserved(value, expected_id):
    # Golden identities captured from the unchanged base implementation.
    op = Op("doc", "policy", value, 1, "node", track=AUTHORIZED)
    doc = CRDTDocument("doc")
    doc.add_op(op)
    assert op.op_id == expected_id
    assert hashlib.sha256(op.raw_bytes()).hexdigest() == expected_id
    assert doc.authorized_view() == {"policy": value}
    assert doc.all_ops()[0].raw_bytes() == op.raw_bytes()


def test_nonserializable_value_does_not_partially_append():
    doc = CRDTDocument("doc")
    doc.add_op(Op("doc", "existing", nested_value(), 1, "node", track=AUTHORIZED))
    original_heads, original_digest = doc.heads(), doc.state_digest()
    with pytest.raises(TypeError):
        doc.add_op(Op("doc", "invalid", object(), 2, "node", track=AUTHORIZED))
    assert len(doc) == 1
    assert doc.heads() == original_heads
    assert doc.state_digest() == original_digest


def test_nested_receipted_state_stays_bound_across_peer_sync_and_reads():
    key = b"test-only-formation-key"
    gateway = FormationGateway("formation", key)
    sender, receiver = MeshNode("sender", "doc"), MeshNode("receiver", "doc")
    assert sender.enroll(gateway, key).success
    assert receiver.enroll(gateway, key).success
    value = nested_value()
    record = sender.write("policy", value)
    original_hash = record["change_hash"]
    change(value)
    # The signed operation still contains the bytes originally supplied to write.
    assert hashlib.sha256(record["op_obj"].raw_bytes()).hexdigest() == original_hash
    assert receiver.apply_remote(record)["track"] == AUTHORIZED
    original_digest = sender.state_digest()
    change(sender.authorized_state()["policy"])
    change(receiver.doc.all_ops()[0].value)
    change(record["op"]["value"])
    assert sender.authorized_state() == receiver.authorized_state() == {"policy": nested_value()}
    assert sender.state_digest() == receiver.state_digest() == original_digest
    # A fresh accepted operation can still deliberately update the same nested value.
    update = sender.write("policy", value)
    assert update["change_hash"] != original_hash
    assert receiver.apply_remote(update)["track"] == AUTHORIZED
    assert sender.authorized_state() == receiver.authorized_state() == {"policy": value}
    assert sender.verify_ledger() == receiver.verify_ledger() == (2, 2)
