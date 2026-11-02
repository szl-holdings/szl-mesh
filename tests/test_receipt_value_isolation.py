# SPDX-License-Identifier: Apache-2.0
# AI-assisted regression tests for retained receipt ownership.
"""Caller and peer mutations cannot rewrite already admitted receipt history."""

from copy import deepcopy

import pytest

from szl_mesh.crdt import AUTHORIZED, OBSERVED
from szl_mesh.enrollment import FormationGateway
from szl_mesh.node import MeshNode


def nodes(count=2):
    formation_key = b"receipt-value-isolation-test-only"
    gateway = FormationGateway("receipt-isolation", formation_key)
    result = [MeshNode(f"node-{i}", "receipt-isolation/doc") for i in range(count)]
    for node in result:
        assert node.enroll(gateway, formation_key).success
    return result


def test_write_result_payload_mutation_does_not_rewrite_signed_history():
    sender, = nodes(1)
    record = sender.write("mode", "ready")
    original = deepcopy(record["receipt"])
    record["receipt"]["payload"] = "invalid"
    sender.write("mode", "running")
    assert sender.verify_ledger() == (2, 2)
    assert sender.receipt_ledger[record["change_hash"]] == original
    assert sender.authorized_state() == {"mode": "running"}


def test_nested_signature_export_mutation_does_not_rewrite_signed_history():
    sender, = nodes(1)
    record = sender.write("mode", "ready")
    original = deepcopy(record["receipt"])
    record["receipt"]["signatures"][0]["sig"] = "invalid"
    record["receipt"]["signatures"].append({"keyid": "untrusted"})
    assert sender.verify_ledger() == (1, 1)
    assert sender.receipt_ledger[record["change_hash"]] == original


def test_received_record_mutation_preserves_sender_and_receiver_receipts():
    sender, receiver = nodes()
    record = sender.write("mode", "ready")
    original = deepcopy(record["receipt"])
    assert receiver.apply_remote(record)["track"] == AUTHORIZED
    record["receipt"]["signatures"].clear()
    assert sender.verify_ledger() == receiver.verify_ledger() == (1, 1)
    assert receiver.receipt_ledger[record["change_hash"]] == original
    assert receiver.authorized_state() == sender.authorized_state() == {"mode": "ready"}


def test_one_peers_ledger_cannot_mutate_another_peers_history():
    sender, first, second = nodes(3)
    record = sender.write("mode", "ready")
    first.apply_remote(record)
    second.apply_remote(record)
    first.receipt_ledger[record["change_hash"]]["signatures"][0]["sig"] = "invalid"
    assert first.verify_ledger() == (0, 1)
    assert second.verify_ledger() == sender.verify_ledger() == (1, 1)


def test_invalid_received_receipt_cannot_be_repaired_by_caller_mutation():
    sender, receiver = nodes()
    record = sender.write("mode", "ready")
    invalid = deepcopy(record)
    invalid["receipt"]["signatures"][0]["sig"] = "invalid"
    assert receiver.apply_remote(invalid)["track"] == OBSERVED
    invalid["receipt"]["signatures"][0]["sig"] = record["receipt"]["signatures"][0]["sig"]
    assert receiver.verify_ledger() == (0, 1)
    assert receiver.authorized_state() == {}
    assert receiver.observed_state() == {"mode": "ready"}
    # Only explicit re-admission of a valid envelope can upgrade the operation.
    assert receiver.apply_remote(record)["track"] == AUTHORIZED
    assert receiver.verify_ledger() == (1, 1)


def test_valid_receipt_bytes_and_reissuance_remain_unchanged():
    sender, receiver = nodes()
    record = sender.write("mode", "ready")
    original = deepcopy(record["receipt"])
    first = receiver.apply_remote(record)
    second = receiver.apply_remote(record)
    assert first["newly_added"] is True
    assert second["newly_added"] is False
    assert first["track"] == second["track"] == AUTHORIZED
    assert sender.receipt_ledger[record["change_hash"]] == original
    assert receiver.receipt_ledger[record["change_hash"]] == original
    assert receiver.verify_ledger() == sender.verify_ledger() == (1, 1)


def test_missing_receipt_stays_observed_without_creating_evidence():
    sender, receiver = nodes()
    record = sender.write("mode", "ready")
    record.pop("receipt")
    assert receiver.apply_remote(record)["track"] == OBSERVED
    assert receiver.receipt_ledger == {}
    assert receiver.authorized_state() == {}
    assert receiver.observed_state() == {"mode": "ready"}


@pytest.mark.parametrize("valid_envelope", [False, True])
def test_unretainable_nested_envelope_stays_observed_without_crashing(valid_envelope):
    sender, receiver = nodes()
    record = sender.write("mode", "ready")
    nested = []
    for _ in range(2000):
        nested = [nested]
    if valid_envelope:
        record["receipt"]["untrusted"] = nested
    else:
        record["receipt"] = {"untrusted": nested}
    assert receiver.apply_remote(record)["track"] == OBSERVED
    assert receiver.authorized_state() == {}
    assert receiver.observed_state() == {"mode": "ready"}
    assert receiver.verify_ledger()[0] == 0
    assert receiver.receipt_ledger == {}
