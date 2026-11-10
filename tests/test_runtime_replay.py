"""Retained authority survives invalid replay only while its evidence is valid.

Origin: OpenAI Codex, implementing the owner's repository audit.
All signing keys and formation state are ephemeral local test fixtures.
"""

from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from szl_mesh import node as node_module
from szl_mesh import receipts as rcpt
from szl_mesh.crdt import AUTHORIZED, OBSERVED, Op
from szl_mesh.enrollment import FormationGateway
from szl_mesh.node import MeshNode


@pytest.fixture
def formation(monkeypatch):
    class Clock(datetime):
        instant = datetime.now(timezone.utc).replace(microsecond=0)

        @classmethod
        def now(cls, tz=None):
            return cls.instant if tz else cls.instant.replace(tzinfo=None)

    monkeypatch.setattr(node_module, "datetime", Clock)
    monkeypatch.setattr(rcpt, "datetime", Clock)
    gateway = FormationGateway("replay-fixture", b"synthetic-formation-key")
    sender, receiver = [MeshNode(name, "test/replay") for name in ("sender", "receiver")]
    for node in (sender, receiver):
        assert node.enroll(gateway, b"synthetic-formation-key").success
    record = sender.write("status", {"value": "ready"})
    return sender, receiver, gateway, record, Clock


def _replay(record, receipt=None):
    return {"op_obj": record["op_obj"], "receipt": receipt}


@pytest.mark.parametrize("kind", ["missing", "bad-signature", "wrong-doctrine", "unretainable"])
def test_invalid_replay_preserves_currently_valid_retained_authority(formation, kind):
    sender, receiver, _, record, _ = formation
    assert receiver.apply_remote(record)["track"] == AUTHORIZED
    retained = deepcopy(receiver.receipt_ledger)
    envelope = deepcopy(record["receipt"])
    if kind == "missing":
        envelope = None
    elif kind == "bad-signature":
        envelope["signatures"][0]["sig"] = "AAAA"
    elif kind == "wrong-doctrine":
        statement = rcpt.decode_statement(envelope)
        statement["doctrine_version"] = "invalid"
        envelope = rcpt.build_dsse_receipt(statement, sender._priv)
    else:
        for _ in range(600):
            envelope = {"nested": envelope}
    result = receiver.apply_remote(_replay(record, envelope))
    assert result["track"] == AUTHORIZED
    assert result["receipt_status"] == rcpt.RECEIPT_VALID
    assert result["incoming_receipt_status"] != rcpt.RECEIPT_VALID
    assert result["used_retained_receipt"] is True
    assert result["newly_added"] is False
    assert receiver.receipt_ledger == retained
    assert receiver.authorized_state() == {"status": {"value": "ready"}}
    assert receiver.verify_ledger() == (1, 1)


@pytest.mark.parametrize("boundary", [-5, 5])
def test_retained_receipt_checks_inclusive_clock_boundary(formation, boundary):
    _, receiver, _, record, clock = formation
    receiver.apply_remote(record)
    clock.instant += timedelta(seconds=boundary)
    assert receiver.apply_remote(_replay(record))["track"] == AUTHORIZED


@pytest.mark.parametrize("change", ["expiry", "revocation", "lost-signer", "lost-gateway", "tamper", "wrong-hash"])
def test_stale_or_untrusted_retained_receipt_cannot_rescue_replay(formation, change):
    sender, receiver, gateway, record, clock = formation
    receiver.apply_remote(record)
    if change == "expiry":
        clock.instant += timedelta(seconds=6)
    elif change == "revocation":
        gateway.revoke(sender.node_id)
    elif change == "lost-signer":
        del gateway.cert_store[sender.node_id]
    elif change == "lost-gateway":
        receiver._gateway = None
    elif change == "tamper":
        receiver.receipt_ledger[record["change_hash"]]["signatures"][0]["sig"] = "AAAA"
    else:
        other = sender.write("other", "value")
        receiver.receipt_ledger[record["change_hash"]] = other["receipt"]
    retained = deepcopy(receiver.receipt_ledger)
    result = receiver.apply_remote(_replay(record))
    assert result["track"] == OBSERVED
    assert receiver.authorized_state() == {}
    assert receiver.observed_state() == {"status": {"value": "ready"}}
    assert receiver.receipt_ledger == retained


def test_clock_rollback_does_not_implicitly_upgrade_observed_operation(formation):
    _, receiver, _, record, clock = formation
    receiver.apply_remote(record)
    clock.instant += timedelta(seconds=6)
    assert receiver.apply_remote(_replay(record))["track"] == OBSERVED
    clock.instant -= timedelta(seconds=6)
    assert receiver.apply_remote(_replay(record))["track"] == OBSERVED
    assert receiver.authorized_state() == {}
    # An actual valid re-issuance can restore authority.
    assert receiver.apply_remote(record)["track"] == AUTHORIZED


def test_replay_cannot_erase_first_observed_evidence(formation):
    sender, receiver, _, record, _ = formation
    statement = rcpt.decode_statement(record["receipt"])
    statement["doctrine_version"] = "invalid"
    first = rcpt.build_dsse_receipt(statement, sender._priv)
    assert receiver.apply_remote(_replay(record, first))["track"] == OBSERVED
    retained = deepcopy(receiver.receipt_ledger)
    assert receiver.apply_remote(_replay(record, {"malformed": True}))["track"] == OBSERVED
    assert receiver.receipt_ledger == retained
    assert receiver.apply_remote(record)["track"] == AUTHORIZED
    assert receiver.receipt_ledger[record["change_hash"]] == record["receipt"]


def test_incoming_authorized_label_never_replaces_local_validation(formation):
    _, receiver, _, record, _ = formation
    op = record["op_obj"]
    remote_claim = Op(op.doc_id, op.key, op.value, op.lamport, op.node_id, track=AUTHORIZED)
    result = receiver.apply_remote({"op_obj": remote_claim})
    assert result["track"] == OBSERVED
    assert receiver.authorized_state() == {}


def test_local_write_retained_evidence_is_also_revalidated(formation):
    sender, _, gateway, record, _ = formation
    assert sender.apply_remote(_replay(record))["track"] == AUTHORIZED
    gateway.revoke(sender.node_id)
    assert sender.apply_remote(_replay(record))["track"] == OBSERVED


def test_valid_reissuance_replaces_old_evidence(formation):
    sender, receiver, _, record, clock = formation
    receiver.apply_remote(record)
    clock.instant += timedelta(seconds=6)
    statement = rcpt.decode_statement(record["receipt"])
    statement["timestamp_utc"] = rcpt.utc_now_iso()
    fresh = rcpt.build_dsse_receipt(statement, sender._priv)
    assert receiver.apply_remote(_replay(record, fresh))["track"] == AUTHORIZED
    assert receiver.receipt_ledger[record["change_hash"]] == fresh
