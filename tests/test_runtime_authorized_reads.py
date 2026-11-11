"""Current authority is checked at the MeshNode read boundary.

Origin: OpenAI Codex, implementing the owner's repository audit.
These fixtures sign locally with ephemeral identities and never access a service.
"""

from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from szl_mesh import node as node_module
from szl_mesh import receipts as rcpt
from szl_mesh.crdt import AUTHORIZED, OBSERVED, REVOKED, CRDTDocument
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
    gateway = FormationGateway("read-fixture", b"synthetic-read-key")
    sender, receiver = [MeshNode(name, "test/reads") for name in ("sender", "receiver")]
    for node in (sender, receiver):
        assert node.enroll(gateway, b"synthetic-read-key").success
    record = sender.write("status", {"value": "ready"})
    assert receiver.apply_remote(record)["track"] == AUTHORIZED
    return sender, receiver, gateway, record, Clock


@pytest.mark.parametrize("read", ["state", "digest"])
@pytest.mark.parametrize("change", ["expiry", "future", "revoked", "lost-signer", "lost-gateway", "missing", "tamper", "wrong-hash", "doctrine", "kernel"])
def test_authorized_reads_revalidate_without_another_remote_record(formation, monkeypatch, read, change):
    sender, receiver, gateway, record, clock = formation
    if change in ("expiry", "future"):
        clock.instant += timedelta(seconds=6 if change == "expiry" else -6)
    elif change == "revoked":
        gateway.revoke(sender.node_id)
    elif change == "lost-signer":
        del gateway.cert_store[sender.node_id]
    elif change == "lost-gateway":
        receiver._gateway = None
    elif change == "missing":
        del receiver.receipt_ledger[record["change_hash"]]
    elif change == "tamper":
        receiver.receipt_ledger[record["change_hash"]]["signatures"][0]["sig"] = "AAAA"
    elif change == "wrong-hash":
        receiver.receipt_ledger[record["change_hash"]] = sender.write("other", "value")["receipt"]
    elif change == "doctrine":
        monkeypatch.setattr(rcpt, "DOCTRINE_VERSION", "different")
    else:
        monkeypatch.setattr(rcpt, "KERNEL_COMMIT", "different")
    evidence = deepcopy(receiver.receipt_ledger)
    heads = receiver.doc.heads()
    if read == "state":
        assert receiver.authorized_state() == {}
    else:
        assert receiver.state_digest(AUTHORIZED) == CRDTDocument(receiver.doc_id).state_digest(AUTHORIZED)
    assert receiver.doc.op_track(record["change_hash"]) == OBSERVED
    assert receiver.observed_state() == {"status": {"value": "ready"}}
    assert receiver.doc.heads() == heads
    assert receiver.receipt_ledger == evidence


@pytest.mark.parametrize("boundary", [-5, 0, 5])
def test_read_revalidation_keeps_inclusive_valid_boundaries(formation, boundary):
    _, receiver, _, record, clock = formation
    expected = receiver.state_digest(AUTHORIZED)
    clock.instant += timedelta(seconds=boundary)
    assert receiver.authorized_state() == {"status": {"value": "ready"}}
    assert receiver.state_digest(AUTHORIZED) == expected
    assert receiver.doc.op_track(record["change_hash"]) == AUTHORIZED


def test_read_downgrade_requires_valid_incoming_reissuance_to_restore(formation):
    _, receiver, _, record, clock = formation
    clock.instant += timedelta(seconds=6)
    assert receiver.authorized_state() == {}
    clock.instant -= timedelta(seconds=6)
    assert receiver.authorized_state() == {}
    assert receiver.doc.op_track(record["change_hash"]) == OBSERVED
    assert receiver.apply_remote(record)["track"] == AUTHORIZED
    assert receiver.authorized_state() == {"status": {"value": "ready"}}


def test_read_revalidation_covers_local_writes_and_does_not_relabel_explicit_revocation(formation):
    sender, _, gateway, record, _ = formation
    gateway.revoke(sender.node_id)
    assert sender.authorized_state() == {}
    sender.doc.set_op_track(record["change_hash"], REVOKED)
    assert sender.authorized_state() == {}
    assert sender.doc.op_track(record["change_hash"]) == REVOKED


def test_ledger_signature_success_does_not_imply_current_authority(formation):
    _, receiver, _, _, clock = formation
    observed_digest = receiver.state_digest(OBSERVED)
    clock.instant += timedelta(seconds=6)
    assert receiver.verify_ledger() == (1, 1)
    assert receiver.authorized_state() == {}
    assert receiver.state_digest(OBSERVED) == observed_digest
    assert receiver.verify_ledger() == (1, 1)


def test_authorized_tombstone_expiry_restores_only_currently_authorized_history(formation):
    sender, receiver, _, _, clock = formation
    tombstone = sender.write("status", None, deletion=True)
    receiver.apply_remote(tombstone)
    clock.instant += timedelta(seconds=6)
    newer = sender.write("other", "current")
    receiver.apply_remote(newer)
    assert receiver.authorized_state() == {"other": "current"}
    assert all(op.track == OBSERVED for op in receiver.doc.all_ops() if op.key == "status")


def test_expired_tombstone_no_longer_hides_a_still_valid_value(formation):
    sender, receiver, _, _, clock = formation
    clock.instant -= timedelta(seconds=3)
    receiver.apply_remote(sender.write("status", None, deletion=True))
    clock.instant += timedelta(seconds=6)
    assert receiver.authorized_state() == {"status": {"value": "ready"}}
    assert receiver.observed_state() == {}


def test_all_ops_in_a_read_use_one_validation_instant(formation, monkeypatch):
    sender, receiver, _, _, clock = formation
    receiver.apply_remote(sender.write("other", "value"))
    seen = []
    original = rcpt.validate_receipt

    def inspect(**kwargs):
        seen.append(kwargs["now_utc"])
        clock.instant += timedelta(seconds=1)
        return original(**kwargs)

    monkeypatch.setattr(rcpt, "validate_receipt", inspect)
    assert receiver.authorized_state() == {"status": {"value": "ready"}, "other": "value"}
    assert len(seen) == 2
    assert seen[0] == seen[1]
