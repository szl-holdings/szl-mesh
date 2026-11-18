# SPDX-License-Identifier: Apache-2.0
"""Offline persistence, partition convergence, and fail-closed authority tests."""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from szl_mesh.chronicle import (  # noqa: E402
    ChronicleIntegrityError, MeshChronicle, MAX_BATCH, MAX_EVIDENCE_PER_OP,
)
from szl_mesh.crdt import AUTHORIZED, OBSERVED, Op  # noqa: E402
from szl_mesh.enrollment import FormationGateway  # noqa: E402
from szl_mesh.node import MeshNode  # noqa: E402


@pytest.fixture
def fleet():
    key = b"szl-mesh-offline-test-key-not-deployment"
    gateway = FormationGateway("isolated-test", key)
    first = MeshNode("first", "mesh/test")
    second = MeshNode("second", "mesh/test")
    assert first.enroll(gateway, key).success
    assert second.enroll(gateway, key).success
    return gateway, first, second


def test_reopen_and_revalidate_actionable_track(tmp_path, fleet):
    gateway, first, _ = fleet
    path = tmp_path / "chronicle.db"
    record = first.write("status", {"ready": True})
    with MeshChronicle(path) as store:
        result = store.ingest_record(record)
        assert result["op_new"] and result["evidence_new"]
        assert result["admission"] == "UNVERIFIED_AT_INGEST"
        assert not result["release_authority"]
        assert store.state("mesh/test", track=OBSERVED) == {"status": {"ready": True}}
        # No independent public-key trust makes a signature self-authorizing.
        assert store.state("mesh/test", track=AUTHORIZED) == {}
        assert store.state("mesh/test", track=AUTHORIZED,
                           registry=gateway.pubkey_registry()) == {}
        assert store.state("mesh/test", track=AUTHORIZED,
                           registry=gateway.pubkey_registry(), revoked=gateway.revoked) == {
                               "status": {"ready": True}}
        verified = store.verify_integrity()
        assert verified["events"] == 2
        assert verified["status"] == "LOCAL_INTEGRITY_VERIFIED"
        assert verified["signed"] is False
        assert store.tip()["external_anchor"] == "UNAVAILABLE"
    with MeshChronicle(path) as reopened:
        assert reopened.state("mesh/test", track=AUTHORIZED,
                              registry=gateway.pubkey_registry(), revoked=gateway.revoked) == {
                                  "status": {"ready": True}}


def test_duplicate_ingest_is_idempotent_and_replay_does_not_demote(tmp_path, fleet):
    gateway, first, _ = fleet
    original = first.write("k", "good")
    altered = copy.deepcopy(original)
    altered["receipt"] = {"payloadType": "invalid", "payload": "no"}
    with MeshChronicle(tmp_path / "idempotent.db") as db:
        assert db.ingest_record(original)["op_new"]
        start = db.tip()
        repeated = db.ingest_record(original)
        assert not repeated["op_new"] and not repeated["evidence_new"]
        assert db.tip() == start
        assert db.ingest_record(altered)["evidence_new"]
        assert db.state("mesh/test", track=AUTHORIZED,
                        registry=gateway.pubkey_registry(), revoked=gateway.revoked) == {"k": "good"}


def test_expired_and_revoked_receipts_are_never_stored_authority(tmp_path, fleet):
    gateway, first, _ = fleet
    record = first.write("k", 17)
    with MeshChronicle(tmp_path / "time.db") as db:
        db.ingest_record(record)
        assert db.state("mesh/test", track=AUTHORIZED,
                        registry=gateway.pubkey_registry(), revoked=gateway.revoked) == {"k": 17}
        future = datetime.now(timezone.utc) + timedelta(seconds=30)
        assert db.state("mesh/test", track=AUTHORIZED,
                        registry=gateway.pubkey_registry(), revoked=gateway.revoked, now=future) == {}
        assert db.state("mesh/test", now=future) == {"k": 17}
        gateway.revoke(first.node_id)
        assert db.state("mesh/test", track=AUTHORIZED,
                        registry=gateway.pubkey_registry(),
                        revoked=gateway.revoked) == {}
        reason = db.explain("mesh/test", "k", registry=gateway.pubkey_registry(),
                            revoked=gateway.revoked)
        assert reason["candidates"][0]["track"] == OBSERVED
        assert not reason["authorized_view_contains_key"]
        assert reason["signing_state"] == "EVIDENCE_REVALIDATED_NOT_DATABASE_SIGNED"


def test_offline_order_independence_and_import_dedup(tmp_path, fleet):
    gateway, first, second = fleet
    one = first.write("shared", {"node": "first"})
    two = second.write("shared", {"node": "second"})
    with MeshChronicle(tmp_path / "left.db") as left, MeshChronicle(
            tmp_path / "right.db") as right:
        left.ingest_batch([{"op": one["op"], "receipt": one["receipt"]},
                           {"op": two["op"], "receipt": two["receipt"]}])
        right.ingest_batch([{"op": two["op"], "receipt": two["receipt"]},
                            {"op": one["op"], "receipt": one["receipt"]}])
        trust = gateway.pubkey_registry()
        assert left.state_digest("mesh/test") == right.state_digest("mesh/test")
        assert left.state_digest("mesh/test", track=AUTHORIZED, registry=trust, revoked=gateway.revoked) == (
            right.state_digest("mesh/test", track=AUTHORIZED, registry=trust, revoked=gateway.revoked))
        assert left.state("mesh/test", track=OBSERVED) == (
            right.state("mesh/test", track=OBSERVED))
        before = right.tip()
        right.ingest_batch(left.export("mesh/test"))
        assert right.tip() == before
        assert left.tip()["hash"] != right.tip()["hash"]  # local ingestion order


def test_transaction_batch_rolls_back_all_on_forged_op_id(tmp_path, fleet):
    _, first, _ = fleet
    one, two = first.write("one", 1), first.write("two", 2)
    broken = {"op": copy.deepcopy(two["op"]), "receipt": two["receipt"]}
    broken["op"]["op_id"] = "f" * 64
    with MeshChronicle(tmp_path / "atomic.db") as db:
        with pytest.raises(ValueError):
            db.ingest_batch([{"op": one["op"], "receipt": one["receipt"]}, broken])
        assert db.tip()["sequence"] == 0
        assert db.state("mesh/test") == {}
        assert db.verify_integrity()["events"] == 0


def test_source_track_is_untrusted_and_external_hash_checked(tmp_path):
    forged = Op("doc", "ready", True, 1, "unauthorized")
    value = forged.to_dict()
    value["track"] = AUTHORIZED
    with MeshChronicle(tmp_path / "untrusted.db") as db:
        db.ingest(value)
        assert db.state("doc") == {"ready": True}
        assert db.state("doc", track=AUTHORIZED, registry={}, revoked=set()) == {}
        wrong = dict(value)
        wrong["op_id"] = "0" * 64
        with pytest.raises(ValueError):
            db.ingest(wrong)
        assert db.verify_integrity()["events"] == 1


def test_exact_local_ingest_time_travel_not_historical_authority(tmp_path, fleet):
    gateway, first, _ = fleet
    with MeshChronicle(tmp_path / "historical.db") as db:
        db.ingest_record(first.write("phase", "one"))
        prior = db.tip()["sequence"]
        db.ingest_record(first.write("phase", "two"))
        assert db.state("mesh/test") == {"phase": "two"}
        assert db.state("mesh/test", at_seq=prior) == {"phase": "one"}
        assert db.state("mesh/test", track=AUTHORIZED, at_seq=prior,
                        registry=gateway.pubkey_registry(), revoked=gateway.revoked) == {"phase": "one"}
        future = datetime.now(timezone.utc) + timedelta(minutes=1)
        assert db.state("mesh/test", at_seq=prior, track=AUTHORIZED,
                        registry=gateway.pubkey_registry(), revoked=gateway.revoked, now=future) == {}
        with pytest.raises(ValueError):
            db.state("mesh/test", at_seq=-1)
        with pytest.raises(ValueError):
            db.state("mesh/test", at_seq=True)


def test_sql_injection_values_are_literals(tmp_path):
    odd_doc = "doc'); DELETE FROM operations; --"
    odd_key = "k'); DROP TABLE evidence; --"
    with MeshChronicle(tmp_path / "escaped.db") as db:
        db.ingest(Op(odd_doc, odd_key, {"literal": "'; SQL"}, 1, "peer"))
        assert db.state(odd_doc) == {odd_key: {"literal": "'; SQL"}}
        assert db.verify_integrity()["events"] == 1


def test_immutable_database_rows_and_reopen_integrity_detection(tmp_path):
    path = tmp_path / "protected.db"
    with MeshChronicle(path) as db:
        record = Op("doc", "key", "value", 1, "peer")
        db.ingest(record)
        with pytest.raises(sqlite3.DatabaseError):
            db._db.execute("UPDATE operations SET key_name='tampered'")
        assert db.verify_integrity()["events"] == 1
    with sqlite3.connect(path) as external:
        external.execute("DROP TRIGGER immutable_ops_update")
        external.execute("UPDATE operations SET op_json=?", (b'{"changed":true}',))
        external.commit()
    with pytest.raises(ChronicleIntegrityError):
        MeshChronicle(path)


def test_bounded_batch_and_op_validation(tmp_path):
    with MeshChronicle(tmp_path / "bounds.db") as db:
        with pytest.raises(ValueError):
            db.ingest_batch([{}] * (MAX_BATCH + 1))
        with pytest.raises(ValueError):
            db.ingest(Op("doc", "nonfinite", float("nan"), 1, "peer"))
        with pytest.raises(ValueError):
            db.ingest({"doc_id": "doc", "key": "k", "node_id": "peer",
                       "value": 1, "lamport": True})
        with pytest.raises(ValueError):
            db.ingest({"doc_id": "doc", "key": "k", "node_id": "peer",
                       "value": 1, "lamport": -1})
        with pytest.raises(ValueError):
            db.state("doc", track="ALLEGED_AUTHORITY")
        assert db.tip()["sequence"] == 0


def test_evidence_fanout_capped_without_invented_authority(tmp_path):
    op = Op("doc", "k", 1, 1, "untrusted")
    with MeshChronicle(tmp_path / "bounded.db") as db:
        db.ingest(op)
        for idx in range(MAX_EVIDENCE_PER_OP):
            db.ingest(op, receipt={"payload": str(idx), "arbitrary": "untrusted"})
        with pytest.raises(ValueError):
            db.ingest(op, receipt={"payload": "last"})
        assert db.state("doc", track=AUTHORIZED, registry={}, revoked=set()) == {}
        assert db.verify_integrity()["events"] == 1 + MAX_EVIDENCE_PER_OP

def test_meshnode_opt_in_durable_write_and_peer_ingest(tmp_path):
    key = b"synthetic-test-key-not-a-live-formation"
    gateway = FormationGateway("chronicle-opt-in-test", key)
    with MeshChronicle(tmp_path / "attached.db") as db:
        first = MeshNode("alpha", "attached/document", chronicle=db)
        second = MeshNode("bravo", "attached/document", chronicle=db)
        assert first.enroll(gateway, key).success
        assert second.enroll(gateway, key).success
        first_write = first.write("active", {"node": "first"})
        assert first_write["track"] == AUTHORIZED
        assert db.state("attached/document", track=OBSERVED) == {
            "active": {"node": "first"}}
        # Remote ingestion must also durably commit before in-memory mutation.
        peer_write = second.write("peer", {"node": "second"})
        assert first.apply_remote(peer_write)["track"] == AUTHORIZED
        assert db.state("attached/document", track=AUTHORIZED,
                        registry=gateway.pubkey_registry(),
                        revoked=gateway.revoked) == {
            "active": {"node": "first"}, "peer": {"node": "second"}}
        assert db.verify_integrity()["events"] == 4


def test_attached_meshnode_durability_failure_blocks_local_mutation(tmp_path):
    key = b"synthetic-fail-closed-formation"
    gateway = FormationGateway("fail-closed", key)
    db = MeshChronicle(tmp_path / "closed.db")
    first = MeshNode("alpha", "durable/doc", chronicle=db)
    second = MeshNode("beta", "durable/doc")
    assert first.enroll(gateway, key).success
    assert second.enroll(gateway, key).success
    remote = second.write("remote", 3)
    before = first.state_digest()
    db.close()
    with pytest.raises(sqlite3.ProgrammingError):
        first.write("blocked", 42)
    assert first.state_digest() == before
    assert first.doc.all_ops() == []
    assert first._lamport == 0
    assert first.receipt_ledger == {}
    with pytest.raises(sqlite3.ProgrammingError):
        first.apply_remote(remote)
    assert first.state_digest() == before
    assert first._lamport == 0

def test_replay_to_empty_unenrolled_node_recovers_observed_only(tmp_path, fleet):
    gateway, first, _ = fleet
    db_path = tmp_path / "recovery.db"
    with MeshChronicle(db_path) as db:
        db.ingest_record(first.write("recovered", {"value": 9}))
    recovered = MeshNode("fresh-identity", "mesh/test")
    with MeshChronicle(db_path) as db:
        outcome = db.replay_to(recovered)
        assert outcome["new_ops"] == 1
        assert outcome["signing_identity_restored"] is False
        assert outcome["enrollment_restored"] is False
        assert recovered.observed_state() == {"recovered": {"value": 9}}
        assert recovered.authorized_state() == {}
        assert not recovered.enrolled
        assert recovered.node_id != first.node_id
        with pytest.raises(ValueError):
            db.replay_to(first)  # already enrolled and populated
        assert gateway.pubkey_registry()[first.node_id] == first.public_key_der()

def test_local_cli_demo_and_existing_file_verify(tmp_path, capsys):
    from szl_mesh.chronicle_demo import demo, main
    result = demo(":memory:")
    assert result["result"] == "SIMULATED_LOCAL_PASS"
    assert result["remote_mesh_connected"] is False
    assert result["production_release_ready"] is False
    assert result["authorized_keys_without_trust"] == 0
    path = tmp_path / "synthetic.sqlite"
    assert main(["--demo", "--db", str(path)]) == 0
    with MeshChronicle(path) as db:
        assert db.verify_integrity()["events"] == 4
    assert main(["--verify-only", "--db", str(path)]) == 0
    assert "LOCAL_INTEGRITY_VERIFIED" in capsys.readouterr().out
    missing = tmp_path / "nonexistent.sqlite"
    assert main(["--verify-only", "--db", str(missing)]) == 2
    captured = capsys.readouterr()
    assert "CHRONICLE_UNAVAILABLE" in captured.err
    assert str(missing) not in captured.err
    assert not missing.exists()

def test_read_only_mode_refuses_every_database_mutation(tmp_path):
    path = tmp_path / "readonly.sqlite"
    with MeshChronicle(path) as writer:
        writer.ingest(Op("doc", "one", 1, 1, "local"))
    with MeshChronicle(path, readonly=True) as reader:
        assert reader.state("doc") == {"one": 1}
        assert reader.verify_integrity()["events"] == 1
        with pytest.raises(PermissionError):
            reader.ingest(Op("doc", "two", 2, 2, "local"))
        with pytest.raises(sqlite3.OperationalError):
            reader._db.execute("CREATE TABLE unauthorized_table(x TEXT)")
    with pytest.raises(ValueError):
        MeshChronicle(tmp_path / "notfound.sqlite", readonly=True)

def test_causal_proof_graph_is_bounded_and_does_not_invent_consensus(tmp_path, fleet):
    gateway, first, _ = fleet
    with MeshChronicle(tmp_path / "causal.db") as db:
        root = first.write("hidden-work-item", {"PRIVATE_SOURCE": "secret-value"})
        db.ingest_record(root)
        boundary = db.tip()["sequence"]
        child = first.write("linked-work-item", "done")
        db.ingest_record(child)
        graph = db.causal_graph("mesh/test", registry=gateway.pubkey_registry(),
                                revoked=gateway.revoked)
        assert graph["node_count"] == 2
        assert graph["edge_count"] == 1
        assert graph["edges"][0]["from"] == root["change_hash"]
        assert graph["edges"][0]["to"] == child["change_hash"]
        assert graph["edges"][0]["evidence"] == "TRUSTED_SIGNER_ASSERTION"
        assert graph["source_deployment_parity"] == "UNKNOWN"
        assert graph["byzantine_agreement_proven"] is False
        assert graph["signature_state"] == "UNSIGNED_LOCAL_STRUCTURAL_HASH"
        assert "secret-value" not in str(graph)
        assert graph == db.causal_graph("mesh/test", registry=gateway.pubkey_registry(),
                                         revoked=gateway.revoked)
        untrusted = db.causal_graph("mesh/test")
        assert untrusted["edges"][0]["evidence"] == "UNVERIFIED_ASSERTION"
        expired = db.causal_graph(
            "mesh/test", registry=gateway.pubkey_registry(),
            revoked=gateway.revoked,
            now=datetime.now(timezone.utc) + timedelta(seconds=30),
        )
        assert expired["edges"][0]["evidence"] == "UNVERIFIED_ASSERTION"
        previous = db.causal_graph("mesh/test", at_seq=boundary)
        assert previous["node_count"] == 1
        assert previous["edge_count"] == 0

def test_bounded_concurrent_ingestion_and_recovery(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    path = tmp_path / "parallel.sqlite"
    records = [Op("concurrent/doc", f"key-{index:03d}", index,
                  index + 1, f"peer-{index % 4}")
               for index in range(128)]
    with MeshChronicle(path) as db:
        def write(index):
            return db.ingest(records[index % len(records)])
        # Retransmissions across four workers must not duplicate event rows.
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(write, range(256)))
        assert sum(result["op_new"] for result in results) == 128
        assert db.verify_integrity()["events"] == 128
        assert len(db.state("concurrent/doc")) == 128
        assert db.state("concurrent/doc", track=AUTHORIZED, registry={},
                        revoked=set()) == {}
    with MeshChronicle(path, readonly=True) as reader:
        assert reader.verify_integrity()["events"] == 128
        assert len(reader.state("concurrent/doc")) == 128
