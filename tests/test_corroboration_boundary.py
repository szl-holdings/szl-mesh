"""Regression controls for soft-safety observations, NOT authenticated consensus."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from szl_mesh.quorum import CorroborationLedger, combined_classification

H = "a" * 64
T0 = datetime(2026, 11, 18, 1, 0, tzinfo=timezone.utc)


def test_original_one_node_threshold_switch_cannot_promote():
    ledger = CorroborationLedger()
    first = ledger.observe(H, "node-1", transition_class="COMMAND")
    assert first["status"] == "PENDING"
    with pytest.raises(ValueError, match="transition_class"):
        ledger.observe(H, "node-1", transition_class="DEPLOYMENT")
    assert ledger.status(H) == "PENDING"
    assert ledger.entries[H]["corroborating_nodes"] == ["node-1"]


def test_default_policy_nested_data_is_not_shared_between_ledgers():
    first, second = CorroborationLedger(), CorroborationLedger()
    first.policies["COMMAND"]["k"] = 1
    assert second.policies["COMMAND"]["k"] == 2


def test_annotation_return_cannot_inject_unverified_extra_witness():
    ledger = CorroborationLedger()
    state = ledger.observe(H, "node-1")
    state["corroborating_nodes"].append("fabricated-peer")
    assert ledger.entries[H]["corroborating_nodes"] == ["node-1"]
    assert ledger.observe(H, "node-1")["status"] == "PENDING"


def test_policy_change_in_existing_entry_requires_new_admission():
    ledger = CorroborationLedger()
    ledger.observe(H, "node-1")
    ledger.policies["PLATFORM_STATUS"]["k"] = 1
    with pytest.raises(ValueError, match="policy"):
        ledger.observe(H, "node-1")
    assert ledger.entries[H]["policy_k"] == 2


@pytest.mark.parametrize("node", ["", "  ", "bad node", "\x00", None, False])
def test_invalid_reporter_identity_never_creates_an_entry(node):
    ledger = CorroborationLedger()
    with pytest.raises(ValueError, match="node_id"):
        ledger.observe(H, node)
    assert not ledger.entries


@pytest.mark.parametrize("identity", ["not-a-digest", "x"*64, "", None, False])
def test_invalid_content_identity_never_creates_an_entry(identity):
    ledger = CorroborationLedger()
    with pytest.raises(ValueError, match="change_hash"):
        ledger.observe(identity, "node-1")
    assert not ledger.entries


def test_unrecognized_class_refuses_before_creating_an_entry():
    ledger = CorroborationLedger()
    with pytest.raises(ValueError, match="transition_class"):
        ledger.observe(H, "node-1", "SUDO_COMMAND")
    assert not ledger.entries


def test_default_window_expires_and_stale_reports_cannot_revive_it():
    ledger = CorroborationLedger()
    first = ledger.observe(H, "node-1", transition_class="COMMAND", now=T0)
    assert first["status"] == "PENDING"
    assert first["window_expires_at"] == (T0 + timedelta(seconds=30)).isoformat()
    assert ledger.status(H, now=T0 + timedelta(seconds=31)) == "FAILED"
    old = ledger.entries[H]["corroborating_nodes"][:]
    stale = ledger.observe(H, "node-2", transition_class="COMMAND", now=T0 + timedelta(seconds=31))
    assert stale["status"] == "FAILED"
    assert stale["corroborating_nodes"] == old
    assert ledger.observe(H, "node-3", transition_class="COMMAND", now=T0 + timedelta(seconds=32))["status"] == "FAILED"


def test_no_time_travel_to_extend_a_window():
    ledger = CorroborationLedger()
    ledger.observe(H, "node-1", now=T0)
    with pytest.raises(ValueError, match="clock"):
        ledger.observe(H, "node-2", now=T0 - timedelta(seconds=1))
    assert ledger.entries[H]["corroborating_nodes"] == ["node-1"]


def test_caller_expiry_cannot_extend_trusted_policy_window():
    ledger = CorroborationLedger()
    with pytest.raises(ValueError, match="window_expires_at"):
        ledger.observe(H, "node-1", now=T0, window_expires_at=(T0+timedelta(days=1)).isoformat())
    assert not ledger.entries


def test_correlated_unverified_node_names_never_grant_operation_authority():
    ledger = CorroborationLedger()
    ledger.observe(H, "reporter-a", now=T0)
    ann = ledger.observe(H, "reporter-b", now=T0+timedelta(seconds=1))
    assert ann["status"] == "CORROBORATED"
    assert ann["identity_verification"] == "UNVERIFIED_NODE_ASSERTIONS"
    assert ann["operational_authority"] is False
    assert "command-ready" not in combined_classification("AUTHORIZED", "CORROBORATED")


def test_corresponding_k1_annotation_is_still_not_a_signature():
    ledger = CorroborationLedger()
    ann = ledger.observe(H, "reported-one", "PACKAGE", now=T0)
    assert ann["policy_k"] == 1
    assert ann["status"] == "CORROBORATED"
    assert ann["identity_verification"] == "UNVERIFIED_NODE_ASSERTIONS"
    assert ann["operational_authority"] is False


def test_mark_failed_stays_failed_after_more_claims():
    ledger = CorroborationLedger()
    ledger.observe(H, "node-1", now=T0)
    ledger.mark_failed(H)
    assert ledger.observe(H, "node-2", now=T0+timedelta(seconds=1))["status"] == "FAILED"
