# SPDX-License-Identifier: Apache-2.0
"""Adversarial finite checks for the two-track CRDT classification join."""
from __future__ import annotations

import itertools
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from szl_mesh.crdt import AUTHORIZED, OBSERVED, REVOKED, CRDTDocument, Op

DOC = "test-doc/track-conflict"
TRACKS = (AUTHORIZED, OBSERVED, REVOKED)


def op(track: str) -> Op:
    return Op(doc_id=DOC, key="machine/availability", value="up",
              lamport=5, node_id="n1", track=track)


def document(track: str) -> CRDTDocument:
    result = CRDTDocument(DOC)
    assert result.add_op(op(track))
    return result


def snapshot(doc: CRDTDocument) -> tuple:
    return (tuple(sorted(doc.authorized_view().items())),
            tuple(sorted(doc.observed_view().items())),
            tuple(doc.heads()),
            doc.state_digest(AUTHORIZED),
            doc.state_digest(OBSERVED),
            tuple((x.op_id, x.track) for x in doc.all_ops()))


def expected_authorized(track: str) -> bool:
    return track == AUTHORIZED


def expected_observed(track: str) -> bool:
    return track != REVOKED


@pytest.mark.parametrize("left,right", list(itertools.product(TRACKS, repeat=2)))
def test_classification_join_is_commutative_even_for_same_op_id(left, right):
    a, b = document(left), document(right)
    ab, ba = CRDTDocument(DOC), CRDTDocument(DOC)
    assert ab.merge(a) == 1
    assert ab.merge(b) == 0
    assert ba.merge(b) == 1
    assert ba.merge(a) == 0
    assert snapshot(ab) == snapshot(ba)
    winner = max((left, right), key={AUTHORIZED: 0, OBSERVED: 1, REVOKED: 2}.get)
    assert ab.all_ops()[0].track == winner
    assert bool(ab.authorized_view()) == expected_authorized(winner)
    assert bool(ab.observed_view()) == expected_observed(winner)


@pytest.mark.parametrize("order", list(itertools.product(TRACKS, repeat=3)))
def test_associativity_and_delivery_permutations(order):
    results = []
    for perm in set(itertools.permutations(order)):
        dst = CRDTDocument(DOC)
        for track in perm:
            dst.merge(document(track))
        results.append(snapshot(dst))
    assert results
    assert len(set(results)) == 1


def test_duplicate_idempotent_downgrade_and_no_revoked_resurrection():
    doc = document(AUTHORIZED)
    assert doc.add_op(op(OBSERVED)) is False
    assert doc.all_ops()[0].track == OBSERVED
    assert doc.authorized_view() == {}
    assert doc.observed_view() == {"machine/availability": "up"}

    assert doc.add_op(op(REVOKED)) is False
    assert doc.all_ops()[0].track == REVOKED
    assert doc.authorized_view() == {}
    assert doc.observed_view() == {}
    assert doc.heads() == []

    # Even a locally supplied forged positive track may not revive revocation.
    assert doc.add_op(op(AUTHORIZED)) is False
    doc.set_op_track(op(AUTHORIZED).op_id, AUTHORIZED)
    assert doc.all_ops()[0].track == REVOKED


def test_validated_receipt_can_upgrade_observed_but_not_revoked():
    doc = document(OBSERVED)
    with pytest.raises(ValueError, match="validated"):
        doc.set_op_track(op(OBSERVED).op_id, AUTHORIZED)
    doc.set_op_track(op(OBSERVED).op_id, AUTHORIZED, validated=True)
    assert doc.authorized_view() == {"machine/availability": "up"}
    doc.set_op_track(op(OBSERVED).op_id, REVOKED)
    doc.set_op_track(op(OBSERVED).op_id, AUTHORIZED, validated=True)
    assert doc.authorized_view() == {}
    assert doc.observed_view() == {}


@pytest.mark.parametrize("bad", ["", "AUTHORIZED!", "QUARANTINED", None, True, 7])
def test_unknown_tracks_are_rejected_before_any_state_change(bad):
    with pytest.raises((ValueError, TypeError)):
        op(bad)


def test_unknown_reclassification_rejected_and_absent_id_is_noop():
    doc = document(OBSERVED)
    with pytest.raises(ValueError, match="track"):
        doc.set_op_track(op(OBSERVED).op_id, "CUSTOM")
    assert doc.all_ops()[0].track == OBSERVED
    doc.set_op_track("not-present", REVOKED)
    assert doc.all_ops()[0].track == OBSERVED

def test_serialized_operation_rejects_supplied_wrong_hash():
    valid = op(OBSERVED)
    serialized = valid.to_dict()
    assert Op.from_dict(serialized).op_id == valid.op_id
    serialized["op_id"] = "0" * 64
    with pytest.raises(ValueError, match="op_id"):
        Op.from_dict(serialized)


def test_artificial_content_address_collision_fails_closed(monkeypatch):
    import szl_mesh.crdt as crdt

    doc = document(OBSERVED)
    original_id = op(OBSERVED).op_id
    collision = Op(DOC, "machine/availability", "tampered", 5, "n1", track=AUTHORIZED)
    monkeypatch.setattr(crdt, "compute_op_id", lambda *args: original_id)
    with pytest.raises(ValueError, match="collision"):
        doc.add_op(collision)
    assert doc.observed_view() == {"machine/availability": "up"}
    assert doc.authorized_view() == {}


def test_seeded_multi_key_replica_permutation_fuzz():
    """Finite randomized regression, not a proof of arbitrary-state convergence."""
    import random

    rng = random.Random(0x5A1C0DE)
    for trial in range(120):
        transmissions = []
        for key in ("a", "b", "c", "d", "e"):
            for ordinal in range(3):
                # Two logical values for some keys plus multiple independent
                # classifications of each exact operation ID.
                value = f"{key}-{ordinal}"
                tracks = rng.sample(TRACKS, k=rng.randint(1, len(TRACKS)))
                for track in tracks:
                    transmissions.append(
                        Op(DOC, key, value, ordinal + 1, "n" + key, track=track)
                    )
        left = CRDTDocument(DOC)
        right = CRDTDocument(DOC)
        left_items, right_items = transmissions[:], transmissions[:]
        rng.shuffle(left_items)
        rng.shuffle(right_items)
        for item in left_items:
            left.merge_ops([item])
        for item in right_items:
            right.add_op(item)
        assert snapshot(left) == snapshot(right), f"failed trial {trial}"


def test_conservative_track_join_has_associativity_idempotence_and_commutativity():
    from szl_mesh.crdt import join_track

    for a, b, c in itertools.product(TRACKS, repeat=3):
        assert join_track(join_track(a, b), c) == join_track(a, join_track(b, c))
        assert join_track(a, b) == join_track(b, a)
        assert join_track(a, a) == a
