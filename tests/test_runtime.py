"""
Tests for the szl_mesh node runtime:
  - CRDT convergence (order-independent, idempotent)
  - DSSE receipt verification (valid + tamper-detect)
  - doctrine-gated enrollment (accept + reject paths)
  - end-to-end multi-node mesh convergence via the harness

Run: python -m pytest tests/  (or python tests/test_runtime.py)
Doctrine v11 LOCKED 749/14/163 · Kernel commit c7c0ba17 · SLSA L1.
"""

from __future__ import annotations

import itertools
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from szl_mesh import receipts as rcpt  # noqa: E402
from szl_mesh.crdt import AUTHORIZED, OBSERVED, CRDTDocument, Op  # noqa: E402
from szl_mesh.enrollment import FormationGateway, build_enrollment_request  # noqa: E402
from szl_mesh.harness import MeshHarness  # noqa: E402

FK = b"test-formation-key"
DOC = "test-doc/platforms"


def _ops():
    return [
        Op(DOC, "a", "1", 1, "n1", track=AUTHORIZED),
        Op(DOC, "b", "2", 2, "n2", track=AUTHORIZED),
        Op(DOC, "a", "3", 3, "n1", track=AUTHORIZED),  # LWW newer wins for "a"
        Op(DOC, "c", "4", 2, "n3", track=OBSERVED),
    ]


def test_crdt_converges_all_orders():
    """All permutations of op delivery yield the same materialised state."""
    ref = None
    for perm in itertools.permutations(_ops()):
        doc = CRDTDocument(DOC)
        for op in perm:
            doc.add_op(op)
        view = doc.observed_view()
        if ref is None:
            ref = view
        assert view == ref, f"divergence under permutation: {view} != {ref}"
    # LWW: "a" should be the lamport=3 value.
    assert ref["a"] == "3"
    print("test_crdt_converges_all_orders: PASS")


def test_crdt_idempotent_and_commutative_merge():
    a = CRDTDocument(DOC)
    b = CRDTDocument(DOC)
    for op in _ops()[:2]:
        a.add_op(op)
    for op in _ops()[2:]:
        b.add_op(op)
    a2 = CRDTDocument(DOC)
    a2.merge(a)
    a2.merge(b)
    a2.merge(b)  # idempotent: merging twice changes nothing
    b2 = CRDTDocument(DOC)
    b2.merge(b)
    b2.merge(a)
    assert a2.observed_view() == b2.observed_view()
    assert a2.state_digest(OBSERVED) == b2.state_digest(OBSERVED)
    print("test_crdt_idempotent_and_commutative_merge: PASS")


def test_two_track_separation():
    doc = CRDTDocument(DOC)
    for op in _ops():
        doc.add_op(op)
    auth = doc.authorized_view()
    obs = doc.observed_view()
    assert "c" not in auth  # c is OBSERVED-only
    assert "c" in obs       # never dropped
    print("test_two_track_separation: PASS")


def test_receipt_sign_and_verify():
    priv, node_id = rcpt.generate_node_keypair()
    raw = b'{"k":"v"}'
    import hashlib

    ch = hashlib.sha256(raw).hexdigest()
    stmt = rcpt.build_state_transition_statement(
        DOC, ch, [], [ch], node_id, "PLATFORM_STATUS"
    )
    env = rcpt.build_dsse_receipt(stmt, priv)
    assert rcpt.verify_receipt_signature(env) is True
    gate = rcpt.validate_receipt(env, raw)
    assert gate.track == AUTHORIZED
    assert gate.receipt_status == rcpt.RECEIPT_VALID
    print("test_receipt_sign_and_verify: PASS")


def test_receipt_tamper_detected():
    priv, node_id = rcpt.generate_node_keypair()
    raw = b'{"k":"v"}'
    import hashlib

    ch = hashlib.sha256(raw).hexdigest()
    stmt = rcpt.build_state_transition_statement(DOC, ch, [], [ch], node_id)
    env = rcpt.build_dsse_receipt(stmt, priv)
    # Tamper with the payload -> signature must fail.
    env["payload"] = env["payload"][:-4] + "AAAA"
    assert rcpt.verify_receipt_signature(env) is False
    # Hash mismatch downgrades to OBSERVED.
    gate = rcpt.validate_receipt(env, b"different-bytes")
    assert gate.track == OBSERVED
    print("test_receipt_tamper_detected: PASS")


def test_wrong_doctrine_downgrades():
    priv, node_id = rcpt.generate_node_keypair()
    raw = b"x"
    import hashlib

    ch = hashlib.sha256(raw).hexdigest()
    stmt = rcpt.build_state_transition_statement(DOC, ch, [], [ch], node_id)
    stmt["doctrine_version"] = "000/00/000"
    env = rcpt.build_dsse_receipt(stmt, priv)
    gate = rcpt.validate_receipt(env, raw)
    assert gate.track == OBSERVED
    assert gate.receipt_status == rcpt.RECEIPT_WRONG_DOCTRINE
    print("test_wrong_doctrine_downgrades: PASS")


def test_enrollment_accept():
    gw = FormationGateway("f1", FK)
    priv, node_id = rcpt.generate_node_keypair()
    req = build_enrollment_request(
        FK, node_id,
        priv.public_key().public_bytes(
            encoding=__import__("cryptography.hazmat.primitives.serialization",
                                fromlist=["Encoding"]).Encoding.DER,
            format=__import__("cryptography.hazmat.primitives.serialization",
                              fromlist=["PublicFormat"]).PublicFormat.SubjectPublicKeyInfo,
        ),
        rcpt.utc_now_iso(),
    )
    res = gw.enroll(req)
    assert res.success is True
    print("test_enrollment_accept: PASS")


def test_enrollment_reject_bad_proof():
    gw = FormationGateway("f1", FK)
    priv, node_id = rcpt.generate_node_keypair()
    from cryptography.hazmat.primitives import serialization

    der = priv.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    req = build_enrollment_request(b"WRONG-KEY", node_id, der, rcpt.utc_now_iso())
    res = gw.enroll(req)
    assert res.success is False
    assert res.failure_reason == "BAD_FORMATION_PROOF"
    print("test_enrollment_reject_bad_proof: PASS")


def test_enrollment_reject_wrong_doctrine():
    gw = FormationGateway("f1", FK)
    priv, node_id = rcpt.generate_node_keypair()
    from cryptography.hazmat.primitives import serialization

    der = priv.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    req = build_enrollment_request(
        FK, node_id, der, rcpt.utc_now_iso(), doctrine_version="999/99/999"
    )
    res = gw.enroll(req)
    assert res.success is False
    assert res.failure_reason == "WRONG_DOCTRINE"
    print("test_enrollment_reject_wrong_doctrine: PASS")


def test_enrollment_reject_section_889():
    gw = FormationGateway("f1", FK)
    priv, node_id = rcpt.generate_node_keypair()
    from cryptography.hazmat.primitives import serialization

    der = priv.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    req = build_enrollment_request(
        FK, node_id, der, rcpt.utc_now_iso(), hardware_vendor="Hikvision"
    )
    res = gw.enroll(req)
    assert res.success is False
    assert res.failure_reason == "SECTION_889_VIOLATION"
    print("test_enrollment_reject_section_889: PASS")


def test_multinode_mesh_convergence():
    """End-to-end: 4 enrolled nodes, randomised gossip, converge identically."""
    for seed in range(8):  # multiple delivery orders
        h = MeshHarness("f-e2e", "e2e/platforms", FK, seed=seed)
        nodes = [h.add_node(n)[0] for n in ("a", "b", "c", "d")]
        for i, nd in enumerate(nodes):
            h.write(nd, f"k{i}", f"v{i}", "PLATFORM_STATUS")
        h.write(nodes[0], "k1", "override", "PLATFORM_STATUS")  # LWW contention
        h.gossip(shuffle=True)
        assert h.converged(AUTHORIZED), f"AUTH diverged seed={seed}"
        assert h.converged(OBSERVED), f"OBS diverged seed={seed}"
    print("test_multinode_mesh_convergence: PASS (8 random delivery orders)")


def test_must_enroll_before_write():
    from szl_mesh.node import MeshNode

    n = MeshNode("solo", DOC)
    try:
        n.write("k", "v")
        assert False, "expected RuntimeError"
    except RuntimeError:
        pass
    print("test_must_enroll_before_write: PASS")


def _run_all():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
    print(f"\nALL {len(fns)} TESTS PASSED")


if __name__ == "__main__":
    _run_all()
