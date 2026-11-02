# Copyright 2026 SZL Holdings
# SPDX-License-Identifier: Apache-2.0
"""Focused tests for szl_mesh.spine — the canonical szl-receipt fold (T302).

Asserts the honest PCGI binding: subject (node id) + input digest + output/state
digest + governing policy id + energy=UNAVAILABLE, signed via the shared
szl-receipt library. Additive: the existing DSSE path in szl_mesh.receipts is
unchanged and still tested by tests/test_runtime.py.

Run: python -m pytest tests/test_spine.py
Doctrine v11 LOCKED 749/14/163 · Kernel commit c7c0ba17 · SLSA L1.
"""

from __future__ import annotations

import hashlib
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# The spine binding requires the optional shared library; skip honestly if absent
# (matches the SpineUnavailable contract — never fabricate a receipt).
pytest.importorskip("szl_receipt")

import szl_receipt  # noqa: E402

from szl_mesh import receipts as rcpt  # noqa: E402
from szl_mesh import spine  # noqa: E402

DOC = "test-doc/platforms"


def _statement():
    raw = b'{"k":"v"}'
    ch = hashlib.sha256(raw).hexdigest()
    _, node_id = rcpt.generate_node_keypair()
    stmt = rcpt.build_state_transition_statement(
        DOC, ch, [], [ch], node_id, "PLATFORM_STATUS"
    )
    return stmt, ch, node_id


def test_energy_is_unavailable_never_fabricated():
    stmt, _ch, _node_id = _statement()
    body = spine.build_mesh_receipt_body(stmt)
    energy = body["energy"]
    assert energy["measured"] is False
    assert energy["joules"] == spine.ENERGY_UNAVAILABLE == "UNAVAILABLE"
    # A joule must never be a fabricated number.
    assert not isinstance(energy["joules"], (int, float))


def test_body_binds_subject_input_output_policy():
    stmt, ch, node_id = _statement()
    body = spine.build_mesh_receipt_body(stmt, quorum_id="q-1")
    assert body["subject"]["node_id"] == node_id
    assert body["subject"]["quorum_id"] == "q-1"
    assert body["policy_id"] == spine.DEFAULT_POLICY_ID
    # Digests re-derive independently from the statement.
    assert body["input_digest"] == spine.transition_input_digest(stmt)
    assert body["output_digest"] == spine.transition_output_digest(stmt)
    # Doctrine pinning is carried into the canonical binding.
    assert body["doctrine_version"] == rcpt.DOCTRINE_VERSION
    assert body["kernel_commit"] == rcpt.KERNEL_COMMIT


def test_body_is_deterministic():
    stmt, _ch, _node_id = _statement()
    d1 = spine.mesh_receipt_body_digest(stmt)
    d2 = spine.mesh_receipt_body_digest(stmt)
    assert d1 == d2
    # Byte-identical canonical bodies via the shared library primitive.
    from szl_receipt._canonical import canonical_json

    b1 = canonical_json(spine.build_mesh_receipt_body(stmt))
    b2 = canonical_json(spine.build_mesh_receipt_body(stmt))
    assert b1 == b2


def test_keyless_is_unsigned_honest():
    stmt, _ch, _node_id = _statement()
    env = spine.emit_mesh_receipt(stmt)  # no key
    assert env["signed"] is False
    ok, detail = spine.verify_mesh_receipt(env)
    assert ok is False
    assert detail == "unsigned-honest"


def test_signed_receipt_verifies_and_rebinds():
    stmt, _ch, _node_id = _statement()
    priv_pem, pub_pem = szl_receipt.generate_keypair()
    env = spine.emit_mesh_receipt(stmt, private_key_pem=priv_pem)
    assert env["signed"] is True
    ok, detail = spine.verify_mesh_receipt(
        env, public_key_pem=pub_pem, stmt=stmt
    )
    assert ok is True, detail
    assert detail == "ok"


def test_tamper_breaks_output_rebind():
    stmt, _ch, _node_id = _statement()
    priv_pem, pub_pem = szl_receipt.generate_keypair()
    env = spine.emit_mesh_receipt(stmt, private_key_pem=priv_pem)
    # Signature alone still verifies...
    ok, _ = spine.verify_mesh_receipt(env, public_key_pem=pub_pem)
    assert ok is True
    # ...but rebinding against a tampered statement (edited resulting state) fails.
    tampered = dict(stmt)
    tampered["to_state_head"] = ["deadbeef"]
    ok2, detail2 = spine.verify_mesh_receipt(
        env, public_key_pem=pub_pem, stmt=tampered
    )
    assert ok2 is False
    assert detail2 == "output-digest-rebind-mismatch"


@pytest.mark.parametrize("changed", ["node", "policy", "quorum", "witnesses"])
def test_rebind_rejects_different_subject_and_governance_context(changed):
    stmt, _, _ = _statement()
    private, public = szl_receipt.generate_keypair()
    options = {"policy_id": "policy-a", "quorum_id": "quorum-a",
               "witnesses": [{"node": "witness-a", "approved": True}]}
    env = spine.emit_mesh_receipt(stmt, private_key_pem=private, **options)
    assert szl_receipt.verify_receipt(env, public)[0]
    assert spine.verify_mesh_receipt(env, public_key_pem=public, stmt=stmt, **options)[0]

    expected = dict(options)
    if changed == "node":
        stmt = dict(stmt, node_id="different-node")
    elif changed == "policy":
        expected["policy_id"] = "different-policy"
    elif changed == "quorum":
        expected["quorum_id"] = "different-quorum"
    else:
        # Python considers True == 1, but their canonical JSON bytes differ.
        expected["witnesses"] = [{"node": "witness-a", "approved": 1}]
    assert spine.verify_mesh_receipt(
        env, public_key_pem=public, stmt=stmt, **expected
    ) == (False, "mesh-body-rebind-mismatch")


@pytest.mark.parametrize("field,value", [
    ("schema", "another-receipt-schema"),
    ("energy", {"measured": True, "joules": 1}),
    ("doctrine_version", "different-doctrine"),
])
def test_rebind_rejects_validly_signed_noncanonical_mesh_claims(field, value):
    stmt, _, _ = _statement()
    private, public = szl_receipt.generate_keypair()
    body = spine.build_mesh_receipt_body(stmt)
    body[field] = value
    env = szl_receipt.sign_receipt(
        szl_receipt.Receipt(kind=spine.RECEIPT_KIND, body=body), private
    )
    assert szl_receipt.verify_receipt(env, public)[0]
    assert spine.verify_mesh_receipt(env, public_key_pem=public, stmt=stmt) == (
        False, "mesh-body-rebind-mismatch"
    )


@pytest.mark.parametrize("body", [[], None, "not-a-mesh-body"])
def test_rebind_rejects_validly_signed_nonobject_body(body):
    stmt, _, _ = _statement()
    private, public = szl_receipt.generate_keypair()
    env = szl_receipt.sign_receipt(szl_receipt.Receipt(kind="other", body=body), private)
    assert szl_receipt.verify_receipt(env, public)[0]
    assert spine.verify_mesh_receipt(env, public_key_pem=public, stmt=stmt) == (
        False, "mesh-body-not-object"
    )


def test_fold_from_existing_dsse_receipt():
    raw = b'{"k":"v"}'
    ch = hashlib.sha256(raw).hexdigest()
    priv, node_id = rcpt.generate_node_keypair()
    stmt = rcpt.build_state_transition_statement(
        DOC, ch, [], [ch], node_id, "PLATFORM_STATUS"
    )
    dsse = rcpt.build_dsse_receipt(stmt, priv)
    # The existing DSSE receipt still verifies (additive — path untouched).
    assert rcpt.verify_receipt_signature(dsse) is True
    # And it folds onto the canonical spine binding.
    env = spine.emit_mesh_receipt_from_dsse(dsse)
    assert env["signed"] is False  # keyless by default -> unsigned-honest
    import base64
    import json

    body = json.loads(base64.b64decode(env["payload"]).decode("utf-8"))
    assert body["input_digest"] == spine.transition_input_digest(stmt)
    assert body["output_digest"] == spine.transition_output_digest(stmt)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
