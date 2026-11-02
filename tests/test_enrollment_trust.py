"""Enrollment supplies trust; receipt self-consistency does not supply it.

Origin: OpenAI Codex, implementing the owner's repository audit.
"""
from copy import deepcopy

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from szl_mesh import receipts as rcpt
from szl_mesh.crdt import AUTHORIZED, OBSERVED
from szl_mesh.enrollment import FormationGateway, build_enrollment_request
from szl_mesh.node import MeshNode

FK = b"local-synthetic-formation-key"
DOC = "test/enrollment-trust"


def _request():
    private, node_id = rcpt.generate_node_keypair()
    der = private.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return build_enrollment_request(FK, node_id, der, rcpt.utc_now_iso())


def _sender():
    gateway = FormationGateway("sender-formation", FK)
    sender = MeshNode("sender", DOC)
    assert sender.enroll(gateway, FK).success
    return gateway, sender, sender.write("status", "ready")


def test_unenrolled_receiver_preserves_observation_without_authorizing():
    _, _, record = _sender()
    receiver = MeshNode("not-enrolled", DOC)
    result = receiver.apply_remote(record)
    assert result["track"] == OBSERVED
    assert receiver.authorized_state() == {}
    assert receiver.observed_state() == {"status": "ready"}
    # Signature checking remains available without asserting formation trust.
    assert receiver.verify_ledger() == (1, 1)


def test_failed_enrollment_does_not_supply_receiver_trust():
    gateway, _, record = _sender()
    receiver = MeshNode("rejected", DOC)
    assert not receiver.enroll(gateway, b"wrong-formation-key").success
    assert receiver.apply_remote(record)["track"] == OBSERVED
    assert receiver.authorized_state() == {}


def test_enrollment_allows_reclassification_under_the_known_registry():
    gateway, _, record = _sender()
    receiver = MeshNode("eventually-enrolled", DOC)
    assert receiver.apply_remote(record)["track"] == OBSERVED
    assert receiver.enroll(gateway, FK).success
    result = receiver.apply_remote(record)
    assert result["newly_added"] is False
    assert result["track"] == AUTHORIZED
    assert receiver.authorized_state() == {"status": "ready"}


def test_other_formation_signer_remains_observed():
    _, _, record = _sender()
    receiver = MeshNode("separate-formation", DOC)
    other = FormationGateway("other", b"different-key")
    assert receiver.enroll(other, b"different-key").success
    assert receiver.apply_remote(record)["track"] == OBSERVED
    assert receiver.authorized_state() == {}


def test_captured_proof_cannot_register_a_substituted_public_key():
    gateway = FormationGateway("test", FK)
    original = _request()
    changed = deepcopy(original)
    changed["public_key_der"] = _request()["public_key_der"]
    # The captured HMAC is unchanged: the gateway must bind its NodeID to DER.
    assert changed["formation_key_proof"] == original["formation_key_proof"]
    result = gateway.enroll(changed)
    assert not result.success
    assert result.failure_reason == "NODE_ID_KEY_MISMATCH"
    assert gateway.pubkey_registry() == {}
    assert gateway.cert_store == {}
    assert gateway.enroll(original).success


def test_malformed_enrollment_key_does_not_poison_certificate_store():
    for value in (None, "not-der", b"", b"not-der", bytearray(b"not-der")):
        gateway = FormationGateway("test", FK)
        request = _request()
        request["public_key_der"] = value
        result = gateway.enroll(request)
        assert not result.success
        assert result.failure_reason == "INVALID_PUBLIC_KEY"
        assert gateway.cert_store == {}


def test_missing_enrollment_key_is_a_rejection_without_mutation():
    gateway = FormationGateway("test", FK)
    request = _request()
    del request["public_key_der"]
    result = gateway.enroll(request)
    assert not result.success
    assert result.failure_reason == "INVALID_PUBLIC_KEY"
    assert gateway.cert_store == {}


def test_enrollment_rejects_keys_outside_the_runtime_p256_contract():
    for key in (ed25519.Ed25519PrivateKey.generate(), ec.generate_private_key(ec.SECP384R1())):
        gateway = FormationGateway("test", FK)
        der = key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        request = build_enrollment_request(
            FK, rcpt.node_id_from_pubkey(key.public_key()), der, rcpt.utc_now_iso(),
        )
        result = gateway.enroll(request)
        assert not result.success
        assert result.failure_reason == "INVALID_PUBLIC_KEY"
        assert gateway.cert_store == {}


def test_valid_duplicate_enrollment_does_not_replace_the_certificate():
    gateway = FormationGateway("test", FK)
    request = _request()
    assert gateway.enroll(request).success
    expected = deepcopy(gateway.cert_store)
    result = gateway.enroll(request)
    assert not result.success
    assert result.failure_reason == "DUPLICATE_NODE_ID"
    assert gateway.cert_store == expected
