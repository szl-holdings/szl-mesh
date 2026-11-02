"""Certificates cannot choose the verifier's trusted quorum policy."""
import json
from pathlib import Path

import pytest

from szl_mesh import quorum as Q


def _signed_certificate():
    vectors = json.loads((Path(__file__).parents[1] / "src/szl_mesh/_vendor/vectors.json").read_text())
    signatures = next(case["signatures"] for case in vectors["cases"]
                      if case["expect"]["consensus_count"] == 4)
    return {"action_hash": vectors["action_hash"], "threshold": 3, "n": 4,
            "witnesses": signatures}, vectors["pubkeys"]


@pytest.mark.parametrize("threshold", [0, -1, 1, 2, False, True, "3", 3.0, float("inf")])
def test_wire_threshold_cannot_downgrade_or_coerce_policy(threshold):
    certificate, keys = _signed_certificate()
    certificate["threshold"] = threshold
    certificate["witnesses"] = certificate["witnesses"][:1]
    result = Q.verify_quorum(certificate, keys)
    assert result.canonical is False


@pytest.mark.parametrize("n", [0, -1, 2, 5, False, "4", 4.0, float("inf")])
def test_wire_population_must_match_trusted_policy(n):
    certificate, keys = _signed_certificate()
    certificate["n"] = n
    assert Q.verify_quorum(certificate, keys).canonical is False


def test_empty_zero_threshold_cannot_fabricate_quorum():
    result = Q.verify_quorum({"action_hash": "a" * 64, "threshold": 0,
                              "n": 4, "witnesses": []}, {})
    assert result.canonical is False
    assert result.consensus_count == 0


def test_custom_policy_requires_explicit_verifier_selection():
    certificate, keys = _signed_certificate()
    certificate.update(threshold=2, n=3)
    certificate["witnesses"] = certificate["witnesses"][:2]
    assert Q.verify_quorum(certificate, keys).canonical is False
    result = Q.verify_quorum(certificate, keys, threshold=2, n=3)
    assert result.canonical is True
    assert result.consensus_count == 2


@pytest.mark.parametrize("threshold,n", [(0, 4), (5, 4), (True, 4), (3, 0), (3, 4.0)])
def test_invalid_trusted_policy_is_rejected(threshold, n):
    with pytest.raises(ValueError, match="quorum policy"):
        Q.verify_quorum({}, {}, threshold=threshold, n=n)
    with pytest.raises(ValueError, match="quorum policy"):
        Q.propose_action("a" * 64, {}, threshold=threshold, n=n)


@pytest.mark.parametrize("threshold,n", [(2, 3), (3, 4)])
def test_serialized_safety_model_matches_selected_policy(threshold, n):
    certificate, keys = _signed_certificate()
    certificate.update(threshold=threshold, n=n)
    certificate["witnesses"] = certificate["witnesses"][:n]
    qc = Q.QuorumCertificate(**certificate)
    result = Q.verify_quorum(qc, keys, threshold=threshold, n=n)
    assert result.canonical is True
    assert result.consensus_count == n
    expected_label = (
        f"khipu-{threshold}of{n}-quorum (real ECDSA-P256 DSSE); "
        "unconditional BFT safety = Conjecture 2 (NOT proven)"
    )
    for serialized in (qc.to_dict(), result.to_dict()):
        assert serialized["threshold"] == threshold
        assert serialized["n"] == n
        assert serialized["safety_model"] == expected_label


def test_rejected_certificate_serializes_trusted_policy_label():
    certificate, keys = _signed_certificate()
    result = Q.verify_quorum(certificate, keys, threshold=2, n=3)
    assert result.canonical is False
    assert result.consensus_count == 0
    serialized = result.to_dict()
    assert serialized["threshold"] == 2
    assert serialized["n"] == 3
    assert serialized["safety_model"].startswith("khipu-2of3-quorum ")
