"""Agentic Router -> Mesh digest observation, never a provider or authority claim."""

import hashlib
import json

import pytest

from szl_mesh.agentic_fabric import observe_router_request

MODEL = "szl-fast"
MESSAGES = [{"role": "user", "content": {"query": "public", "n": 3}}]
SHA = "a" * 40


def request_sha(model=MODEL, messages=None):
    body = {"model": model, "messages": MESSAGES if messages is None else messages}
    return hashlib.sha256(
        json.dumps(
            body, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    ).hexdigest()


def observe(*, model=MODEL, messages=None, receipt=None, source=SHA):
    if receipt is None:
        receipt = {"model": model, "request_digest": request_sha(model, messages)}
    return observe_router_request(
        model=model,
        messages=MESSAGES if messages is None else messages,
        receipt_body=receipt,
        expected_router_source_sha=SHA,
        reported_router_source_sha=source,
    )


def test_matching_digest_stays_observed_and_never_authorizes():
    result = observe()
    assert result["state"] == "OBSERVED_ONLY"
    assert result["reasons"] == []
    assert result["request_digest_recomputed"] == request_sha()
    assert result["source_freshness_independently_verified"] is False
    assert result["provider_identity_verified"] is False
    assert result["signature_verified"] is False
    assert result["receipt_authoritative"] is False
    assert result["tool_calls_executed"] == 0
    assert result["sql_writes_executed"] == 0
    assert result["payment_authorized"] is False
    assert result["production_ready"] is False


def test_changed_payload_is_held():
    different = [{"role": "user", "content": {"query": "public", "n": 4}}]
    result = observe(
        messages=different,
        receipt={
            "model": MODEL,
            "request_digest": request_sha(),
        },
    )
    assert result["state"] == "HOLD"
    assert "REQUEST_DIGEST_MISMATCH" in result["reasons"]


def test_unpinned_router_source_claim_is_held():
    result = observe(source="b" * 40)
    assert result["state"] == "HOLD"
    assert "ROUTER_SOURCE_CLAIM_MISMATCH" in result["reasons"]


def test_wrong_claimed_model_held():
    result = observe(receipt={"model": "szl-large", "request_digest": request_sha()})
    assert "MODEL_MISMATCH" in result["reasons"]


@pytest.mark.parametrize(
    "invalid", [float("nan"), float("inf"), -float("inf"), object()]
)
def test_nonfinite_or_non_json_cannot_be_rehashed(invalid):
    bad = [{"role": "user", "content": invalid}]
    with pytest.raises(ValueError, match="finite JSON"):
        observe(messages=bad, receipt={"model": MODEL, "request_digest": "a" * 64})


def test_malformed_digest_is_a_hold_not_signed():
    result = observe(receipt={"model": MODEL, "request_digest": True})
    assert result["state"] == "HOLD"
    assert "RECEIPT_DIGEST_INVALID" in result["reasons"]
    assert result["request_digest_reported"] is None


@pytest.mark.parametrize(
    "injected", [{"authorized": True}, {"signed": True}, {"production_ready": True}]
)
def test_authority_injected_into_untrusted_receipt_is_rejected(injected):
    receipt = {"model": MODEL, "request_digest": request_sha(), **injected}
    with pytest.raises(ValueError, match="unrecognized router receipt"):
        observe(receipt=receipt)


def test_optional_router_receipt_fields_are_data_only():
    receipt = {
        "model": MODEL,
        "request_digest": request_sha(),
        "energy": "UNAVAILABLE",
        "sovereign": False,
        "served_by": "reported-node",
        "attempts": [],
        "observer": {"auth_mode": "reported"},
    }
    result = observe(receipt=receipt)
    assert result["state"] == "OBSERVED_ONLY"
    assert result["provider_identity_verified"] is False


def test_bound_rejects_excessive_untrusted_messages():
    bad = [{"role": "user", "content": "x" * 35000}]
    with pytest.raises(ValueError, match="finite JSON"):
        observe(messages=bad, receipt={"model": MODEL, "request_digest": "a" * 64})


def test_missing_source_pin_is_an_error_not_a_false_match():
    with pytest.raises(ValueError, match="source identities"):
        observe(source="main")
