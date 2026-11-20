# SPDX-License-Identifier: Apache-2.0
"""Source-only Kimi/Mistral peer-code-review *advisory* for szl-mesh.

This is not khipu-consensus, a quorum certificate, a signature, a code merger
or an execution grant. Reviewer/model identity is DECLARED, not authenticated.
No model calls, network, file reads, provider SDKs, process spawning or writes.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
import re
from typing import Any

SCHEMA = "szl.mesh.peer-code-review-advisory/v1"
DOMAIN = b"szl.mesh.peer-code-review-advisory/v1\x00"
MAX_BYTES = 8192
MAX_AGE_SECONDS = 900
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA64 = re.compile(r"[0-9a-f]{64}\Z")
REPO = re.compile(r"szl-holdings/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\Z")
MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,95}\Z")

TOP = frozenset({"schema", "repository", "source_sha", "patch_sha256",
                 "reviewers", "tests"})
REVIEW = frozenset({"role", "provider_family", "model_id", "source_sha",
                   "patch_sha256", "response_sha256", "observed_at_utc",
                   "verdict", "reason_code"})
TESTS = frozenset({"status", "source_sha", "patch_sha256", "observed_at_utc",
                   "passed", "failed", "evidence_sha256"})
ROLES = frozenset({"PROPOSER", "CRITIC"})
FAMILIES = frozenset({"MOONSHOT", "MISTRAL"})
REASONS = frozenset({"NO_FINDINGS", "SOURCE_DRIFT", "PATCH_MISMATCH",
                     "TEST_FAILURE", "POLICY_HOLD", "SECURITY_RISK",
                     "INSUFFICIENT_EVIDENCE", "UNSUPPORTED_CLAIM"})


class PeerReviewHold(ValueError):
    """A fixed refusal classification, not model-supplied text."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise PeerReviewHold(code)


def _shape(value: Any, keys: frozenset[str], code: str) -> dict:
    _require(type(value) is dict and set(value) == keys, code)
    return value


def _digest(value: Any, pattern: re.Pattern[str], code: str) -> str:
    _require(type(value) is str and pattern.fullmatch(value) is not None, code)
    return value


def _date(value: Any, code: str) -> datetime:
    _require(type(value) is str and 15 <= len(value) <= 40, code)
    try:
        parsed = datetime.fromisoformat(
            value[:-1] + "+00:00" if value.endswith("Z") else value
        )
    except ValueError:
        raise PeerReviewHold(code) from None
    _require(parsed.tzinfo is not None and parsed.utcoffset() is not None, code)
    return parsed.astimezone(timezone.utc)


def _fresh(value: Any, now: datetime) -> bool:
    diff = (now - _date(value, "TIMESTAMP_INVALID")).total_seconds()
    return -5 <= diff <= MAX_AGE_SECONDS


def _canonical(value: Any) -> bytes:
    try:
        encoded = json.dumps(value, sort_keys=True, ensure_ascii=True,
                             allow_nan=False, separators=(",", ":")).encode("ascii")
    except (ValueError, TypeError, OverflowError, RecursionError):
        raise PeerReviewHold("NONCANONICAL_PACKET") from None
    _require(len(encoded) <= MAX_BYTES, "PACKET_TOO_LARGE")
    return encoded


def compile_peer_review(packet: dict, *, now: datetime) -> dict:
    """Evaluate *reported* evidence only; never authorize effects."""
    _shape(packet, TOP, "PACKET_FIELDS")
    _require(packet["schema"] == SCHEMA, "SCHEMA_MISMATCH")
    _require(isinstance(now, datetime) and now.tzinfo is not None
             and now.utcoffset() is not None, "INDEPENDENT_CLOCK_REQUIRED")
    now = now.astimezone(timezone.utc)
    _canonical(packet)
    repository = _digest(packet["repository"], REPO, "REPOSITORY_INVALID")
    source = _digest(packet["source_sha"], SHA40, "SOURCE_SHA_INVALID")
    patch = _digest(packet["patch_sha256"], SHA64, "PATCH_DIGEST_INVALID")
    reviews = packet["reviewers"]
    _require(type(reviews) is list and len(reviews) == 2, "TWO_REVIEWERS_REQUIRED")

    reasons: set[str] = set()
    seen_roles: set[str] = set()
    seen_families: set[str] = set()
    seen_models: set[str] = set()
    response_digests: list[str] = []
    rows: list[dict] = []
    for record in reviews:
        _shape(record, REVIEW, "REVIEW_FIELDS")
        role = record["role"]
        family = record["provider_family"]
        _require(type(role) is str and role in ROLES, "ROLE_INVALID")
        _require(type(family) is str and family in FAMILIES, "PROVIDER_FAMILY_INVALID")
        model_name = _digest(record["model_id"], MODEL, "MODEL_IDENTIFIER_INVALID")
        # A model identifier may include namespace separators, never a URL,
        # path traversal or an endpoint with network/credential semantics.
        _require("://" not in model_name and "//" not in model_name
                 and "/.." not in model_name and "../" not in model_name,
                 "MODEL_IDENTIFIER_URL_OR_TRAVERSAL")
        if model_name in seen_models:
            reasons.add("DUPLICATED_DECLARED_MODEL_ID")
        seen_models.add(model_name)
        reviewer_source = _digest(record["source_sha"], SHA40, "REVIEW_SOURCE_INVALID")
        reviewer_patch = _digest(record["patch_sha256"], SHA64, "REVIEW_PATCH_INVALID")
        digest = _digest(record["response_sha256"], SHA64, "RESPONSE_DIGEST_INVALID")
        _require(type(record["verdict"]) is str and record["verdict"] in
                 {"APPROVE", "REJECT", "ABSTAIN"}, "VERDICT_INVALID")
        _require(type(record["reason_code"]) is str and record["reason_code"] in
                 REASONS, "REASON_CODE_INVALID")
        if record["verdict"] == "APPROVE":
            _require(record["reason_code"] == "NO_FINDINGS", "APPROVAL_REASON_INCONSISTENT")
        else:
            _require(record["reason_code"] != "NO_FINDINGS", "REFUSAL_REASON_REQUIRED")
        if role in seen_roles:
            reasons.add("ROLE_DUPLICATED")
        if family in seen_families:
            reasons.add("PROVIDER_FAMILY_DUPLICATED")
        # Role separation is declared, not authenticated, but even a
        # swapped Kimi/Mistral label cannot silently pass the contract.
        if (role, family) not in {("PROPOSER", "MOONSHOT"), ("CRITIC", "MISTRAL")}:
            reasons.add("REVIEW_ROLE_FAMILY_MISMATCH")
        seen_roles.add(role)
        seen_families.add(family)
        response_digests.append(digest)
        if reviewer_source != source:
            reasons.add("REVIEW_SOURCE_MISMATCH")
        if reviewer_patch != patch:
            reasons.add("REVIEW_PATCH_MISMATCH")
        if not _fresh(record["observed_at_utc"], now):
            reasons.add("STALE_OR_FUTURE_REVIEW")
        if record["verdict"] == "REJECT":
            reasons.add("PEER_DISSENT")
        elif record["verdict"] == "ABSTAIN":
            reasons.add("PEER_ABSTAINED")
        rows.append({"role": role, "provider_family": family,
                     "model_id_declared": record["model_id"],
                     "decision_reported": record["verdict"],
                     "reason_code": record["reason_code"],
                     "response_digest_declared": digest})

    if seen_roles != ROLES:
        reasons.add("REVIEW_ROLE_COVERAGE_MISSING")
    if seen_families != FAMILIES:
        reasons.add("MODEL_FAMILY_DIVERSITY_MISSING")
    if len(set(response_digests)) != 2:
        reasons.add("DUPLICATED_RESPONSE_DIGEST")

    tests = _shape(packet["tests"], TESTS, "TEST_FIELDS")
    test_source = _digest(tests["source_sha"], SHA40, "TEST_SOURCE_INVALID")
    test_patch = _digest(tests["patch_sha256"], SHA64, "TEST_PATCH_INVALID")
    test_digest = _digest(tests["evidence_sha256"], SHA64, "TEST_EVIDENCE_INVALID")
    _require(type(tests["status"]) is str and tests["status"] in
             {"PASS", "FAIL", "UNAVAILABLE"}, "TEST_STATUS_INVALID")
    _require(type(tests["passed"]) is int and 0 <= tests["passed"] <= 100000,
             "PASSED_COUNT_INVALID")
    _require(type(tests["failed"]) is int and 0 <= tests["failed"] <= 100000,
             "FAILED_COUNT_INVALID")
    if tests["status"] == "PASS":
        _require(tests["passed"] > 0 and tests["failed"] == 0, "PASS_COUNTER_INCONSISTENT")
    elif tests["status"] == "FAIL":
        _require(tests["failed"] > 0, "FAIL_COUNTER_INCONSISTENT")
    else:
        _require(tests["passed"] == 0 and tests["failed"] == 0,
                 "UNAVAILABLE_COUNTER_INCONSISTENT")
    if test_source != source or test_patch != patch:
        reasons.add("TEST_SOURCE_OR_PATCH_MISMATCH")
    if not _fresh(tests["observed_at_utc"], now):
        reasons.add("STALE_OR_FUTURE_TESTS")
    if tests["status"] == "FAIL":
        reasons.add("REPORTED_TEST_FAILURE")
    if tests["status"] == "UNAVAILABLE":
        reasons.add("TESTS_UNAVAILABLE")

    rows.sort(key=lambda x: (x["role"], x["provider_family"]))
    result = {
        "schema": SCHEMA,
        "state": "HOLD" if reasons else "READY_FOR_OWNER_REVIEW",
        "reasons": sorted(reasons),
        "repository": repository,
        "source_sha_reported_not_attested": source,
        "patch_sha256_reported_not_recomputed": patch,
        "reviewers": rows,
        "reported_tests": {"status": tests["status"], "passed": tests["passed"],
                           "failed": tests["failed"], "evidence_sha256": test_digest},
        "observed_at_utc": now.isoformat(),
        "provider_family_diversity_declared": seen_families == FAMILIES,
        "reviewer_independence_verified": False,
        "models_authenticated": False,
        "test_evidence_independently_verified": False,
        "signature_verified": False,
        "cryptographic_quorum_claimed": False,
        "tool_calls_performed": 0,
        "writes_performed": 0,
        "execution_authorized": False,
        "merge_authorized": False,
        "deployment_authorized": False,
        "production_ready": False,
    }
    return {**result, "unsigned_sha256_not_signature":
            sha256(DOMAIN + _canonical(result)).hexdigest()}


# The emitted packet is strictly shape-checked on replay; a self-recomputed
# digest over arbitrary new keys must never pass the bounded advisory decoder.
OUTPUT_KEYS = frozenset({
    "schema", "state", "reasons", "repository",
    "source_sha_reported_not_attested", "patch_sha256_reported_not_recomputed",
    "reviewers", "reported_tests", "observed_at_utc",
    "provider_family_diversity_declared", "reviewer_independence_verified",
    "models_authenticated", "test_evidence_independently_verified",
    "signature_verified", "cryptographic_quorum_claimed",
    "tool_calls_performed", "writes_performed", "execution_authorized",
    "merge_authorized", "deployment_authorized", "production_ready",
})
OUTPUT_REVIEW_KEYS = frozenset({
    "role", "provider_family", "model_id_declared", "decision_reported",
    "reason_code", "response_digest_declared",
})
OUTPUT_TEST_KEYS = frozenset({"status", "passed", "failed", "evidence_sha256"})
HOLD_REASON_CODES = frozenset({
    "ROLE_DUPLICATED", "PROVIDER_FAMILY_DUPLICATED",
    "REVIEW_ROLE_FAMILY_MISMATCH", "DUPLICATED_DECLARED_MODEL_ID", "REVIEW_SOURCE_MISMATCH",
    "REVIEW_PATCH_MISMATCH", "STALE_OR_FUTURE_REVIEW",
    "PEER_DISSENT", "PEER_ABSTAINED", "REVIEW_ROLE_COVERAGE_MISSING",
    "MODEL_FAMILY_DIVERSITY_MISSING", "DUPLICATED_RESPONSE_DIGEST",
    "TEST_SOURCE_OR_PATCH_MISMATCH", "STALE_OR_FUTURE_TESTS",
    "REPORTED_TEST_FAILURE", "TESTS_UNAVAILABLE",
})


def verify_peer_review(record: Any) -> bool:
    """Strict structural replay: never authenticate model, tests or signer.

    Rehashing any self-declared, internally consistent record remains possible.
    Only an independently trusted source/test/signer can make evidence binding.
    """
    if type(record) is not dict:
        return False
    try:
        _shape(record, OUTPUT_KEYS | {"unsigned_sha256_not_signature"},
               "OUTPUT_PACKET_FIELDS")
        body = {k: v for k, v in record.items()
                if k != "unsigned_sha256_not_signature"}
        digest = _digest(record["unsigned_sha256_not_signature"], SHA64,
                         "OUTPUT_DIGEST_INVALID")
        if digest != sha256(DOMAIN + _canonical(body)).hexdigest():
            return False
        if body["schema"] != SCHEMA:
            return False
        _digest(body["repository"], REPO, "OUTPUT_REPOSITORY_INVALID")
        _digest(body["source_sha_reported_not_attested"], SHA40,
                "OUTPUT_SOURCE_INVALID")
        _digest(body["patch_sha256_reported_not_recomputed"], SHA64,
                "OUTPUT_PATCH_INVALID")
        _date(body["observed_at_utc"], "OUTPUT_TIMESTAMP_INVALID")
        if body["state"] not in ("HOLD", "READY_FOR_OWNER_REVIEW"):
            return False
        reasons = body["reasons"]
        if type(reasons) is not list or sorted(set(reasons)) != reasons:
            return False
        if any(type(reason) is not str or reason not in HOLD_REASON_CODES
               for reason in reasons):
            return False
        if (body["state"] == "READY_FOR_OWNER_REVIEW") != (reasons == []):
            return False
        for key in ("reviewer_independence_verified", "models_authenticated",
                    "test_evidence_independently_verified", "signature_verified",
                    "cryptographic_quorum_claimed", "execution_authorized",
                    "merge_authorized", "deployment_authorized",
                    "production_ready"):
            if body[key] is not False:
                return False
        for key in ("tool_calls_performed", "writes_performed"):
            if type(body[key]) is not int or body[key] != 0:
                return False

        reviews = body["reviewers"]
        if type(reviews) is not list or len(reviews) != 2:
            return False
        seen_roles, seen_families, names, response_hashes = [], [], [], []
        decisions = []
        for row in reviews:
            _shape(row, OUTPUT_REVIEW_KEYS, "OUTPUT_REVIEW_FIELDS")
            role, family = row["role"], row["provider_family"]
            if type(role) is not str or role not in ROLES:
                return False
            if type(family) is not str or family not in FAMILIES:
                return False
            name = _digest(row["model_id_declared"], MODEL,
                           "OUTPUT_MODEL_IDENTIFIER_INVALID")
            if "://" in name or "//" in name or "/.." in name or "../" in name:
                return False
            _digest(row["response_digest_declared"], SHA64,
                    "OUTPUT_RESPONSE_DIGEST_INVALID")
            verdict, reason = row["decision_reported"], row["reason_code"]
            if type(verdict) is not str or verdict not in ("APPROVE", "REJECT", "ABSTAIN"):
                return False
            if type(reason) is not str or reason not in REASONS:
                return False
            if (verdict == "APPROVE") != (reason == "NO_FINDINGS"):
                return False
            decisions.append(verdict)
            seen_roles.append(role)
            seen_families.append(family)
            names.append(name)
            response_hashes.append(row["response_digest_declared"])
        if body["provider_family_diversity_declared"] is not (
                set(seen_families) == FAMILIES):
            return False

        tests = _shape(body["reported_tests"], OUTPUT_TEST_KEYS,
                       "OUTPUT_TEST_FIELDS")
        status = tests["status"]
        if type(status) is not str or status not in ("PASS", "FAIL", "UNAVAILABLE"):
            return False
        passed, failed = tests["passed"], tests["failed"]
        if (type(passed) is not int or type(failed) is not int or
                not 0 <= passed <= 100000 or not 0 <= failed <= 100000):
            return False
        if status == "PASS" and not (passed > 0 and failed == 0):
            return False
        if status == "FAIL" and failed <= 0:
            return False
        if status == "UNAVAILABLE" and (passed != 0 or failed != 0):
            return False
        _digest(tests["evidence_sha256"], SHA64, "OUTPUT_TEST_DIGEST_INVALID")
        if body["state"] == "READY_FOR_OWNER_REVIEW":
            if (set(seen_roles) != ROLES or set(seen_families) != FAMILIES or
                    set(zip(seen_roles, seen_families)) != {
                        ("PROPOSER", "MOONSHOT"), ("CRITIC", "MISTRAL")
                    } or
                    len(set(names)) != 2 or len(set(response_hashes)) != 2 or
                    decisions != ["APPROVE", "APPROVE"] or status != "PASS"):
                return False
        return True
    except (PeerReviewHold, ValueError, TypeError, OverflowError,
            RecursionError, KeyError):
        return False