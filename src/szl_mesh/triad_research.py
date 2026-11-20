# SPDX-License-Identifier: Apache-2.0
"""Yuyay Triad: bounded source-only three-role review evidence compiler.

This is deliberately NOT a model, agent runner, signer, provider adapter,
source of trusted identities, execution grant, or autonomous merge authority.
It never reads prompts, executes tools, calls providers, trains, or publishes.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any

PLAN_SCHEMA = "szl.mesh.yuyay-plan/v1"
SUBMISSION_SCHEMA = "szl.mesh.yuyay-review/v1"
REPORT_SCHEMA = "szl.mesh.yuyay-advisory/v1"
PLAN_DOMAIN = b"szl.mesh.yuyay-plan/v1\x00"
REPORT_DOMAIN = b"szl.mesh.yuyay-advisory/v1\x00"
ROLE_FAMILIES = {
    "KIMI_PROPOSER": "MOONSHOT",
    "MISTRAL_CRITIC": "MISTRAL",
    "GPT6_REFEREE": "OPENAI",
}
VERDICT_REASONS = {
    "APPROVE": {"NO_FINDINGS"},
    "REJECT": {"EVIDENCE_CONFLICT", "SAFETY_RISK", "REGRESSION"},
    "ABSTAIN": {"INSUFFICIENT_EVIDENCE"},
    "UNAVAILABLE": {"REVIEW_UNAVAILABLE"},
}
MAX_CASES = 256
MAX_PACKET_BYTES = 512 * 1024
MAX_AGE_SECONDS = 900
_SHA40 = re.compile(r"[a-f0-9]{40}\Z")
_SHA64 = re.compile(r"[a-f0-9]{64}\Z")
_REPO = re.compile(r"szl-holdings/[a-zA-Z0-9][a-zA-Z0-9_.-]{0,99}\Z")
_MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,95}\Z")
_PLAN = {"schema", "repository", "source_sha", "patch_sha256", "rubric_sha256",
         "case_digests", "cycle", "prior_cycle_digest"}
_SUBMISSION = {"schema", "role", "model_family", "model_id", "operator_digest",
               "source_sha", "patch_sha256", "plan_sha256", "submission_sha256",
               "response_sha256", "observed_at_utc", "rows"}
_ROW = {"case_sha256", "verdict", "reason"}


class TriadHold(ValueError):
    """Only a fixed refusal code. Never print case IDs, model text or secrets."""


def _require(ok: bool, code: str) -> None:
    if not ok:
        raise TriadHold(code)


def _shape(obj: Any, keys: set[str], code: str) -> dict:
    _require(type(obj) is dict and set(obj) == keys, code)
    return obj


def _sha(obj: Any, pattern: re.Pattern[str], n: int) -> bool:
    return type(obj) is str and pattern.fullmatch(obj) is not None and obj != "0" * n


def _canonical(obj: Any) -> bytes:
    try:
        wire = json.dumps(obj, sort_keys=True, ensure_ascii=True,
                          allow_nan=False, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, OverflowError, RecursionError):
        raise TriadHold("NONCANONICAL_INPUT") from None
    _require(0 < len(wire) <= MAX_PACKET_BYTES, "INPUT_BYTE_BUDGET")
    return wire


def _moment(value: Any) -> datetime:
    _require(type(value) is str and 16 <= len(value) <= 40 and value.endswith("Z"),
             "TIMESTAMP_INVALID")
    try:
        dt = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise TriadHold("TIMESTAMP_INVALID") from None
    _require(dt.tzinfo is not None and dt.utcoffset() == timezone.utc.utcoffset(dt),
             "TIMESTAMP_INVALID")
    return dt


def _plan(plan: Any, expected_plan_sha256: Any, expected_source_sha: Any) -> tuple[dict, list[str]]:
    _shape(plan, _PLAN, "PLAN_SCHEMA_INVALID")
    _require(plan["schema"] == PLAN_SCHEMA, "PLAN_VERSION_INVALID")
    _require(type(plan["repository"]) is str and _REPO.fullmatch(plan["repository"]) is not None,
             "REPOSITORY_INVALID")
    _require(_sha(expected_source_sha, _SHA40, 40) and
             plan["source_sha"] == expected_source_sha, "SOURCE_PIN_INVALID")
    _require(_sha(plan["patch_sha256"], _SHA64, 64) and
             _sha(plan["rubric_sha256"], _SHA64, 64), "PATCH_OR_RUBRIC_INVALID")
    cycle = plan["cycle"]
    _require(type(cycle) is int and 1 <= cycle <= 10, "CYCLE_OUT_OF_BOUNDS")
    prior = plan["prior_cycle_digest"]
    _require(prior is None if cycle == 1 else _sha(prior, _SHA64, 64),
             "CYCLE_PREDECESSOR_INVALID")
    case_ids = plan["case_digests"]
    _require(type(case_ids) is list and 1 <= len(case_ids) <= MAX_CASES,
             "CASE_POPULATION_INVALID")
    _require(all(_sha(case, _SHA64, 64) for case in case_ids), "CASE_ID_INVALID")
    _require(len(set(case_ids)) == len(case_ids), "DUPLICATE_CASE")
    _require(_sha(expected_plan_sha256, _SHA64, 64), "PLAN_DIGEST_INVALID")
    _require(sha256(PLAN_DOMAIN + _canonical(plan)).hexdigest() == expected_plan_sha256,
             "FROZEN_PLAN_DIGEST_MISMATCH")
    return plan, case_ids


def plan_digest(plan: Any) -> str:
    """Deterministic, self-declared plan identity. NOT signer/preregistration."""
    _shape(plan, _PLAN, "PLAN_SCHEMA_INVALID")
    return sha256(PLAN_DOMAIN + _canonical(plan)).hexdigest()


def _failure(code: str) -> dict:
    return {
        "schema": REPORT_SCHEMA, "state": "HOLD", "reason": code,
        "identity_authenticated": False, "reviewers_independent_verified": False,
        "signatures_verified": False, "source_signature_verified": False,
        "test_evidence_verified": False, "frozen_plan_preregistered": False,
        "cycle_predecessor_independently_verified": False,
        "merge_authorized": False, "deployment_authorized": False,
        "training_authorized": False, "provider_writes_performed": False,
        "production_qualified": False,
    }


def _compile(plan: Any, submissions: Any, *, expected_plan_sha256: Any,
             expected_source_sha: Any, now: Any) -> dict:
    _require(type(now) is datetime and now.tzinfo is not None and
             now.utcoffset() is not None, "INDEPENDENT_CLOCK_REQUIRED")
    now = now.astimezone(timezone.utc)
    plan, case_ids = _plan(plan, expected_plan_sha256, expected_source_sha)
    _require(type(submissions) is list and len(submissions) <= 3,
             "SUBMISSION_COUNT_INVALID")
    _canonical(submissions)

    by_role: dict[str, dict] = {}
    seen_names: set[str] = set()
    seen_submissions: set[str] = set()
    response_digests: set[str] = set()
    seen_operators: set[str] = set()
    suspicious: set[str] = set()
    for submission in submissions:
        sub = _shape(submission, _SUBMISSION, "SUBMISSION_SCHEMA_INVALID")
        _require(sub["schema"] == SUBMISSION_SCHEMA, "SUBMISSION_VERSION_INVALID")
        role, family = sub["role"], sub["model_family"]
        _require(type(role) is str and role in ROLE_FAMILIES and
                 type(family) is str and ROLE_FAMILIES[role] == family,
                 "DECLARED_SLOT_FAMILY_MISMATCH")
        _require(role not in by_role, "DUPLICATE_REVIEWER_SLOT")
        name = sub["model_id"]
        _require(type(name) is str and _MODEL.fullmatch(name) is not None and
                 "://" not in name and "//" not in name and "../" not in name and
                 "/.." not in name, "MODEL_ID_INVALID")
        _require(name not in seen_names, "DUPLICATE_DECLARED_MODEL")
        seen_names.add(name)
        for key in ("operator_digest", "submission_sha256", "response_sha256"):
            _require(_sha(sub[key], _SHA64, 64), "REVIEW_DIGEST_INVALID")
        _require(sub["submission_sha256"] not in seen_submissions,
                 "REPLAYED_SUBMISSION_ID")
        seen_submissions.add(sub["submission_sha256"])
        if sub["operator_digest"] in seen_operators:
            suspicious.add("DECLARED_OPERATOR_COLLISION")
        seen_operators.add(sub["operator_digest"])
        if sub["response_sha256"] in response_digests:
            suspicious.add("DUPLICATE_RESPONSE_DIGEST")
        response_digests.add(sub["response_sha256"])
        _require(sub["source_sha"] == plan["source_sha"] and
                 sub["patch_sha256"] == plan["patch_sha256"] and
                 sub["plan_sha256"] == expected_plan_sha256,
                 "REVIEW_SOURCE_OR_PLAN_MISMATCH")
        age = (now - _moment(sub["observed_at_utc"])).total_seconds()
        if not -5 <= age <= MAX_AGE_SECONDS:
            suspicious.add("STALE_OR_FUTURE_DECLARATION")

        rows = sub["rows"]
        _require(type(rows) is list and len(rows) == len(case_ids),
                 "REVIEW_POPULATION_INCOMPLETE")
        seen_cases: set[str] = set()
        for row in rows:
            row = _shape(row, _ROW, "REVIEW_ROW_SCHEMA_INVALID")
            key = row["case_sha256"]
            _require(_sha(key, _SHA64, 64) and key in set(case_ids),
                     "UNKNOWN_OR_SUBSTITUTED_CASE")
            _require(key not in seen_cases, "DUPLICATE_REVIEW_CASE")
            seen_cases.add(key)
            decision, reason = row["verdict"], row["reason"]
            _require(type(decision) is str and decision in VERDICT_REASONS and
                     type(reason) is str and reason in VERDICT_REASONS[decision],
                     "REVIEW_DECISION_REASON_INVALID")
        _require(seen_cases == set(case_ids), "REVIEW_COHORT_NOT_EXACT")
        by_role[role] = {row["case_sha256"]: row["verdict"] for row in rows}

    missing = sorted(set(ROLE_FAMILIES) - set(by_role))
    statuses = []
    total_dissent = total_abstain = total_unavailable = total_agree = 0
    for ordinal, case in enumerate(case_ids):
        decisions = [by_role[role][case] for role in sorted(by_role)]
        rejected = decisions.count("REJECT")
        abstained = decisions.count("ABSTAIN")
        unavailable = decisions.count("UNAVAILABLE")
        approved = decisions.count("APPROVE")
        if rejected:
            status = "HOLD_DISSENT"
            total_dissent += 1
        elif abstained:
            status = "HOLD_ABSTENTION"
            total_abstain += 1
        elif unavailable:
            status = "HOLD_UNAVAILABLE"
            total_unavailable += 1
        elif missing:
            status = "HOLD_MISSING_REVIEWER"
        else:
            status = "DECLARED_THREE_ROLE_AGREEMENT"
            total_agree += 1
        # Output deliberately excludes case IDs, prompts, raw reviewer text and
        # allegedly verified provider identities. Only frozen ordinal is shown.
        statuses.append({"case_ordinal": ordinal, "state": status,
                         "declared_approvals": approved, "declared_rejections": rejected,
                         "declared_abstentions": abstained,
                         "declared_unavailable": unavailable})

    reason = (
        "DECLARED_DISSENT" if total_dissent else
        "DECLARED_ABSTENTION" if total_abstain else
        "DECLARED_UNAVAILABLE" if total_unavailable else
        "MISSING_REVIEWER" if missing else
        "SUSPICIOUS_DECLARATIONS" if suspicious else
        "THREE_DECLARED_MATRIX_AGREEMENT_NOT_AUTHENTICATED"
    )
    result = {
        **_failure("OWNER_GATE_ALWAYS_REQUIRED"),
        "advisory_state": reason,
        "repository": plan["repository"],
        "plan_digest_not_signature": expected_plan_sha256,
        "source_sha_declared": plan["source_sha"],
        "patch_digest_declared": plan["patch_sha256"],
        "cycle": plan["cycle"], "max_supported_cycles": 10,
        "frozen_cases": len(case_ids),
        "declared_reviewer_slots": sorted(by_role),
        "missing_reviewer_slots": missing,
        "suspicious_declarations": sorted(suspicious),
        "dissenting_cases": total_dissent,
        "abstaining_cases": total_abstain,
        "unavailable_cases": total_unavailable,
        "declared_unanimous_cases": total_agree,
        "case_summaries": statuses,
    }
    result["unsigned_report_digest_not_signature"] = sha256(
        REPORT_DOMAIN + _canonical(result)
    ).hexdigest()
    return result


def compile_triad(plan: Any, submissions: Any, *, expected_plan_sha256: Any,
                  expected_source_sha: Any, now: Any) -> dict:
    """Offline advisory only; all outputs are HOLD for independent owner review."""
    try:
        return _compile(plan, submissions,
                        expected_plan_sha256=expected_plan_sha256,
                        expected_source_sha=expected_source_sha, now=now)
    except TriadHold as exc:
        return _failure(str(exc))
    except (TypeError, ValueError, OverflowError, RecursionError):
        return _failure("MALFORMED_INPUT")


def _unique_json(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise TriadHold("DUPLICATE_JSON_KEY")
        obj[key] = value
    return obj


def _no_nonfinite(_value):
    raise TriadHold("NONFINITE_JSON")


def load_json(path: Path) -> Any:
    """Bounded ordinary files only. Never deserialize archives, pickle or code."""
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= MAX_PACKET_BYTES:
        raise TriadHold("INPUT_UNAVAILABLE_OR_TOO_LARGE")
    raw = path.read_bytes()
    if not 0 < len(raw) <= MAX_PACKET_BYTES:
        raise TriadHold("INPUT_UNAVAILABLE_OR_TOO_LARGE")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_json,
                          parse_constant=_no_nonfinite)
    except (UnicodeError, ValueError) as exc:
        raise TriadHold("MALFORMED_JSON") from exc
