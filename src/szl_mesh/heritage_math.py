# SPDX-License-Identifier: Apache-2.0
"""A source-cited, offline ancient-mathematics *analogy* for SZL Mesh.

Pure stdlib mathematics, synthetic data only.  This does not decode physical
khipus, transcribe manuscripts, execute an agent, sign receipts, call Hatun,
read the Second Brain, run Lean, or create training data.  A successful numeric
witness is never authorization for an effect or evidence of historical intent.
"""
from __future__ import annotations

from datetime import datetime, timezone
from fractions import Fraction
from hashlib import sha256
import json
from math import gcd, lcm
import re
from typing import Any

SCHEMA = "szl.mesh.heritage-math-synthetic/v1"
WITNESS_SCHEMA = "szl.mesh.heritage-math-witness/v1"
MAX_INPUT_BYTES = 4_096
MAX_INTEGER = 1_000_000_000
MAX_FRACTION_TERMS = 12
MAX_DENOMINATOR = 10**12
MAX_EUCLID_STEPS = 64
DOCTRINE = "749/14/163"
LAMBDA_CLASS = "CONJECTURE_1_ADVISORY_NOT_A_THEOREM"
LOCKED8 = ("F1", "F4", "F7", "F11", "F12", "F18", "F19", "F22")
IDENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")

# Immutable GitHub source *references*, not verified live source, signed releases,
# manuscript rights, or a claim of independently reproduced measurements.
SOURCES = (
    {"id": "szl-ancient-lineage", "repository": "szl-holdings/a11oy",
     "path": "docs/ANCIENT_TEXTS_FORMULA_LINEAGE.md",
     "blob_sha1": "de7ddf67d5226ccc4ef4b9d2f3b57f6cf60285b6"},
    {"id": "szl-papers", "repository": "szl-holdings/szl-papers",
     "path": "metadata/locked-claim-contract.json",
     "blob_sha1": "191fba3278277e9cd0c93c95c079dda186c4099f"},
    {"id": "szl-okr-khipu", "repository": "szl-holdings/szl-khipu",
     "path": "research/okr_corpus/README.md",
     "blob_sha1": "034c01506fd33c8a3195ad2f8438ca032a788619"},
    {"id": "szl-formula-kernel", "repository": "szl-holdings/szl-formulas",
     "path": "torch-ext/szl_formulas/__init__.py",
     "blob_sha1": "f5c8f392afebbb983714bf09c7f9841695ecd4c7"},
)
HISTORICAL_REFERENCES = (
    {"tradition": "Inka khipu", "source": "https://github.com/khipulab/open-khipu-repository",
     "scope": "decimal numerical cords and scholarly transcription; not general decipherment"},
    {"tradition": "Egyptian Rhind mathematical papyrus", "source": "https://www.britishmuseum.org/sites/default/files/2022-10/Hieroglyphs_unlocking_ancient_Egypt_large_print_guide_The_British_Museum_2.pdf",
     "scope": "documented arithmetic, unit fractions and problems; modern algorithm below"},
    {"tradition": "Greek Euclid, Elements VII.2", "source": "https://mathcs.clarku.edu/~%20djoyce/elements/bookVII/propVII2.html",
     "scope": "common-measure reduction; modern modulo implementation"},
    {"tradition": "Babylonian YBC 7289", "source": "https://old.maa.org/press/periodicals/convergence/the-best-known-old-babylonian-tablet",
     "scope": "base-60 numerical notation; this code is not a tablet transcription"},
    {"tradition": "Maya Dresden Codex", "source": "https://www.slub-dresden.de/en/explore/manuscripts/the-dresden-maya-codex",
     "scope": "codex/cyclical calendar metadata only, not a read of astronomical tables"},
)


def _json_bytes(value: Any, *, limit: int) -> bytes:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False).encode("ascii")
    if len(raw) > limit:
        raise ValueError("bounded JSON packet required")
    return raw


def _strict_fields(value: Any, keys: set[str], label: str) -> None:
    if type(value) is not dict or set(value) != keys:
        raise ValueError("invalid " + label + " shape")


def _uint(value: Any, *, positive: bool = False) -> int:
    if type(value) is not int or not (1 if positive else 0) <= value <= MAX_INTEGER:
        raise ValueError("bounded integer required")
    return value


def _digits(value: Any, base: int, *, max_count: int) -> int:
    if (type(value) is not list or not 1 <= len(value) <= max_count
            or any(type(n) is not int or not 0 <= n < base for n in value)
            or (len(value) > 1 and value[0] == 0)):
        raise ValueError("canonical positional digit vector required")
    number = 0
    for digit in value:
        number = number * base + digit
        if number > MAX_INTEGER:
            raise ValueError("numerical capacity exceeded")
    return number


def inka_decimal_value(digits: list[int]) -> int:
    """Modern abstract decimal place-value model; NEVER a physical knot decoder."""
    return _digits(digits, 10, max_count=10)


def sexagesimal_value(digits: list[int]) -> int:
    """Modern positional base-60 model, not an interpretation of any tablet."""
    return _digits(digits, 60, max_count=6)


def egyptian_doubling_multiply(left: int, right: int) -> tuple[int, list[list[int]]]:
    """Binary/doubling multiplication by exact addition, with a bounded trace."""
    left, right = _uint(left), _uint(right)
    if left * right > MAX_INTEGER:
        raise ValueError("product capacity exceeded")
    steps: list[list[int]] = []
    mul, addend, total = left, right, 0
    while mul:
        if mul & 1:
            total += addend
            steps.append([mul, addend])
        mul >>= 1
        addend *= 2
    assert total == left * right  # local arithmetic assertion, NOT historical proof
    return total, steps


def euclid_remainder_gcd(left: int, right: int) -> tuple[int, list[list[int]]]:
    """Modern equivalent of Euclidean mutual-subtraction common-measure steps."""
    left, right = _uint(left, positive=True), _uint(right, positive=True)
    steps: list[list[int]] = []
    while right:
        quotient, remainder = divmod(left, right)
        if len(steps) >= MAX_EUCLID_STEPS:
            raise ValueError("Euclid step budget exhausted")
        steps.append([left, right, quotient, remainder])
        left, right = right, remainder
    return left, steps


def unit_fraction_decomposition(numerator: int, denominator: int) -> list[int]:
    """A modern greedy Egyptian-fraction *analogy*, not Rhind table replay.

    For 0 < n/d < 1, returns increasing unit denominators.  Stops rather
    than creating arbitrarily large values or implying a manuscript solution.
    """
    numerator, denominator = _uint(numerator, positive=True), _uint(denominator, positive=True)
    if numerator >= denominator:
        raise ValueError("proper positive fraction required")
    rest = Fraction(numerator, denominator)
    terms: list[int] = []
    while rest > 0:
        if len(terms) >= MAX_FRACTION_TERMS:
            raise ValueError("unit fraction step budget exhausted")
        d = (rest.denominator + rest.numerator - 1) // rest.numerator
        if d > MAX_DENOMINATOR or (terms and d <= terms[-1]):
            raise ValueError("unit fraction denominator budget exhausted")
        terms.append(d)
        rest -= Fraction(1, d)
    if sum((Fraction(1, d) for d in terms), Fraction()) != Fraction(numerator, denominator):
        raise ValueError("unit fraction identity mismatch")
    return terms


def false_position_linear(coefficient: int, target: int, trial: int) -> dict[str, int]:
    """Modern exact proportional correction for c*x=t with positive integers."""
    coefficient = _uint(coefficient, positive=True)
    target = _uint(target)
    trial = _uint(trial, positive=True)
    estimate = Fraction(trial * target, coefficient * trial)
    if coefficient * estimate != target:
        raise ValueError("false-position equality mismatch")
    return {"solution_numerator": estimate.numerator,
            "solution_denominator": estimate.denominator,
            "trial_result": coefficient * trial}


def babylonian_ybc7289_sqrt2_residual() -> Fraction:
    """Exact modern residual for the recorded 1;24,51,10 sexagesimal value.

    The tablet value and its reading come from published scholarship; this
    module does not inspect the tablet image, transcribe cuneiform or prove
    how the ancient approximation was derived.
    """
    value = Fraction(1) + Fraction(24, 60) + Fraction(51, 60**2) + Fraction(10, 60**3)
    return value * value - 2


def calendar_round_days() -> int:
    """Modern LCM of documented calendar periods; NOT codex decipherment."""
    return lcm(260, 365)


def compile_heritage_witness(packet: dict[str, Any]) -> dict[str, Any]:
    """Return an exact synthetic arithmetic proposal without authority/effects."""
    allowed = {"schema", "tenant", "event_id", "input_class", "inka_digits",
               "babylonian_digits", "egyptian_factor", "gcd_partner", "fraction",
               "false_position", "calendar_periods"}
    _strict_fields(packet, allowed, "heritage packet")
    _json_bytes(packet, limit=MAX_INPUT_BYTES)
    if packet["schema"] != SCHEMA:
        raise ValueError("unsupported heritage packet schema")
    for k in ("tenant", "event_id"):
        if type(packet[k]) is not str or not IDENT.fullmatch(packet[k]):
            raise ValueError("opaque tenant/event identifiers required")
    reasons: list[str] = []
    if packet["input_class"] != "SYNTHETIC" or type(packet["input_class"]) is not str:
        reasons.append("CULTURAL_ARTIFACT_ADMISSION_NOT_PROVIDED")
    inka = inka_decimal_value(packet["inka_digits"])
    base60 = sexagesimal_value(packet["babylonian_digits"])
    factor = _uint(packet["egyptian_factor"])
    partner = _uint(packet["gcd_partner"], positive=True)
    _strict_fields(packet["fraction"], {"numerator", "denominator"}, "fraction")
    _strict_fields(packet["false_position"], {"coefficient", "target", "trial"}, "false position")
    if packet["calendar_periods"] != [260, 365] or type(packet["calendar_periods"]) is not list:
        raise ValueError("fixed calendar periods required")
    egyptian_product, doubles = egyptian_doubling_multiply(inka, factor)
    euclid_result, divisions = euclid_remainder_gcd(max(inka, 1), partner)
    numerator, denominator = packet["fraction"]["numerator"], packet["fraction"]["denominator"]
    terms: list[int] = []
    try:
        terms = unit_fraction_decomposition(numerator, denominator)
    except ValueError:
        # Retain a bounded mathematical HOLD, not an implicit success or
        # an unbounded denominator growth exception.
        reasons.append("UNIT_FRACTION_NOT_RESOLVED_WITHIN_POLICY")
    fp = false_position_linear(**packet["false_position"])
    if inka != base60:
        reasons.append("CROSS_NOTATION_VALUE_MISMATCH")
    if inka == 0:
        reasons.append("ZERO_QUANTITY_NOT_ADMITTED_FOR_GCD_COMPOSITION")
    if euclid_result != gcd(max(inka, 1), partner):
        reasons.append("GCD_CONSERVATION_FAILED")
    if egyptian_product != inka * factor:
        reasons.append("DOUBLING_CONSERVATION_FAILED")
    core = {
        "schema": WITNESS_SCHEMA,
        "scope": "OFFLINE_SYNTHETIC_MATH_ONLY",
        "state": "HOLD" if reasons else "NUMERIC_ANALOGY_READY_FOR_REVIEW",
        "reasons": sorted(set(reasons)),
        "tenant_digest": sha256(packet["tenant"].encode()).hexdigest(),
        "input_sha256": sha256(_json_bytes(packet, limit=MAX_INPUT_BYTES)).hexdigest(),
        "source_refs": list(SOURCES),
        "reference_count": len(HISTORICAL_REFERENCES),
        "source_attribution_is_math_inspiration": True,
        "historical_claims_verified": False,
        "ocr_or_artifact_decipherment_performed": False,
        "okr_corpus_replayed": False,
        "papers_claim_promoted": False,
        "lean_kernel_rechecked": False,
        "numerical_proof_class": "PYTHON_EXACT_ARITHMETIC_SYNTHETIC_NOT_LEAN",
        "doctrine": DOCTRINE,
        "locked_proven_reference": list(LOCKED8),
        "lambda_claim": LAMBDA_CLASS,
        "math": {
            "inka_abstract_decimal": inka,
            "babylonian_abstract_sexagesimal": base60,
            "egyptian_doubling_product": egyptian_product,
            "egyptian_selected_double_count": len(doubles),
            "greek_euclid_gcd": euclid_result,
            "greek_division_steps": len(divisions),
            "egyptian_modern_unit_fraction_denominators": terms,
            "egyptian_false_position": fp,
            "maya_calendar_lcm_days": calendar_round_days(),
            "babylonian_ybc7289_sqrt2_squared_residual": {
                "numerator": babylonian_ybc7289_sqrt2_residual().numerator,
                "denominator": babylonian_ybc7289_sqrt2_residual().denominator,
            },
        },
        "hatun_tools_invoked": 0,
        "second_brain_private_rows_read": 0,
        "anatomy_runtime_verified": False,
        "ouroboros_training_started": False,
        "sql_effects": 0,
        "authorized_effects": 0,
        "independent_witness_present": False,
        "receipt_signed": False,
        "runtime_ready": False,
        "model_training_authorized": False,
    }
    return {**core, "unsigned_sha256": sha256(_json_bytes(core, limit=16_384)).hexdigest()}


def verify_heritage_witness(witness: Any) -> bool:
    """Check only source-record checksum/shape, NEVER origin or permission."""
    if type(witness) is not dict:
        return False
    try:
        digest = witness.get("unsigned_sha256")
        core = {k: v for k, v in witness.items() if k != "unsigned_sha256"}
        if type(digest) is not str or SHA256.fullmatch(digest) is None:
            return False
        if sha256(_json_bytes(core, limit=16_384)).hexdigest() != digest:
            return False
        return (core.get("schema") == WITNESS_SCHEMA
                and core.get("scope") == "OFFLINE_SYNTHETIC_MATH_ONLY"
                and core.get("state") in ("HOLD", "NUMERIC_ANALOGY_READY_FOR_REVIEW")
                and core.get("historical_claims_verified") is False
                and core.get("ocr_or_artifact_decipherment_performed") is False
                and core.get("okr_corpus_replayed") is False
                and core.get("papers_claim_promoted") is False
                and core.get("lean_kernel_rechecked") is False
                and core.get("independent_witness_present") is False
                and core.get("receipt_signed") is False
                and core.get("runtime_ready") is False
                and core.get("model_training_authorized") is False
                and core.get("authorized_effects") == 0
                and core.get("hatun_tools_invoked") == 0
                and core.get("sql_effects") == 0
                and core.get("second_brain_private_rows_read") == 0
                and core.get("ouroboros_training_started") is False)
    except (ValueError, OverflowError, TypeError):
        return False

JOINT_SCHEMA = "szl.mesh.organ-heritage-junction/v1"


def compile_joint_advisory(organ_packet: dict[str, Any], heritage_packet: dict[str, Any], *, now: datetime) -> dict[str, Any]:
    """Bind two already-scoped *unsigned proposals*; never combine permissions.

    Consumes the existing eight-organ Source Only junction unchanged, so
    Second Brain/Anatomy/Ouroboros/Hatun and real Khipu remain canonical owners.
    No caller-provided `approved`/`signed` field can become a tool permit.
    """
    from .agentic_fabric import compile_advisory, verify_advisory

    organs = compile_advisory(organ_packet, now=now)
    history = compile_heritage_witness(heritage_packet)
    if not verify_advisory(organs) or not verify_heritage_witness(history):
        raise ValueError("unverifiable parent proposal")
    reasons: list[str] = []
    if organ_packet["tenant"] != heritage_packet["tenant"]:
        reasons.append("CROSS_TENANT_EVIDENCE_REFUSED")
    if organs["state"] != "PROPOSAL_READY_FOR_OWNER_REVIEW":
        reasons.append("EIGHT_ORGAN_EVIDENCE_NOT_ADMITTED")
    if history["state"] != "NUMERIC_ANALOGY_READY_FOR_REVIEW":
        reasons.append("HERITAGE_NUMERIC_WITNESS_NOT_ADMITTED")
    core = {
        "schema": JOINT_SCHEMA,
        "state": "HOLD" if reasons else "JOINT_PROPOSAL_READY_FOR_OWNER_REVIEW",
        "scope": "TWO_OFFLINE_UNSIGNED_PROPOSALS_NO_EFFECT_AUTHORITY",
        "reasons": reasons,
        "organ_proposal_sha256": organs["unsigned_sha256"],
        "heritage_proposal_sha256": history["unsigned_sha256"],
        "tenant_digest": sha256(organ_packet["tenant"].encode()).hexdigest(),
        "math_input_class": heritage_packet["input_class"],
        "source_count_reported_by_organ_advisory": organs["source_count_supplied"],
        "math_source_refs_count": len(SOURCES),
        "lambda_claim": LAMBDA_CLASS,
        "receipt_signed": False,
        "tools_invoked": 0,
        "agent_actions_executed": 0,
        "training_dispatched": False,
        "sql_writes": 0,
        "authorized_effects": 0,
        "production_ready": False,
    }
    return {**core, "unsigned_sha256": sha256(_json_bytes(core, limit=16_384)).hexdigest()}


def verify_joint_advisory(record: Any) -> bool:
    """Recompute only the unsigned joint checksum and hard non-authority flags."""
    if type(record) is not dict or type(record.get("unsigned_sha256")) is not str:
        return False
    try:
        payload = {k: v for k, v in record.items() if k != "unsigned_sha256"}
        return (
            SHA256.fullmatch(record["unsigned_sha256"]) is not None
            and sha256(_json_bytes(payload, limit=16_384)).hexdigest() == record["unsigned_sha256"]
            and payload.get("schema") == JOINT_SCHEMA
            and payload.get("scope") == "TWO_OFFLINE_UNSIGNED_PROPOSALS_NO_EFFECT_AUTHORITY"
            and payload.get("state") in ("HOLD", "JOINT_PROPOSAL_READY_FOR_OWNER_REVIEW")
            and payload.get("receipt_signed") is False
            and payload.get("training_dispatched") is False
            and payload.get("production_ready") is False
            and payload.get("tools_invoked") == 0
            and payload.get("agent_actions_executed") == 0
            and payload.get("authorized_effects") == 0
            and payload.get("sql_writes") == 0
            and type(payload.get("organ_proposal_sha256")) is str
            and SHA256.fullmatch(payload["organ_proposal_sha256"]) is not None
            and type(payload.get("heritage_proposal_sha256")) is str
            and SHA256.fullmatch(payload["heritage_proposal_sha256"]) is not None
        )
    except (TypeError, ValueError, OverflowError):
        return False
