# SPDX-License-Identifier: Apache-2.0
"""Source-only, fail-closed Python junction for SZL's research organs.

This module performs no provider I/O, source imports, SQL writes, tool calls,
training, signature verification, policy admission or cryptographic signing.
The result is an UNSIGNED proposal record; it cannot authorize effects.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
import re
from typing import Any, Mapping

SCHEMA = "szl.mesh.agentic-organ-proposal/v1"
MAX_BYTES = 32_768
MAX_AGE_SECONDS = 3600
MAX_ORO_STEPS = 12
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA64 = re.compile(r"^[0-9a-f]{64}$")
IDENT = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$")
DOCTRINE = "749/14/163"
KERNEL_PIN = "c7c0ba17"
LAMBDA_STATUS = "CONJECTURE_1_ADVISORY"
LOCKED8 = frozenset({"F1", "F4", "F7", "F11", "F12", "F18", "F19", "F22"})

# Exact observed GitHub source identities, NOT an attested deployment manifest.
# Changes require a source review, not a moving branch name or auto-refresh.
SOURCE_PINS = {
    "second_brain": ("szl-second-brain", "73e8e4388268d092c50eac849d2a6f22a18418f2"),
    "anatomy": ("anatomy", "02d9dbbac66993015005e423f2123dde3dc3b4a7"),
    "ouroboros": ("szl-ouroboros", "f3713283d6ef8fb00acd46f1430ba095e12016c9"),
    "formulas": ("szl-formulas", "6e6c18ade01acec627eed04645e6e9c661916cb4"),
    "invariants": ("szl-invariants", "233833d00163b255836ec72b5a0b4f53b8f11e17"),
    "hatun": ("hatun-mcp", "1cec84742e07c151a34c329ae2fb50dd5f87c7ab"),
    "lean": ("lutar-lean", "80e35f859801d80fce7cf81e4d9b0c8bdf91cfea"),
    "khipu": ("szl-khipu", "54849c8458dddd7a77473201777d5ff644237f9a"),
}

# These are historical locked-eight labels, NOT mappings to the 21 formula APIs.
FORMULAS21 = frozenset({
    "lambda_aggregate", "lambda_homogeneous", "lambda_bounded", "pac_bayes_mcallester",
    "bekenstein_cascade", "reidemeister_invariant", "khipu_merkle_root",
    "dsse_envelope", "gleason_quantum_lambda", "hoeffding_tail",
    "pinsker_kl_bound", "fisher_rao_distance", "bohr_complementarity_floor",
    "kochen_specker_18vector_witness", "two_witness_ks18_soundness",
    "shor_codeword_distance", "css_ingress_verify", "kitaev_surface_correct",
    "reed_solomon_singleton", "madhava_series", "schur_concave_lambda_two_axis",
})
INVARIANTS8 = frozenset({
    "receipt-chain-continuity", "ledger-failure-shape", "served-run-has-model",
    "signed-columns-atomic", "loop-steps-positive", "receipt-ed25519-verify",
    "receipt-columns-consistent", "flywheel-lineage",
})
ORGANS5 = frozenset({"YUYAY", "YAWAR", "YACHAY", "OTEL", "KHIPU"})
# The catalog is explicitly proposal-only. Never dispatch an MCP tool here.
READONLY_HATUN = frozenset({
    "szl_doctrine_lookup", "szl_anatomy_3d_render", "szl_formula_evaluate",
    "szl_lean_verify", "szl_khipu_verify", "szl_frontier_chain_read",
})
EDGES = (
    ("second_brain", "ouroboros"),
    ("ouroboros", "anatomy"),
    ("anatomy", "formulas"),
    ("formulas", "invariants"),
    ("lean", "invariants"),
    ("invariants", "hatun"),
    ("khipu", "hatun"),
)


def _canonical(value: Any) -> bytes:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False).encode("ascii")
    if len(raw) > MAX_BYTES:
        raise ValueError("source-only packet exceeds byte budget")
    return raw


def _keys(obj: Any, allowed: set[str], required: set[str], what: str) -> None:
    if type(obj) is not dict or set(obj) - allowed or not required <= set(obj):
        raise ValueError(f"invalid {what} shape")


def _utc(value: Any) -> datetime:
    if type(value) is not str or len(value) > 40:
        raise ValueError("timestamp required")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid timestamp") from exc
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ValueError("timezone-aware timestamp required")
    return dt.astimezone(timezone.utc)


def _acyclic(nodes: set[str], edges: Any) -> bool:
    if type(edges) is not list or len(edges) > 32:
        raise ValueError("bounded graph edges required")
    indegree = {n: 0 for n in nodes}
    next_nodes = {n: set() for n in nodes}
    for edge in edges:
        if type(edge) is not list or len(edge) != 2 or any(type(n) is not str or n not in nodes for n in edge):
            raise ValueError("invalid graph edge")
        a, b = edge
        if a == b:
            return False
        if b not in next_nodes[a]:
            next_nodes[a].add(b)
            indegree[b] += 1
    ready = sorted(n for n in nodes if indegree[n] == 0)
    seen = 0
    while ready:
        n = ready.pop(0)
        seen += 1
        for child in sorted(next_nodes[n]):
            indegree[child] -= 1
            if indegree[child] == 0:
                ready.append(child)
                ready.sort()
    return seen == len(nodes)


def compile_advisory(packet: dict[str, Any], *, now: datetime) -> dict[str, Any]:
    """Compile a replayable, untrusted *proposal* from eight source-bound owners.

    No returned field can be used as tool or production authority; downstream
    owners must independently verify source, signer, revocation, tenant and effect.
    """
    _keys(packet, {"schema", "tenant", "event_id", "sources", "handles", "organs",
                   "formulas", "invariants", "hatun_tool", "oro_steps", "oro_terminated",
                   "lambda_status", "locked8", "edges"},
          {"schema", "tenant", "event_id", "sources", "handles", "organs",
           "formulas", "invariants", "hatun_tool", "oro_steps", "oro_terminated",
           "lambda_status", "locked8"}, "packet")
    if packet["schema"] != SCHEMA:
        raise ValueError("wrong packet schema")
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("independent aware clock required")
    now = now.astimezone(timezone.utc)
    for key in ("tenant", "event_id"):
        if type(packet[key]) is not str or IDENT.fullmatch(packet[key]) is None:
            raise ValueError("opaque tenant/event identifiers required")
    if packet["lambda_status"] != LAMBDA_STATUS or type(packet["locked8"]) is not list or (
        len(packet["locked8"]) != 8 or
        any(type(x) is not str for x in packet["locked8"]) or
        set(packet["locked8"]) != LOCKED8
    ):
        raise ValueError("false mathematical proof claim")
    if type(packet["oro_steps"]) is not int or not 0 <= packet["oro_steps"] <= MAX_ORO_STEPS:
        raise ValueError("unbounded Ouroboros step count")
    if type(packet["oro_terminated"]) is not bool:
        raise ValueError("Ouroboros termination must be explicit")
    if type(packet["hatun_tool"]) is not str or len(packet["hatun_tool"]) > 80:
        raise ValueError("Hatun tool must be literal")
    _canonical(packet)  # reject non-JSON, non-finite and oversized input up front
    reasons: set[str] = set()

    # All declared source identities remain DATA. A digest or matching SHA
    # is not a DSSE signature and does not authenticate an authority grant.
    sources = packet["sources"]
    if type(sources) is not dict or set(sources) - set(SOURCE_PINS):
        raise ValueError("unknown source owner")
    for owner, (_, pin) in SOURCE_PINS.items():
        entry = sources.get(owner)
        if entry is None:
            reasons.add(f"SOURCE_MISSING:{owner}")
            continue
        _keys(entry, {"revision", "digest", "observed_utc", "state", "tenant"},
              {"revision", "digest", "observed_utc", "state", "tenant"}, "source")
        if type(entry["revision"]) is not str or SHA40.fullmatch(entry["revision"]) is None or entry["revision"] != pin:
            reasons.add(f"SOURCE_REVISION_MISMATCH:{owner}")
        if type(entry["digest"]) is not str or SHA64.fullmatch(entry["digest"]) is None:
            reasons.add(f"SOURCE_DIGEST_UNAVAILABLE:{owner}")
        if entry["tenant"] != packet["tenant"]:
            reasons.add(f"SOURCE_TENANT_MISMATCH:{owner}")
        if entry["state"] != "OBSERVED":
            reasons.add(f"SOURCE_UNOBSERVED:{owner}")
        age = (now - _utc(entry["observed_utc"])).total_seconds()
        if not -5 <= age <= MAX_AGE_SECONDS:
            reasons.add(f"SOURCE_STALE:{owner}")

    handles = packet["handles"]
    if type(handles) is not list or len(handles) > 16:
        raise ValueError("bounded public handles only")
    seen_handles = set()
    for handle in handles:
        _keys(handle, {"digest", "source_revision", "tenant", "review_state"},
              {"digest", "source_revision", "tenant", "review_state"}, "memory handle")
        if type(handle["digest"]) is not str or SHA64.fullmatch(handle["digest"]) is None:
            reasons.add("MEMORY_DIGEST_INVALID")
        else:
            if handle["digest"] in seen_handles:
                reasons.add("MEMORY_DUPLICATE")
            seen_handles.add(handle["digest"])
        if handle["source_revision"] != SOURCE_PINS["second_brain"][1] or handle["tenant"] != packet["tenant"]:
            reasons.add("MEMORY_SOURCE_OR_TENANT_MISMATCH")
        if handle["review_state"] != "REVIEWED_PUBLIC":
            reasons.add("MEMORY_REVIEW_REQUIRED")

    organs = packet["organs"]
    if type(organs) is not dict or set(organs) != ORGANS5:
        raise ValueError("five named Anatomy organs required")
    for name, state in organs.items():
        if state not in ("UP", "DOWN", "UNAVAILABLE") or type(state) is not str:
            raise ValueError("invalid organ observation state")
        if state != "UP":
            reasons.add(f"ANATOMY_NOT_UP:{name}")

    formulas = packet["formulas"]
    if type(formulas) is not list or len(formulas) > 4 or any(type(f) is not str or f not in FORMULAS21 for f in formulas):
        raise ValueError("unreviewed or unbounded formula identifier")
    if len(set(formulas)) != len(formulas):
        reasons.add("DUPLICATED_FORMULA")

    invariants = packet["invariants"]
    if type(invariants) is not dict or set(invariants) != INVARIANTS8:
        raise ValueError("exact eight runtime-invariant results required")
    for key, state in invariants.items():
        if type(state) is not str or state not in ("HOLDS", "VIOLATED", "KEY_ROTATED", "NO_DATA", "UNAVAILABLE"):
            raise ValueError("invalid invariant status")
        if state != "HOLDS":
            reasons.add(f"INVARIANT_NOT_HOLDS:{key}")

    if packet["hatun_tool"] not in READONLY_HATUN:
        reasons.add("HATUN_TOOL_NOT_IN_READONLY_CATALOG")
    if not packet["oro_terminated"]:
        reasons.add("OUROBOROS_NOT_TERMINATED")
    edges = packet.get("edges", [list(e) for e in EDGES])
    if not _acyclic(set(SOURCE_PINS), edges):
        reasons.add("EVIDENCE_GRAPH_CYCLE")

    core = {
        "schema": SCHEMA,
        "scope": "OFFLINE_SOURCE_ONLY_NO_PROVIDER_EFFECTS",
        "evaluated_utc": now.isoformat(),
        "event_digest": sha256(_canonical({"event": packet["event_id"], "tenant": packet["tenant"]})).hexdigest(),
        "source_count_expected": len(SOURCE_PINS),
        "source_count_supplied": len(sources),
        "source_pins": {owner: {"repo": f"szl-holdings/{name}", "revision": pin}
                        for owner, (name, pin) in SOURCE_PINS.items()},
        "public_handle_count": len(handles),
        "anatomy_organs_observed": len(organs),
        "invariant_results_supplied": len(invariants),
        "formula_registry_count": len(FORMULAS21),
        "formula_calls_executed": 0,
        "formula_queries": list(formulas),
        "locked_proven_identifiers": sorted(LOCKED8),
        "lean_kernel_context": KERNEL_PIN,
        "doctrine_version": DOCTRINE,
        "lambda_status": LAMBDA_STATUS,
        "ouroboros_steps_declared": packet["oro_steps"],
        "ouroboros_max_steps": MAX_ORO_STEPS,
        "hatun_proposed_tool": packet["hatun_tool"],
        "reasons": sorted(reasons),
        "state": "HOLD" if reasons else "PROPOSAL_READY_FOR_OWNER_REVIEW",
        "source_witness_independently_authenticated": False,
        "invariant_results_independently_recomputed": False,
        "lean_proofs_rechecked": False,
        "mcp_tools_executed": 0,
        "agent_actions_executed": 0,
        "authorized_effects": 0,
        "receipt_signed": False,
        "training_dispatched": False,
        "production_ready": False,
    }
    return {**core, "unsigned_sha256": sha256(_canonical(core)).hexdigest()}


def verify_advisory(record: dict[str, Any]) -> bool:
    """Recompute unsigned body digest; never interpret it as a signature."""
    if type(record) is not dict or "unsigned_sha256" not in record:
        return False
    try:
        body = {k: v for k, v in record.items() if k != "unsigned_sha256"}
        return (type(record["unsigned_sha256"]) is str and
                SHA64.fullmatch(record["unsigned_sha256"]) is not None and
                sha256(_canonical(body)).hexdigest() == record["unsigned_sha256"] and
                body.get("schema") == SCHEMA and
                body.get("scope") == "OFFLINE_SOURCE_ONLY_NO_PROVIDER_EFFECTS" and
                body.get("state") in ("HOLD", "PROPOSAL_READY_FOR_OWNER_REVIEW") and
                body.get("source_witness_independently_authenticated") is False and
                body.get("invariant_results_independently_recomputed") is False and
                body.get("lean_proofs_rechecked") is False and
                body.get("agent_actions_executed") == 0 and
                body.get("mcp_tools_executed") == 0 and
                body.get("authorized_effects") == 0 and
                body.get("receipt_signed") is False and
                body.get("training_dispatched") is False and
                body.get("production_ready") is False)
    except (ValueError, TypeError, OverflowError):
        return False