"""Deterministic, bounded scenario runner over the existing SZL Mesh CRDT."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from szl_mesh.crdt import (
    AUTHORIZED,
    OBSERVED,
    REVOKED,
    CRDTDocument,
    Op,
)

from .config import (
    DOC_ID_RE,
    MAX_DOC_ID_BYTES,
    MAX_KEY_BYTES,
    MAX_LAMPORT,
    MAX_NODE_ID_BYTES,
    MAX_OPERATIONS,
    MAX_REPLICAS,
    MAX_VALUE_BYTES,
    NODE_ID_RE,
    canonical_bytes,
    sha256_bytes,
)

TRACKS = {AUTHORIZED, OBSERVED, REVOKED}


class SimulationError(ValueError):
    """Raised when a scenario exceeds the lab's deterministic contract."""


def _bounded_text(value: Any, *, label: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise SimulationError(f"{label} must be a string")
    if value != value.strip() or not value:
        raise SimulationError(f"{label} must be non-empty without edge whitespace")
    if len(value.encode("utf-8")) > maximum:
        raise SimulationError(f"{label} exceeds byte limit")
    if any(ord(character) < 32 for character in value):
        raise SimulationError(f"{label} contains a control character")
    return value


def _normalize_operations(
    doc_id: str,
    replicas: int,
    operations: Sequence[Mapping[str, Any]],
) -> tuple[list[tuple[int, Op]], list[Op], int]:
    if not 1 <= len(operations) <= MAX_OPERATIONS:
        raise SimulationError(f"operations must contain 1 to {MAX_OPERATIONS} entries")

    delivered: list[tuple[int, Op]] = []
    unique: dict[str, Op] = {}
    duplicates = 0
    for index, row in enumerate(operations):
        if not isinstance(row, Mapping):
            raise SimulationError(f"operations[{index}] must be an object")
        unknown = set(row) - {
            "node_id",
            "key",
            "value",
            "lamport",
            "deletion",
            "track",
            "origin",
        }
        if unknown:
            raise SimulationError(
                f"operations[{index}] contains unsupported keys: {sorted(unknown)}"
            )
        node_id = _bounded_text(
            row.get("node_id"),
            label=f"operations[{index}].node_id",
            maximum=MAX_NODE_ID_BYTES,
        )
        if not NODE_ID_RE.fullmatch(node_id):
            raise SimulationError(f"operations[{index}].node_id has invalid shape")
        key = _bounded_text(
            row.get("key"),
            label=f"operations[{index}].key",
            maximum=MAX_KEY_BYTES,
        )
        lamport = row.get("lamport")
        if isinstance(lamport, bool) or not isinstance(lamport, int):
            raise SimulationError(f"operations[{index}].lamport must be an integer")
        if not 0 <= lamport <= MAX_LAMPORT:
            raise SimulationError(f"operations[{index}].lamport is outside bounds")
        deletion = row.get("deletion", False)
        if not isinstance(deletion, bool):
            raise SimulationError(f"operations[{index}].deletion must be boolean")
        track = row.get("track", OBSERVED)
        if track not in TRACKS:
            raise SimulationError(f"operations[{index}].track is unsupported")
        origin = row.get("origin", index % replicas)
        if isinstance(origin, bool) or not isinstance(origin, int):
            raise SimulationError(f"operations[{index}].origin must be an integer")
        if not 0 <= origin < replicas:
            raise SimulationError(f"operations[{index}].origin is outside replica range")
        value = row.get("value")
        try:
            value_bytes = canonical_bytes(value)
        except (TypeError, ValueError) as exc:
            raise SimulationError(
                f"operations[{index}].value is not finite JSON"
            ) from exc
        if len(value_bytes) > MAX_VALUE_BYTES:
            raise SimulationError(f"operations[{index}].value exceeds byte limit")

        operation = Op(
            doc_id=doc_id,
            key=key,
            value=value,
            lamport=lamport,
            node_id=node_id,
            deletion=deletion,
            track=track,
        )
        prior = unique.get(operation.op_id)
        if prior is not None:
            if prior.track != operation.track:
                raise SimulationError(
                    f"operations[{index}] reuses an op identity with a conflicting track"
                )
            duplicates += 1
        else:
            unique[operation.op_id] = operation
        delivered.append((origin, operation))
    return delivered, [unique[key] for key in sorted(unique)], duplicates


def _document(doc_id: str, operations: Sequence[Op]) -> CRDTDocument:
    document = CRDTDocument(doc_id)
    document.merge_ops(operations)
    return document


def _snapshot(name: str, document: CRDTDocument) -> dict[str, Any]:
    return {
        "replica": name,
        "operation_count": len(document),
        "heads": document.heads(),
        "authorized_view": document.authorized_view(),
        "observed_view": document.observed_view(),
        "authorized_digest": document.state_digest(AUTHORIZED),
        "observed_digest": document.state_digest(OBSERVED),
    }


def _order_for_replica(operations: Sequence[Op], index: int) -> list[Op]:
    values = list(operations)
    if not values:
        return values
    strategy = index % 4
    if strategy == 0:
        return values
    if strategy == 1:
        return list(reversed(values))
    if strategy == 2:
        offset = index % len(values)
        return values[offset:] + values[:offset]
    return sorted(values, key=lambda op: (op.key, -op.lamport, op.node_id, op.op_id))


def _commutativity_check(doc_id: str, operations: Sequence[Op]) -> bool:
    first = operations[::2]
    second = operations[1::2]
    left = _document(doc_id, first)
    right = _document(doc_id, second)

    first_then_second = _document(doc_id, left.all_ops())
    first_then_second.merge(right)
    second_then_first = _document(doc_id, right.all_ops())
    second_then_first.merge(left)
    return _snapshot("ab", first_then_second) | {"replica": "x"} == (
        _snapshot("ba", second_then_first) | {"replica": "x"}
    )


def _associativity_check(doc_id: str, operations: Sequence[Op]) -> bool:
    groups = [operations[index::3] for index in range(3)]
    a, b, c = (_document(doc_id, group) for group in groups)

    left = _document(doc_id, a.all_ops())
    left.merge(b)
    left.merge(c)

    b_then_c = _document(doc_id, b.all_ops())
    b_then_c.merge(c)
    right = _document(doc_id, a.all_ops())
    right.merge(b_then_c)
    return _snapshot("left", left) | {"replica": "x"} == (
        _snapshot("right", right) | {"replica": "x"}
    )


def simulate_scenario(value: Mapping[str, Any]) -> dict[str, Any]:
    """Run one finite scenario; this is evidence for that input, not a BFT proof."""
    if not isinstance(value, Mapping):
        raise SimulationError("scenario must be an object")
    unknown = set(value) - {"doc_id", "replicas", "operations"}
    if unknown:
        raise SimulationError(f"scenario contains unsupported keys: {sorted(unknown)}")
    doc_id = _bounded_text(
        value.get("doc_id"), label="doc_id", maximum=MAX_DOC_ID_BYTES
    )
    if not DOC_ID_RE.fullmatch(doc_id):
        raise SimulationError("doc_id has invalid shape")
    replicas = value.get("replicas")
    if isinstance(replicas, bool) or not isinstance(replicas, int):
        raise SimulationError("replicas must be an integer")
    if not 2 <= replicas <= MAX_REPLICAS:
        raise SimulationError(f"replicas must be between 2 and {MAX_REPLICAS}")
    operations_value = value.get("operations")
    if not isinstance(operations_value, list):
        raise SimulationError("operations must be an array")

    delivered, unique, duplicate_inputs = _normalize_operations(
        doc_id, replicas, operations_value
    )

    partitions = [CRDTDocument(doc_id) for _ in range(replicas)]
    for origin, operation in delivered:
        partitions[origin].add_op(operation)
    initial = [
        _snapshot(f"replica-{index + 1}", document)
        for index, document in enumerate(partitions)
    ]

    final_documents: list[CRDTDocument] = []
    idempotence = True
    for index in range(replicas):
        document = CRDTDocument(doc_id)
        document.merge_ops(_order_for_replica(unique, index))
        before = (
            document.state_digest(AUTHORIZED),
            document.state_digest(OBSERVED),
            tuple(document.heads()),
        )
        replay_additions = sum(1 for operation in unique if document.add_op(operation))
        after = (
            document.state_digest(AUTHORIZED),
            document.state_digest(OBSERVED),
            tuple(document.heads()),
        )
        idempotence = idempotence and replay_additions == 0 and before == after
        final_documents.append(document)

    final = [
        _snapshot(f"replica-{index + 1}", document)
        for index, document in enumerate(final_documents)
    ]
    observed_digests = {row["observed_digest"] for row in final}
    authorized_digests = {row["authorized_digest"] for row in final}
    head_sets = {tuple(row["heads"]) for row in final}
    convergence = (
        len(observed_digests) == 1
        and len(authorized_digests) == 1
        and len(head_sets) == 1
    )
    commutativity = _commutativity_check(doc_id, unique)
    associativity = _associativity_check(doc_id, unique)

    result: dict[str, Any] = {
        "schema": "szl.mesh-convergence-lab/v1",
        "status": (
            "CONVERGED"
            if convergence and idempotence and commutativity and associativity
            else "DIVERGED"
        ),
        "doc_id": doc_id,
        "replica_count": replicas,
        "input_operation_count": len(delivered),
        "unique_operation_count": len(unique),
        "duplicate_input_count": duplicate_inputs,
        "operation_ids": [operation.op_id for operation in unique],
        "initial_partitions": initial,
        "reconciled_replicas": final,
        "checks": {
            "same_operation_set_converged": convergence,
            "replay_idempotent": idempotence,
            "sample_merge_commutative": commutativity,
            "sample_merge_associative": associativity,
        },
        "evidence_boundary": {
            "scenario_bounded": True,
            "same_operation_set_required": True,
            "transport_exercised": False,
            "peer_enrollment_exercised": False,
            "dsse_signatures_verified": False,
            "byzantine_fault_tolerance_claimed": False,
            "tracks_are_scenario_inputs": True,
            "network_or_repository_mutation": False,
        },
    }
    result["receipt_sha256"] = sha256_bytes(canonical_bytes(result))
    return result


SCENARIOS: dict[str, dict[str, Any]] = {
    "two-track-signal": {
        "doc_id": "signal-grid",
        "replicas": 4,
        "operations": [
            {
                "node_id": "sensor-alpha",
                "key": "sector-7",
                "value": {"state": "nominal", "confidence": 0.91},
                "lamport": 10,
                "track": AUTHORIZED,
                "origin": 0,
            },
            {
                "node_id": "sensor-bravo",
                "key": "sector-7",
                "value": {"state": "anomaly", "confidence": 0.63},
                "lamport": 11,
                "track": OBSERVED,
                "origin": 1,
            },
            {
                "node_id": "operator",
                "key": "action",
                "value": "hold-for-corroboration",
                "lamport": 12,
                "track": AUTHORIZED,
                "origin": 2,
            },
        ],
    },
    "partition-rejoin": {
        "doc_id": "fleet-state",
        "replicas": 5,
        "operations": [
            {
                "node_id": "west",
                "key": "route",
                "value": "north",
                "lamport": 1,
                "track": AUTHORIZED,
                "origin": 0,
            },
            {
                "node_id": "east",
                "key": "route",
                "value": "south",
                "lamport": 1,
                "track": AUTHORIZED,
                "origin": 4,
            },
            {
                "node_id": "center",
                "key": "fuel",
                "value": 72,
                "lamport": 2,
                "track": OBSERVED,
                "origin": 2,
            },
        ],
    },
    "revocation-tombstone": {
        "doc_id": "policy-state",
        "replicas": 3,
        "operations": [
            {
                "node_id": "policy-a",
                "key": "rule-17",
                "value": "allow",
                "lamport": 1,
                "track": AUTHORIZED,
                "origin": 0,
            },
            {
                "node_id": "policy-b",
                "key": "rule-17",
                "value": None,
                "lamport": 2,
                "track": AUTHORIZED,
                "deletion": True,
                "origin": 1,
            },
            {
                "node_id": "forensics",
                "key": "discarded-claim",
                "value": "retained-for-awareness",
                "lamport": 3,
                "track": REVOKED,
                "origin": 2,
            },
        ],
    },
}
