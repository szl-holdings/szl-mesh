#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Deterministic, read-only CRDT merge observatory for SZL Mesh.

This service simulates disconnected-state convergence. It has no radio, socket,
peer-discovery, deployment, command-execution, or external mutation authority.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

APP_VERSION = "1.0.1"
SCHEMA = "szl.mesh-convergence-receipt/v1"
MAX_NODES = 64
MAX_CLOCK_ENTRIES = 64
MAX_RECORDS_PER_NODE = 1_000
MAX_TOTAL_RECORDS = 4_000
MAX_VALUE_BYTES = 16_384
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,95}$")
ROOT = Path(__file__).resolve().parents[1]
STATIC = Path(__file__).resolve().parent / "static"


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
        default=str,
    ).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def source_revision() -> str:
    value = (
        os.getenv("SOURCE_REVISION")
        or os.getenv("GIT_COMMIT")
        or os.getenv("SPACE_COMMIT_SHA")
        or ""
    ).strip().lower()
    return value if re.fullmatch(r"[0-9a-f]{40,64}", value) else "UNAVAILABLE"


class Clock(BaseModel):
    model_config = ConfigDict(extra="forbid")
    values: dict[str, int] = Field(default_factory=dict, max_length=MAX_CLOCK_ENTRIES)

    @field_validator("values")
    @classmethod
    def valid_values(cls, values: dict[str, int]) -> dict[str, int]:
        for node, counter in values.items():
            if not IDENTIFIER.fullmatch(node):
                raise ValueError(f"invalid clock node: {node!r}")
            if isinstance(counter, bool) or counter < 0 or counter > 2**53 - 1:
                raise ValueError(f"invalid clock counter for {node!r}")
        return values


class Register(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
    value: Any = None
    logical_time: int = Field(ge=0, le=2**53 - 1)
    writer: str = Field(min_length=1, max_length=96, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,95}$")
    tombstone: bool = False

    @field_validator("value")
    @classmethod
    def bounded_value(cls, value: Any) -> Any:
        if len(canonical(value)) > MAX_VALUE_BYTES:
            raise ValueError(f"register value exceeds {MAX_VALUE_BYTES} canonical bytes")
        return value


class Snapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")
    node_id: str = Field(min_length=1, max_length=96, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,95}$")
    clock: Clock = Field(default_factory=Clock)
    registers: list[Register] = Field(default_factory=list, max_length=MAX_RECORDS_PER_NODE)

    @model_validator(mode="after")
    def unique_register_keys(self) -> "Snapshot":
        keys = [record.key for record in self.registers]
        if len(keys) != len(set(keys)):
            raise ValueError("a snapshot may contain at most one register per key")
        return self


class MergeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    snapshots: list[Snapshot] = Field(min_length=1, max_length=MAX_NODES)
    include_tombstones: bool = False

    @model_validator(mode="after")
    def validate_shape(self) -> "MergeRequest":
        nodes = [snapshot.node_id for snapshot in self.snapshots]
        if len(nodes) != len(set(nodes)):
            raise ValueError("snapshot node_id values must be unique")
        total = sum(len(snapshot.registers) for snapshot in self.snapshots)
        if total > MAX_TOTAL_RECORDS:
            raise ValueError(f"total register count exceeds {MAX_TOTAL_RECORDS}")
        return self


def compare_clocks(left: dict[str, int], right: dict[str, int]) -> Literal["before", "after", "equal", "concurrent"]:
    names = set(left) | set(right)
    le = all(left.get(name, 0) <= right.get(name, 0) for name in names)
    ge = all(left.get(name, 0) >= right.get(name, 0) for name in names)
    if le and ge:
        return "equal"
    if le:
        return "before"
    if ge:
        return "after"
    return "concurrent"


def merge_clock(snapshots: list[Snapshot]) -> dict[str, int]:
    merged: dict[str, int] = {}
    for snapshot in snapshots:
        for node, counter in snapshot.clock.values.items():
            merged[node] = max(merged.get(node, 0), counter)
    return dict(sorted(merged.items()))


def winner_key(record: Register) -> tuple[int, str, str, bool]:
    # Logical time + writer provides deterministic LWW ordering. The content
    # digest closes otherwise-identical ties without using arrival order.
    return (record.logical_time, record.writer, digest(record.value), record.tombstone)


def merge_snapshots(request: MergeRequest) -> dict[str, Any]:
    # Normalize the replica set before any derived output is assembled. This
    # makes candidate ordering, selected source nodes, clock-relation orientation,
    # and the output receipt independent of request arrival order.
    snapshots = sorted(request.snapshots, key=lambda snapshot: snapshot.node_id)

    grouped: dict[str, list[tuple[str, Register]]] = defaultdict(list)
    for snapshot in snapshots:
        for register in snapshot.registers:
            grouped[register.key].append((snapshot.node_id, register))

    registers: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    for key in sorted(grouped):
        candidates = grouped[key]
        winner_node, winner = max(
            candidates, key=lambda item: (*winner_key(item[1]), item[0])
        )
        distinct = {digest(record.model_dump(mode="json")) for _, record in candidates}
        if len(distinct) > 1:
            conflicts.append(
                {
                    "key": key,
                    "candidate_count": len(candidates),
                    "candidate_nodes": sorted(node for node, _ in candidates),
                    "selected_writer": winner.writer,
                    "selected_node": winner_node,
                    "resolution": "DETERMINISTIC_LWW_REGISTER",
                }
            )
        if not winner.tombstone or request.include_tombstones:
            registers.append(
                {
                    **winner.model_dump(mode="json"),
                    "selected_from_node": winner_node,
                    "value_sha256": digest(winner.value),
                }
            )

    clock_relations: list[dict[str, str]] = []
    for index, left in enumerate(snapshots):
        for right in snapshots[index + 1 :]:
            clock_relations.append(
                {
                    "left": left.node_id,
                    "right": right.node_id,
                    "relation": compare_clocks(left.clock.values, right.clock.values),
                }
            )

    body = {
        "schema": SCHEMA,
        "algorithm": "deterministic-lww-register-v1",
        "nodes": [snapshot.node_id for snapshot in snapshots],
        "merged_clock": merge_clock(snapshots),
        "registers": registers,
        "conflicts": conflicts,
        "clock_relations": clock_relations,
        "input_state": "OPERATOR_SUPPLIED",
        "network_state": "NOT_ACCESSED",
        "execution_authority": False,
    }
    return {
        **body,
        "receipt": {
            "algorithm": "sha256",
            "input_digest": digest(request.model_dump(mode="json")),
            "output_digest": digest(body),
            "canonical_output_bytes": len(canonical(body)),
        },
    }


def default_topology() -> dict[str, Any]:
    nodes = [
        {"id": "field-alpha", "role": "edge", "link": "INTERMITTENT", "authority": "OBSERVE"},
        {"id": "field-bravo", "role": "edge", "link": "PARTITIONED", "authority": "OBSERVE"},
        {"id": "relay-one", "role": "relay", "link": "AVAILABLE", "authority": "FORWARD_DECLARED"},
        {"id": "command", "role": "coordinator", "link": "AVAILABLE", "authority": "APPROVAL_REQUIRED"},
    ]
    edges = [
        {"from": "field-alpha", "to": "relay-one", "state": "INTERMITTENT"},
        {"from": "field-bravo", "to": "relay-one", "state": "UNAVAILABLE"},
        {"from": "relay-one", "to": "command", "state": "AVAILABLE"},
    ]
    body = {
        "schema": "szl.mesh-topology/v1",
        "state": "DECLARED_DEMO_TOPOLOGY",
        "nodes": nodes,
        "edges": edges,
        "live_network_measurement": "UNAVAILABLE_NOT_ATTEMPTED",
        "radio_or_socket_access": False,
    }
    return {**body, "receipt": {"algorithm": "sha256", "digest": digest(body)}}


app = FastAPI(
    title="SZL Mesh Command",
    version=APP_VERSION,
    docs_url="/api/docs",
    redoc_url=None,
)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    return {"status": "ok", "service": "szl-mesh-command", "version": APP_VERSION}


@app.get("/readyz")
def readyz() -> dict[str, Any]:
    checks = {
        "static_index": (STATIC / "index.html").is_file(),
        "algorithm": True,
    }
    return {"status": "ready" if all(checks.values()) else "not-ready", "checks": checks}


@app.get("/api/source")
def source() -> dict[str, Any]:
    controlled = [
        Path(__file__),
        STATIC / "index.html",
        STATIC / "app.js",
        STATIC / "styles.css",
    ]
    body = {
        "schema": "szl.source-identity/v1",
        "repository": "szl-holdings/szl-mesh",
        "revision": source_revision(),
        "controlled_files": {
            path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in controlled
            if path.is_file()
        },
        "network_authority": False,
        "execution_authority": False,
        "deployment_authority": False,
    }
    return {**body, "receipt": {"algorithm": "sha256", "digest": digest(body)}}


@app.get("/api/topology")
def topology() -> dict[str, Any]:
    return default_topology()


@app.post("/api/simulate/merge")
def simulate_merge(request: MergeRequest) -> dict[str, Any]:
    try:
        return merge_snapshots(request)
    except (TypeError, ValueError, OverflowError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)[:500]) from exc


@app.get("/deployment.json")
def deployment() -> dict[str, Any]:
    return {
        "schema": "szl.mesh-deployment/v1",
        "service": "szl-mesh-command",
        "version": APP_VERSION,
        "source_revision": source_revision(),
        "runtime_state": "MEASURED_BY_THIS_RESPONSE",
        "hub_publication": "UNAVAILABLE_UNLESS_PROVIDER_READBACK_EXISTS",
        "live_mesh_connectivity": "UNAVAILABLE_NOT_ATTEMPTED",
    }


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")
