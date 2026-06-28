# SPDX-License-Identifier: Apache-2.0
# SZL Holdings — Sovereign Mesh HTTP API
# © 2026 Lutar, Stephen P. — SZL Holdings · ORCID 0009-0001-0110-4173
# Doctrine v11 LOCKED · 749/14/163 · c7c0ba17 · Λ = Conjecture 1
"""
src/sovereign/api.py — Sovereign Mesh FastAPI HTTP surface
===========================================================
Exposes the sovereign mesh node-join + dispatch over HTTP, wiring
szl_mesh_agent.py and szl_mesh_coordinator.py as FastAPI endpoints.

Three routes:
    POST /api/szl/v1/mesh/join      — Doctrine-gated node enrollment
    GET  /api/szl/v1/mesh/nodes     — Live node registry (UP/DOWN/OFFLINE)
    POST /api/szl/v1/mesh/dispatch  — Λ-gated work dispatch → signed receipt

HONEST LABELS (carry in all responses — non-negotiable per Doctrine v11):
  - mesh_type  = "scheduler — software load-balancer, not hardware interconnect"
  - vram_fusion = "ROADMAP — NVLink-only (consumer Ada/Blackwell have no NVLink)"
  - lambda_label = "advisory Conjecture 1 — NEVER a theorem"
  - throughput  = "MODELED until founder reports MEASURED benchmark"
  - join_token_signing = "HMAC-SHA256 classical — ML-DSA (FIPS 204) upgrade = ROADMAP"

FORMULA ANCHORS (kernel c7c0ba17, locked_count_eight, sorry-free):
  F1  replay determinism       → seeded RNG: same request_id → same node pick
  F4  Khipu hash-chain         → dispatch receipt chain (prev_hash ‖ body → hash)
  F7  Chaski relay idempotence → request_id dedup; duplicates returned unchanged
  F11 Ayni reciprocity         → node contribution tracked across all dispatches
  F22 emit-monotone            → receipt seq is append-only, never reordered

Usage:
    # Set env: SZL_FORMATION_KEY=<hex-encoded 32-byte key>
    uvicorn src.sovereign.api:app --host 0.0.0.0 --port 9090

Or mount into an existing FastAPI app:
    from src.sovereign.api import register
    register(app, ns="/api/szl/v1/mesh")

NO GPU REQUIRED — pure Python stdlib + FastAPI. No torch/CUDA calls.
Signed-off-by: Stephen Lutar <stephenlutar2@gmail.com>
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional

# FastAPI import — required dependency
try:
    from fastapi import FastAPI, HTTPException
    from pydantic import BaseModel, Field
except ImportError as _e:  # pragma: no cover
    raise ImportError(
        "FastAPI and pydantic are required for src.sovereign.api. "
        "Install with: pip install fastapi pydantic"
    ) from _e

# Import sovereign agent + coordinator (same package — relative import)
try:
    from .szl_mesh_agent import (
        COSIGN_KEYID,
        LAMBDA_THRESHOLD_ADVISORY,
        MeshNodeAgent,
        NodeHardware,
        issue_join_token,
        verify_join_token,
    )
    from .szl_mesh_coordinator import MeshCoordinator
except ImportError:
    # Fallback: try absolute import when running as a standalone module
    import sys as _sys
    import pathlib as _pathlib

    _sys.path.insert(0, str(_pathlib.Path(__file__).parent))
    from szl_mesh_agent import (  # type: ignore[no-redef]
        COSIGN_KEYID,
        LAMBDA_THRESHOLD_ADVISORY,
        MeshNodeAgent,
        NodeHardware,
        issue_join_token,
        verify_join_token,
    )
    from szl_mesh_coordinator import MeshCoordinator  # type: ignore[no-redef]

log = logging.getLogger("szl.mesh.api")

# ---------------------------------------------------------------------------
# Constants & honest labels
# ---------------------------------------------------------------------------

HONEST_MESH_LABELS: Dict[str, str] = {
    "mesh_type": "scheduler — software load-balancer, not hardware interconnect",
    "vram_fusion": "ROADMAP — NVLink-only (consumer Ada/Blackwell have no NVLink)",
    "lambda_label": "advisory Conjecture 1 — NEVER a theorem",
    "throughput": "MODELED until founder reports MEASURED benchmark",
    "join_token_signing": "HMAC-SHA256 classical — ML-DSA (FIPS 204) upgrade = ROADMAP",
    "doctrine": "749/14/163",
    "kernel_commit": "c7c0ba17",
}

DEFAULT_NS = "/api/szl/v1/mesh"

# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------
_coordinator: Optional[MeshCoordinator] = None
_formation_key: bytes = b""


def _get_coordinator() -> Optional[MeshCoordinator]:
    """Return the coordinator, initialising lazily from SZL_FORMATION_KEY env."""
    global _coordinator, _formation_key
    if _coordinator is None:
        key_hex = os.environ.get("SZL_FORMATION_KEY", "")
        if key_hex:
            try:
                _formation_key = bytes.fromhex(key_hex)
                _coordinator = MeshCoordinator(formation_key=_formation_key)
                log.info(
                    "Coordinator initialised from SZL_FORMATION_KEY "
                    "(formation_id=%s)", _coordinator.formation_id
                )
            except Exception as exc:
                log.warning("Failed to init coordinator from SZL_FORMATION_KEY: %s", exc)
    return _coordinator


# ---------------------------------------------------------------------------
# Pydantic request / response models
# ---------------------------------------------------------------------------


class JoinRequest(BaseModel):
    """Node enrollment request (doctrine-gated HMAC proof)."""

    node_id: str = Field(..., description="Unique node identifier")
    hardware: Dict[str, Any] = Field(
        ...,
        description=(
            "NodeHardware fields: name, vram_gb, backend (CUDA/Vulkan/CPU), arch. "
            "HONEST: vram_fusion=ROADMAP; mesh=scheduler only."
        ),
    )
    formation_key_proof: str = Field(
        ...,
        description=(
            "HMAC-SHA256 hex digest over "
            "node_id + timestamp_utc + '749/14/163' + 'c7c0ba17'. "
            "HMAC-SHA256 classical signing — ML-DSA (FIPS 204) upgrade = ROADMAP."
        ),
    )
    timestamp_utc: str = Field(..., description="ISO-8601 UTC timestamp of the proof")


class DispatchRequest(BaseModel):
    """Work dispatch request (Λ-gated)."""

    request_id: str = Field(..., description="Unique request identifier (for F1 replay determinism)")
    payload: Dict[str, Any] = Field(..., description="Work payload")
    lambda_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description=(
            "Advisory Λ score from caller (Conjecture 1 — NEVER a theorem). "
            f"Must be >= {LAMBDA_THRESHOLD_ADVISORY} for dispatch."
        ),
    )


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------


def _join_handler(req: JoinRequest) -> Dict[str, Any]:
    """POST /join — doctrine-gated node enrollment."""
    coordinator = _get_coordinator()
    if coordinator is None:
        return {
            "status": "DEGRADED",
            "reason": "SZL_FORMATION_KEY not set — coordinator not initialised",
            "honest_labels": HONEST_MESH_LABELS,
        }

    # Validate formation_key_proof: HMAC-SHA256 over canonical string
    expected_material = (
        req.node_id + req.timestamp_utc + "749/14/163" + "c7c0ba17"
    ).encode()
    expected_hmac = hmac.new(_formation_key, expected_material, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected_hmac, req.formation_key_proof.lower()):
        raise HTTPException(
            status_code=403,
            detail={
                "error": "formation_key_proof invalid",
                "hint": "HMAC-SHA256(node_id + timestamp_utc + '749/14/163' + 'c7c0ba17')",
                "honest_labels": HONEST_MESH_LABELS,
            },
        )

    # Build NodeHardware from request dict
    hw_data = req.hardware.copy()
    hw = NodeHardware(
        name=hw_data.get("name", req.node_id),
        vram_gb=float(hw_data.get("vram_gb", 0.0)),
        backend=hw_data.get("backend", "CPU"),
        arch=hw_data.get("arch", "unknown"),
    )

    # Issue join token via coordinator
    try:
        result = coordinator.enroll_node(
            node_id=req.node_id,
            hardware=hw,
            formation_key_proof=req.formation_key_proof,
            timestamp_utc=req.timestamp_utc,
        )
    except Exception as exc:
        log.warning("enroll_node error for %s: %s", req.node_id, exc)
        raise HTTPException(
            status_code=422,
            detail={
                "error": str(exc),
                "honest_labels": HONEST_MESH_LABELS,
            },
        ) from exc

    return {
        "status": "ENROLLED",
        "node_id": req.node_id,
        "formation_id": coordinator.formation_id,
        "result": result,
        "honest_labels": HONEST_MESH_LABELS,
    }


def _nodes_handler() -> Dict[str, Any]:
    """GET /nodes — live node registry."""
    coordinator = _get_coordinator()
    if coordinator is None:
        return {
            "status": "DEGRADED",
            "nodes": [],
            "reason": "SZL_FORMATION_KEY not set — no active formation",
            "honest_labels": HONEST_MESH_LABELS,
        }
    nodes = coordinator.list_nodes()
    return {
        "status": "LIVE",
        "formation_id": coordinator.formation_id,
        "nodes": nodes,
        "node_count": len(nodes),
        "honest_labels": HONEST_MESH_LABELS,
    }


def _dispatch_handler(req: DispatchRequest) -> Dict[str, Any]:
    """POST /dispatch — Λ-gated work dispatch, returns signed receipt."""
    if req.lambda_score < LAMBDA_THRESHOLD_ADVISORY:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "Λ advisory gate: lambda_score below threshold",
                "lambda_score": req.lambda_score,
                "threshold": LAMBDA_THRESHOLD_ADVISORY,
                "lambda_label": (
                    f"Conjecture 1 advisory — gate threshold = {LAMBDA_THRESHOLD_ADVISORY}. "
                    "This is an advisory gate, never a proven safety guarantee."
                ),
                "honest_labels": HONEST_MESH_LABELS,
            },
        )

    coordinator = _get_coordinator()
    if coordinator is None:
        return {
            "status": "DEGRADED",
            "reason": "SZL_FORMATION_KEY not set — no active formation",
            "request_id": req.request_id,
            "honest_labels": HONEST_MESH_LABELS,
        }

    try:
        result = coordinator.dispatch(req.request_id, req.payload)
    except Exception as exc:
        log.warning("dispatch error for %s: %s", req.request_id, exc)
        raise HTTPException(
            status_code=503,
            detail={
                "error": str(exc),
                "request_id": req.request_id,
                "honest_labels": HONEST_MESH_LABELS,
            },
        ) from exc

    return {
        "status": "DISPATCHED",
        "request_id": req.request_id,
        "lambda_score": req.lambda_score,
        "lambda_label": "Conjecture 1 advisory — NOT a proven safety guarantee",
        "result": result,
        "honest_labels": HONEST_MESH_LABELS,
    }


# ---------------------------------------------------------------------------
# FastAPI app + register() helper
# ---------------------------------------------------------------------------


def register(app: FastAPI, ns: str = DEFAULT_NS) -> FastAPI:
    """
    Register sovereign mesh routes on an existing FastAPI app.

    Example:
        from fastapi import FastAPI
        from src.sovereign.api import register

        app = FastAPI()
        register(app, ns="/api/szl/v1/mesh")

    Routes registered:
        POST {ns}/join      — doctrine-gated node enrollment
        GET  {ns}/nodes     — live node registry
        POST {ns}/dispatch  — Λ-gated work dispatch → signed receipt
    """

    @app.post(
        f"{ns}/join",
        summary="Doctrine-gated sovereign node enrollment",
        description=(
            "Enrolls a node into the sovereign mesh formation. "
            "Validates HMAC-SHA256 formation_key_proof before issuing a join token. "
            "HONEST: mesh = scheduler (software); VRAM fusion = ROADMAP; "
            "Λ = Conjecture 1 advisory."
        ),
    )
    async def join(req: JoinRequest) -> Dict[str, Any]:
        return _join_handler(req)

    @app.get(
        f"{ns}/nodes",
        summary="Live sovereign node registry",
        description=(
            "Returns UP/DOWN/OFFLINE status for all enrolled nodes. "
            "HONEST: mesh = scheduler; VRAM fusion = ROADMAP."
        ),
    )
    async def nodes() -> Dict[str, Any]:
        return _nodes_handler()

    @app.post(
        f"{ns}/dispatch",
        summary="Λ-gated work dispatch — returns signed receipt",
        description=(
            "Routes a job through the Λ advisory gate (Conjecture 1) and "
            "dispatches to a sovereign node via F1 seeded-pick. "
            "Signs the dispatch receipt (F4 hash-chain + F22 emit-monotone). "
            "HONEST: Λ = advisory Conjecture 1 — NEVER a theorem; "
            "mesh = scheduler; VRAM fusion = ROADMAP."
        ),
    )
    async def dispatch(req: DispatchRequest) -> Dict[str, Any]:
        return _dispatch_handler(req)

    return app


# ---------------------------------------------------------------------------
# Standalone app (for uvicorn direct launch)
# ---------------------------------------------------------------------------

app = FastAPI(
    title="SZL Sovereign Mesh API",
    description=(
        "Sovereign node-join + dispatch over HTTP. "
        "Wires szl_mesh_agent + szl_mesh_coordinator. "
        "Doctrine v11 LOCKED · 749/14/163 · c7c0ba17. "
        "Λ = Conjecture 1 (advisory, never a theorem). "
        "VRAM fusion = ROADMAP. Mesh = scheduler."
    ),
    version="0.4.0",
    license_info={"name": "Apache-2.0", "url": "https://www.apache.org/licenses/LICENSE-2.0"},
    contact={
        "name": "Lutar, Stephen P. — SZL Holdings",
        "url": "https://szlholdings.com",
        "email": "stephenlutar2@gmail.com",
    },
)

# Register mesh routes on the standalone app
register(app, ns=DEFAULT_NS)


@app.get("/healthz", summary="Health check")
async def healthz() -> Dict[str, Any]:
    """Health check — returns mesh status + honest labels."""
    coordinator = _get_coordinator()
    return {
        "status": "ok",
        "formation_active": coordinator is not None,
        "formation_id": coordinator.formation_id if coordinator else None,
        "node_count": len(coordinator.list_nodes()) if coordinator else 0,
        "honest_labels": HONEST_MESH_LABELS,
        "doctrine": "749/14/163",
        "kernel_commit": "c7c0ba17",
    }
