"""FastAPI surface for finite, read-only SZL Mesh convergence experiments."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal

from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from szl_mesh.crdt import AUTHORIZED, OBSERVED, REVOKED

from .config import (
    CONTROLLED_FILES,
    MAX_OPERATIONS,
    MAX_REPLICAS,
    MAX_REQUEST_BYTES,
    sha256_file,
)
from .simulator import SCENARIOS, SimulationError, simulate_scenario


class OperationInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    node_id: str = Field(min_length=1, max_length=64)
    key: str = Field(min_length=1, max_length=128)
    value: Any = None
    lamport: int = Field(ge=0, le=2_147_483_647)
    deletion: bool = False
    track: Literal[AUTHORIZED, OBSERVED, REVOKED] = OBSERVED
    origin: int | None = Field(default=None, ge=0, lt=MAX_REPLICAS)


class SimulationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    doc_id: str = Field(min_length=1, max_length=96)
    replicas: int = Field(ge=2, le=MAX_REPLICAS)
    operations: list[OperationInput] = Field(
        min_length=1,
        max_length=MAX_OPERATIONS,
    )


def _source_identity(repo_root: Path) -> dict[str, Any]:
    revision = (
        os.getenv("SOURCE_REVISION")
        or os.getenv("GITHUB_SHA")
        or os.getenv("SPACE_COMMIT_SHA")
    )
    hashes = {
        name: sha256_file(repo_root / name) if (repo_root / name).is_file() else None
        for name in CONTROLLED_FILES
    }
    return {
        "schema": "szl.source-identity/v1",
        "repository": "szl-holdings/szl-mesh",
        "revision": revision,
        "revision_state": "MEASURED_ENVIRONMENT" if revision else "UNAVAILABLE",
        "controlled_files_sha256": hashes,
        "provider_head": "UNAVAILABLE_REQUIRES_EXTERNAL_READBACK",
        "hub_publication": "UNAVAILABLE_REQUIRES_EXTERNAL_READBACK",
        "runtime_source_match": "UNAVAILABLE_REQUIRES_EXTERNAL_READBACK",
    }


def create_app(repo_root: Path | None = None) -> FastAPI:
    root = (repo_root or Path(__file__).resolve().parents[1]).resolve()
    static_root = Path(__file__).resolve().parent / "static"
    application = FastAPI(
        title="SZL Mesh Convergence Lab",
        version="1.0.0",
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )

    @application.middleware("http")
    async def bounded_security_headers(request: Request, call_next):
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > MAX_REQUEST_BYTES:
            response = JSONResponse(
                status_code=413,
                content={"detail": "REQUEST_TOO_LARGE"},
            )
        else:
            response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        )
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; base-uri 'none'; connect-src 'self'; "
            "font-src 'self'; frame-ancestors 'self' https://huggingface.co "
            "https://*.huggingface.co; img-src 'self' data:; object-src 'none'; "
            "script-src 'self'; style-src 'self'"
        )
        response.headers["Cache-Control"] = (
            "no-store"
            if request.url.path.startswith("/api/")
            or request.url.path in {"/healthz", "/readyz"}
            else "public, max-age=300"
        )
        response.headers["X-SZL-Authority"] = "finite-read-only-simulation"
        return response

    @application.get("/healthz")
    def healthz() -> dict[str, Any]:
        return {
            "status": "ok",
            "service": "szl-mesh-convergence-lab",
            "network_transport": False,
            "mutation_authority": False,
            "bft_claim": False,
        }

    @application.get("/readyz")
    def readyz():
        required = [
            static_root / "index.html",
            static_root / "app.js",
            static_root / "styles.css",
            static_root / "responsive.css",
            root / "src" / "szl_mesh" / "crdt.py",
        ]
        missing = [path.relative_to(root).as_posix() for path in required if not path.is_file()]
        return JSONResponse(
            status_code=200 if not missing else 503,
            content={
                "status": "ready" if not missing else "not_ready",
                "missing": missing,
                "scenario_count": len(SCENARIOS),
            },
        )

    @application.get("/api/source")
    def source() -> dict[str, Any]:
        return _source_identity(root)

    @application.get("/api/scenarios")
    def scenarios() -> dict[str, Any]:
        return {
            "schema": "szl.mesh-convergence-lab.scenarios/v1",
            "items": [
                {
                    "slug": slug,
                    "doc_id": scenario["doc_id"],
                    "replicas": scenario["replicas"],
                    "operation_count": len(scenario["operations"]),
                    "scenario": scenario,
                }
                for slug, scenario in sorted(SCENARIOS.items())
            ],
            "evidence_boundary": "FINITE_SCENARIO_ONLY",
        }

    @application.get("/api/scenarios/{slug}")
    def scenario(slug: str) -> dict[str, Any]:
        value = SCENARIOS.get(slug)
        if value is None:
            raise HTTPException(status_code=404, detail="SCENARIO_NOT_FOUND")
        return {"slug": slug, "scenario": value}

    @application.post("/api/simulate")
    def simulate(request: SimulationRequest = Body(...)) -> dict[str, Any]:
        payload = request.model_dump(exclude_none=True)
        try:
            return simulate_scenario(payload)
        except SimulationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)[:500]) from exc

    @application.get("/")
    def index():
        return FileResponse(static_root / "index.html")

    @application.get("/{asset_name}", include_in_schema=False)
    def asset(asset_name: str):
        allowed = {
            "app.js": "application/javascript",
            "styles.css": "text/css",
            "responsive.css": "text/css",
        }
        media_type = allowed.get(asset_name)
        if media_type is None:
            raise HTTPException(status_code=404, detail="NOT_FOUND")
        return FileResponse(static_root / asset_name, media_type=media_type)

    return application


app = create_app()
