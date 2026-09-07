from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from lab.app import create_app
from lab.simulator import SCENARIOS, SimulationError, simulate_scenario


@pytest.mark.parametrize("slug", sorted(SCENARIOS))
def test_builtin_scenarios_converge_deterministically(slug: str) -> None:
    scenario = deepcopy(SCENARIOS[slug])
    first = simulate_scenario(scenario)
    second = simulate_scenario(scenario)
    assert first == second
    assert first["status"] == "CONVERGED"
    assert all(first["checks"].values())
    assert len(first["receipt_sha256"]) == 64
    assert first["evidence_boundary"]["byzantine_fault_tolerance_claimed"] is False
    assert first["evidence_boundary"]["network_or_repository_mutation"] is False


def test_two_track_views_remain_distinct_and_converged() -> None:
    result = simulate_scenario(deepcopy(SCENARIOS["two-track-signal"]))
    for replica in result["reconciled_replicas"]:
        assert replica["authorized_view"]["sector-7"]["state"] == "nominal"
        assert replica["observed_view"]["sector-7"]["state"] == "anomaly"
    assert len({row["authorized_digest"] for row in result["reconciled_replicas"]}) == 1
    assert len({row["observed_digest"] for row in result["reconciled_replicas"]}) == 1


def test_duplicate_replay_is_counted_but_not_reapplied() -> None:
    operation = {
        "node_id": "alpha",
        "key": "status",
        "value": "ready",
        "lamport": 7,
        "track": "AUTHORIZED",
        "origin": 0,
    }
    duplicate = dict(operation, origin=1)
    result = simulate_scenario(
        {
            "doc_id": "replay-check",
            "replicas": 2,
            "operations": [operation, duplicate],
        }
    )
    assert result["input_operation_count"] == 2
    assert result["unique_operation_count"] == 1
    assert result["duplicate_input_count"] == 1
    assert result["checks"]["replay_idempotent"] is True


def test_conflicting_track_for_same_operation_identity_fails_closed() -> None:
    base = {
        "node_id": "alpha",
        "key": "status",
        "value": "ready",
        "lamport": 7,
        "origin": 0,
    }
    with pytest.raises(SimulationError, match="conflicting track"):
        simulate_scenario(
            {
                "doc_id": "track-conflict",
                "replicas": 2,
                "operations": [
                    dict(base, track="AUTHORIZED"),
                    dict(base, track="OBSERVED", origin=1),
                ],
            }
        )


def test_nonfinite_json_value_fails_closed() -> None:
    with pytest.raises(SimulationError, match="finite JSON"):
        simulate_scenario(
            {
                "doc_id": "nonfinite",
                "replicas": 2,
                "operations": [
                    {
                        "node_id": "alpha",
                        "key": "score",
                        "value": float("nan"),
                        "lamport": 1,
                    }
                ],
            }
        )


def test_bounds_and_unknown_fields_fail_closed() -> None:
    with pytest.raises(SimulationError, match="replicas"):
        simulate_scenario(
            {"doc_id": "too-wide", "replicas": 9, "operations": [{}]}
        )
    with pytest.raises(SimulationError, match="unsupported keys"):
        simulate_scenario(
            {
                "doc_id": "unknown",
                "replicas": 2,
                "operations": [
                    {
                        "node_id": "alpha",
                        "key": "x",
                        "value": 1,
                        "lamport": 1,
                        "effect": "forbidden",
                    }
                ],
            }
        )


def test_api_health_source_simulation_and_headers() -> None:
    api = TestClient(create_app())
    health = api.get("/healthz")
    assert health.status_code == 200
    assert health.json()["mutation_authority"] is False
    assert health.json()["bft_claim"] is False
    assert health.headers["x-szl-authority"] == "finite-read-only-simulation"
    assert "default-src 'self'" in health.headers["content-security-policy"]
    assert api.get("/readyz").status_code == 200
    assert api.get("/api/source").json()["repository"] == "szl-holdings/szl-mesh"

    response = api.post("/api/simulate", json=SCENARIOS["partition-rejoin"])
    assert response.status_code == 200
    assert response.json()["status"] == "CONVERGED"


def test_api_rejects_out_of_range_origin() -> None:
    api = TestClient(create_app())
    scenario = deepcopy(SCENARIOS["partition-rejoin"])
    scenario["replicas"] = 2
    scenario["operations"][0]["origin"] = 7
    response = api.post("/api/simulate", json=scenario)
    assert response.status_code == 422


def test_frontend_is_local_and_responsive() -> None:
    api = TestClient(create_app())
    html = api.get("/").text
    javascript = api.get("/app.js").text
    css = api.get("/styles.css").text + api.get("/responsive.css").text
    assert 'src="/app.js"' in html
    assert 'href="/styles.css"' in html
    assert 'href="/responsive.css"' in html
    assert "https://" not in html + javascript + css
    external_http = (html + javascript + css).replace(
        "http://www.w3.org/2000/svg", ""
    )
    assert "http://" not in external_http
    assert "localStorage" not in javascript
    assert "sessionStorage" not in javascript
    assert "prefers-reduced-motion" in css
    assert "forced-colors" in css
    assert "@media print" in css
