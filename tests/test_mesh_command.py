# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json

from fastapi.testclient import TestClient

from mesh_command import app as module

client = TestClient(module.app)


SAMPLE = {
    "snapshots": [
        {
            "node_id": "alpha",
            "clock": {"values": {"alpha": 2}},
            "registers": [
                {
                    "key": "mission.phase",
                    "value": "observe",
                    "logical_time": 2,
                    "writer": "alpha",
                    "tombstone": False,
                }
            ],
        },
        {
            "node_id": "bravo",
            "clock": {"values": {"bravo": 2}},
            "registers": [
                {
                    "key": "mission.phase",
                    "value": "hold",
                    "logical_time": 2,
                    "writer": "bravo",
                    "tombstone": False,
                }
            ],
        },
    ],
    "include_tombstones": False,
}


def test_health_readiness_and_source_boundaries() -> None:
    assert client.get("/healthz").json()["status"] == "ok"
    assert client.get("/readyz").json()["status"] == "ready"
    source = client.get("/api/source").json()
    assert source["repository"] == "szl-holdings/szl-mesh"
    assert source["network_authority"] is False
    assert source["execution_authority"] is False
    assert source["deployment_authority"] is False
    assert len(source["receipt"]["digest"]) == 64


def test_concurrent_vector_clocks_are_reported() -> None:
    response = client.post("/api/simulate/merge", json=SAMPLE)
    assert response.status_code == 200
    payload = response.json()
    assert payload["clock_relations"] == [
        {"left": "alpha", "right": "bravo", "relation": "concurrent"}
    ]
    assert payload["network_state"] == "NOT_ACCESSED"
    assert payload["execution_authority"] is False


def test_merge_is_arrival_order_independent() -> None:
    first = client.post("/api/simulate/merge", json=SAMPLE).json()
    reversed_sample = {
        "snapshots": list(reversed(SAMPLE["snapshots"])),
        "include_tombstones": False,
    }
    second = client.post("/api/simulate/merge", json=reversed_sample).json()
    assert first["registers"] == second["registers"]
    assert first["merged_clock"] == second["merged_clock"]
    assert first["receipt"]["output_digest"] == second["receipt"]["output_digest"]


def test_deterministic_writer_tiebreak_is_explicit() -> None:
    payload = client.post("/api/simulate/merge", json=SAMPLE).json()
    assert payload["registers"][0]["writer"] == "bravo"
    assert payload["registers"][0]["value"] == "hold"
    assert payload["conflicts"][0]["resolution"] == "DETERMINISTIC_LWW_REGISTER"


def test_duplicate_snapshot_nodes_fail_closed() -> None:
    invalid = json.loads(json.dumps(SAMPLE))
    invalid["snapshots"][1]["node_id"] = "alpha"
    response = client.post("/api/simulate/merge", json=invalid)
    assert response.status_code == 422
    assert "node_id values must be unique" in response.text


def test_duplicate_register_keys_fail_closed() -> None:
    invalid = json.loads(json.dumps(SAMPLE))
    invalid["snapshots"][0]["registers"].append(
        {
            "key": "mission.phase",
            "value": "duplicate",
            "logical_time": 3,
            "writer": "alpha",
            "tombstone": False,
        }
    )
    response = client.post("/api/simulate/merge", json=invalid)
    assert response.status_code == 422
    assert "at most one register per key" in response.text


def test_extra_effect_request_field_is_rejected() -> None:
    invalid = {**SAMPLE, "transmit": True}
    response = client.post("/api/simulate/merge", json=invalid)
    assert response.status_code == 422


def test_oversized_register_value_is_rejected() -> None:
    invalid = json.loads(json.dumps(SAMPLE))
    invalid["snapshots"][0]["registers"][0]["value"] = "x" * (module.MAX_VALUE_BYTES + 1)
    response = client.post("/api/simulate/merge", json=invalid)
    assert response.status_code == 422
    assert "canonical bytes" in response.text


def test_tombstones_are_hidden_by_default_and_visible_on_request() -> None:
    payload = {
        "snapshots": [
            {
                "node_id": "alpha",
                "clock": {"values": {"alpha": 1}},
                "registers": [
                    {
                        "key": "contact.old",
                        "value": None,
                        "logical_time": 1,
                        "writer": "alpha",
                        "tombstone": True,
                    }
                ],
            }
        ],
        "include_tombstones": False,
    }
    assert client.post("/api/simulate/merge", json=payload).json()["registers"] == []
    payload["include_tombstones"] = True
    visible = client.post("/api/simulate/merge", json=payload).json()["registers"]
    assert visible[0]["tombstone"] is True


def test_topology_is_declared_not_live_measurement() -> None:
    payload = client.get("/api/topology").json()
    assert payload["state"] == "DECLARED_DEMO_TOPOLOGY"
    assert payload["live_network_measurement"] == "UNAVAILABLE_NOT_ATTEMPTED"
    assert payload["radio_or_socket_access"] is False


def test_frontend_has_adaptive_and_local_only_contracts() -> None:
    html = (module.STATIC / "index.html").read_text(encoding="utf-8")
    js = (module.STATIC / "app.js").read_text(encoding="utf-8")
    css = (module.STATIC / "styles.css").read_text(encoding="utf-8")
    assert 'href="#main"' in html
    assert "https://" not in html and "http://" not in html
    assert "localStorage" not in js and "sessionStorage" not in js
    assert "prefers-reduced-motion" in css
    assert "prefers-contrast" in css
    assert "forced-colors" in css
    assert "@media print" in css


def test_deployment_identity_is_honest() -> None:
    payload = client.get("/deployment.json").json()
    assert payload["runtime_state"] == "MEASURED_BY_THIS_RESPONSE"
    assert payload["hub_publication"].startswith("UNAVAILABLE")
    assert payload["live_mesh_connectivity"] == "UNAVAILABLE_NOT_ATTEMPTED"
