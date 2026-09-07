# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from fastapi.testclient import TestClient

from mesh_command import app as module

client = TestClient(module.app)


def _snapshot(node_id: str) -> dict[str, object]:
    return {
        "node_id": node_id,
        "clock": {"values": {node_id: 1}},
        "registers": [
            {
                "key": "mission.phase",
                "value": "observe",
                "logical_time": 1,
                "writer": "shared",
                "tombstone": False,
            }
        ],
    }


def test_receipt_and_selected_source_are_arrival_order_independent() -> None:
    alpha = _snapshot("alpha")
    zeta = _snapshot("zeta")

    first = client.post(
        "/api/simulate/merge",
        json={"snapshots": [zeta, alpha], "include_tombstones": False},
    ).json()
    second = client.post(
        "/api/simulate/merge",
        json={"snapshots": [alpha, zeta], "include_tombstones": False},
    ).json()

    assert first["registers"] == second["registers"]
    assert first["registers"][0]["selected_from_node"] == "alpha"
    assert first["clock_relations"] == second["clock_relations"]
    assert first["clock_relations"] == [
        {"left": "alpha", "right": "zeta", "relation": "concurrent"}
    ]
    assert first["receipt"]["output_digest"] == second["receipt"]["output_digest"]
    assert first["receipt"]["canonical_output_bytes"] == second["receipt"]["canonical_output_bytes"]
