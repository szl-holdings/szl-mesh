#!/usr/bin/env python3
"""Apply the exact SZL Mesh receipt-order and pytest 9 successor repair."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "mesh_command" / "app.py"
TESTS = ROOT / "tests" / "test_mesh_command.py"
REQ = ROOT / "requirements-mesh-command-dev.txt"
DOCKERFILE = ROOT / "Dockerfile.mesh-command"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


def main() -> int:
    app = APP.read_text(encoding="utf-8")
    app = replace_once(
        app,
        "        winner_node, winner = max(candidates, key=lambda item: winner_key(item[1]))",
        "        winner_node, winner = max(\n"
        "            candidates, key=lambda item: (*winner_key(item[1]), item[0])\n"
        "        )",
        "node-stable register tie break",
    )
    app = replace_once(
        app,
        "    clock_relations: list[dict[str, str]] = []\n"
        "    for index, left in enumerate(request.snapshots):\n"
        "        for right in request.snapshots[index + 1 :]:",
        "    clock_relations: list[dict[str, str]] = []\n"
        "    ordered_snapshots = sorted(request.snapshots, key=lambda snapshot: snapshot.node_id)\n"
        "    for index, left in enumerate(ordered_snapshots):\n"
        "        for right in ordered_snapshots[index + 1 :]:",
        "canonical clock relation order",
    )
    APP.write_text(app, encoding="utf-8")

    tests = TESTS.read_text(encoding="utf-8")
    marker = "\n\ndef test_duplicate_snapshot_nodes_fail_closed() -> None:\n"
    regression = '''\n\ndef test_identical_register_tie_is_node_stable() -> None:\n    identical = {\n        "snapshots": [\n            {\n                "node_id": "alpha",\n                "clock": {"values": {"alpha": 1}},\n                "registers": [\n                    {\n                        "key": "mission.mode",\n                        "value": "observe",\n                        "logical_time": 1,\n                        "writer": "operator",\n                        "tombstone": False,\n                    }\n                ],\n            },\n            {\n                "node_id": "bravo",\n                "clock": {"values": {"bravo": 1}},\n                "registers": [\n                    {\n                        "key": "mission.mode",\n                        "value": "observe",\n                        "logical_time": 1,\n                        "writer": "operator",\n                        "tombstone": False,\n                    }\n                ],\n            },\n        ],\n        "include_tombstones": False,\n    }\n    first = client.post("/api/simulate/merge", json=identical).json()\n    identical["snapshots"].reverse()\n    second = client.post("/api/simulate/merge", json=identical).json()\n    assert first["registers"] == second["registers"]\n    assert first["registers"][0]["selected_from_node"] == "bravo"\n    assert first["receipt"]["output_digest"] == second["receipt"]["output_digest"]\n'''
    tests = replace_once(tests, marker, regression + marker, "node-stable regression insertion")
    TESTS.write_text(tests, encoding="utf-8")

    req = REQ.read_text(encoding="utf-8")
    req = replace_once(req, "pytest==8.3.4", "pytest==9.0.3", "pytest pin")
    REQ.write_text(req, encoding="utf-8")

    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    dockerfile = replace_once(
        dockerfile,
        "COPY . .\nRUN chown -R szl:szl /app",
        "COPY --chown=10001:10001 mesh_command/ ./mesh_command/",
        "non-root image copy",
    )
    DOCKERFILE.write_text(dockerfile, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
