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
    old_winner = "        winner_node, winner = max(candidates, key=lambda item: winner_key(item[1]))"
    new_winner = (
        "        winner_node, winner = max(\n"
        "            candidates, key=lambda item: (*winner_key(item[1]), item[0])\n"
        "        )"
    )
    if new_winner not in app:
        app = replace_once(app, old_winner, new_winner, "node-stable register tie break")

    normalized = "    snapshots = sorted(request.snapshots, key=lambda snapshot: snapshot.node_id)"
    if normalized not in app:
        app = replace_once(
            app,
            "def merge_snapshots(request: MergeRequest) -> dict[str, Any]:\n"
            "    grouped: dict[str, list[tuple[str, Register]]] = defaultdict(list)\n"
            "    for snapshot in request.snapshots:",
            "def merge_snapshots(request: MergeRequest) -> dict[str, Any]:\n"
            "    # Normalize the replica set before any derived output is assembled.\n"
            "    snapshots = sorted(request.snapshots, key=lambda snapshot: snapshot.node_id)\n\n"
            "    grouped: dict[str, list[tuple[str, Register]]] = defaultdict(list)\n"
            "    for snapshot in snapshots:",
            "canonical replica order",
        )
        app = replace_once(
            app,
            "    for index, left in enumerate(request.snapshots):\n"
            "        for right in request.snapshots[index + 1 :]:",
            "    for index, left in enumerate(snapshots):\n"
            "        for right in snapshots[index + 1 :]:",
            "canonical clock relation order",
        )
    if "for index, left in enumerate(snapshots):" not in app:
        raise RuntimeError("canonical clock relation order is absent")
    APP.write_text(app, encoding="utf-8")

    tests = TESTS.read_text(encoding="utf-8")
    marker = "\n\ndef test_duplicate_snapshot_nodes_fail_closed() -> None:\n"
    regression = '''\n\ndef test_identical_register_tie_is_node_stable() -> None:\n    identical = {\n        "snapshots": [\n            {\n                "node_id": "alpha",\n                "clock": {"values": {"alpha": 1}},\n                "registers": [\n                    {\n                        "key": "mission.mode",\n                        "value": "observe",\n                        "logical_time": 1,\n                        "writer": "operator",\n                        "tombstone": False,\n                    }\n                ],\n            },\n            {\n                "node_id": "bravo",\n                "clock": {"values": {"bravo": 1}},\n                "registers": [\n                    {\n                        "key": "mission.mode",\n                        "value": "observe",\n                        "logical_time": 1,\n                        "writer": "operator",\n                        "tombstone": False,\n                    }\n                ],\n            },\n        ],\n        "include_tombstones": False,\n    }\n    first = client.post("/api/simulate/merge", json=identical).json()\n    identical["snapshots"].reverse()\n    second = client.post("/api/simulate/merge", json=identical).json()\n    assert first["registers"] == second["registers"]\n    assert first["registers"][0]["selected_from_node"] == "bravo"\n    assert first["receipt"]["output_digest"] == second["receipt"]["output_digest"]\n'''
    if "def test_identical_register_tie_is_node_stable" not in tests:
        tests = replace_once(tests, marker, regression + marker, "node-stable regression insertion")
    TESTS.write_text(tests, encoding="utf-8")

    req = REQ.read_text(encoding="utf-8")
    if "pytest==9.0.3" not in req:
        req = replace_once(req, "pytest==8.3.4", "pytest==9.0.3", "pytest pin")
    REQ.write_text(req, encoding="utf-8")

    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    hardened = "COPY --chown=10001:10001 mesh_command/ ./mesh_command/"
    if hardened not in dockerfile:
        dockerfile = replace_once(
            dockerfile,
            "COPY . .\nRUN chown -R szl:szl /app",
            hardened,
            "non-root image copy",
        )
    DOCKERFILE.write_text(dockerfile, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
