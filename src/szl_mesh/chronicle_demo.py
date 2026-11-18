# SPDX-License-Identifier: Apache-2.0
"""Credential-free, LOCAL demo and read-only integrity CLI for Mesh Chronicle.

Demo uses ephemeral test identities and synthetic data. It cannot perform any
production join, release, API mutation, live trust admission, or deployment.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import secrets
import sys

from .chronicle import MeshChronicle
from .crdt import AUTHORIZED, OBSERVED
from .enrollment import FormationGateway
from .node import MeshNode


def demo(database: str) -> dict:
    key = secrets.token_bytes(32)
    gateway = FormationGateway("chronicle-synthetic-demo", key)
    a, b = MeshNode("left", "demo/chronicle"), MeshNode("right", "demo/chronicle")
    if not a.enroll(gateway, key).success or not b.enroll(gateway, key).success:
        raise RuntimeError("synthetic enrollment failed")
    # Distinct append orders on independently generated local SQLite stores.
    ops = [a.write("peer.left", {"status": "OBSERVED_SIMULATED"}),
           b.write("peer.right", {"status": "OBSERVED_SIMULATED"})]
    with MeshChronicle(database) as storage:
        storage.ingest_record(ops[1])
        storage.ingest_record(ops[0])
        observed = storage.state("demo/chronicle", track=OBSERVED)
        unknown = storage.state("demo/chronicle", track=AUTHORIZED)
        admitted = storage.state("demo/chronicle", track=AUTHORIZED,
                                 registry=gateway.pubkey_registry(),
                                 revoked=gateway.revoked)
        integrity = storage.verify_integrity()
        assert len(observed) == len(admitted) == 2 and unknown == {}
        assert integrity["events"] == 4
        return {
            "schema": "szl.mesh.chronicle-local-smoke/v1",
            "result": "SIMULATED_LOCAL_PASS",
            "engine": "SQLite WAL" if database != ":memory:" else "SQLite MEMORY",
            "observed_keys": len(observed),
            "authorized_keys_with_ephemeral_independent_test_trust": len(admitted),
            "authorized_keys_without_trust": len(unknown),
            "integrity": integrity,
            "external_signature": "UNAVAILABLE",
            "remote_mesh_connected": False,
            "production_release_ready": False,
        }


def main(argv: list[str] | None = None) -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    mode = cli.add_mutually_exclusive_group(required=True)
    mode.add_argument("--demo", action="store_true",
                      help="run a synthetic local-only CRDT/SQLite persistence smoke")
    mode.add_argument("--verify-only", action="store_true",
                      help="read-only verify an EXISTING node-local SQLite store")
    cli.add_argument("--db", default=":memory:",
                     help="local DB path; demo defaults to ephemeral in-memory")
    args = cli.parse_args(argv)
    try:
        if args.demo:
            result = demo(args.db)
        else:
            if args.db == ":memory:" or not Path(args.db).is_file():
                raise ValueError("verify-only requires an existing local DB")
            with MeshChronicle(args.db, readonly=True) as chronicle:
                result = chronicle.verify_integrity()
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except Exception:
        # Do not leak paths, provider errors, credentials, or database contents.
        print("CHRONICLE_UNAVAILABLE", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
