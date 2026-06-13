#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# © 2026 Lutar, Stephen P. — SZL Holdings · ORCID 0009-0001-0110-4173
"""
quorum_demo.py — wire a mesh canonical action through the REAL khipu-consensus
3-of-4 quorum and show: a canonical QC, a 3-of-4 (dropped 4th) QC, and a 2-bad
(NOT canonical) QC. Generates REAL ECDSA-P256 witness keys IN MEMORY ONLY — keys
are NEVER written to disk or committed.

Run:  python examples/quorum_demo.py

Doctrine v11: 3-of-4 Khipu quorum is REAL (ECDSA-P256 DSSE). Khipu BFT
*unconditional* safety = Conjecture 2 (NOT proven). The soft-safety AP
corroboration model (spec/04) is the real shipped one.
"""
import json
import os
import sys

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "src"))

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption,
)

import szl_mesh.quorum as Q


def gen_keys(organs):
    priv, pub = {}, {}
    for o in organs:
        k = ec.generate_private_key(ec.SECP256R1())
        priv[o] = k.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
        pub[o] = k.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    return priv, pub  # IN MEMORY ONLY — never persisted


def main():
    organs = list(Q.DEFAULT_ORGANS)
    priv, pub = gen_keys(organs)

    action = {
        "type": "szl-mesh/state-transition/v1",
        "crdt_document_id": "formation-001/platforms",
        "change_hash": "deadbeef" * 8,
        "transition_class": "COMMAND",
        "node_id": "node-alpha",
    }

    print("== 4-of-4 (all allow) ==")
    qc = Q.propose_action(action, witness_keys=priv)
    print(json.dumps(qc.to_dict(), indent=2)[:600], "...\n")
    print("verify:", Q.verify_quorum(qc, pub).to_dict()["khipu_consensus"],
          "canonical=", Q.verify_quorum(qc, pub).canonical, "\n")

    print("== 3-of-4 (4th witness dropped) -> still CANONICAL ==")
    dropped = {o: priv[o] for o in organs[:3]}
    qc3 = Q.propose_action(action, witness_keys=dropped)
    print("canonical=", qc3.canonical, "count=", qc3.consensus_count, "\n")

    print("== 2-bad (two witnesses block) -> NOT canonical ==")
    qc2 = Q.propose_action(action, witness_keys=priv,
                           verdicts={organs[2]: "block", organs[3]: "block"})
    print("canonical=", qc2.canonical, "count=", qc2.consensus_count, "\n")

    print("== soft-safety AP corroboration (spec/04) — annotation, never blocks ==")
    ledger = Q.CorroborationLedger()
    ch = action["change_hash"]
    print("after node-1:", ledger.observe(ch, "node-1", "COMMAND")["status"])
    print("after node-2:", ledger.observe(ch, "node-2", "COMMAND")["status"])
    print("blocks_writes =", ledger.blocks_writes, "(soft-safety AP, NOT blocking BFT)")
    print("\nKhipu BFT unconditional safety = Conjecture 2 (NOT proven).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
