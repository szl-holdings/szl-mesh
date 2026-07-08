# SPDX-License-Identifier: Apache-2.0
# © 2026 Lutar, Stephen P. — SZL Holdings · ORCID 0009-0001-0110-4173
"""
Tests for szl_mesh.quorum — proves the wiring matches the REAL khipu-consensus
engine and its deterministic test vectors, plus the 3-of-4 / 2-bad cases and the
soft-safety AP corroboration annotation.

Run directly:  python tests/test_quorum.py
(Also pytest-discoverable.)
"""
import json
import os
import sys

HERE = os.path.dirname(__file__)
# src/ layout; the REAL engine is resolved by szl_mesh.quorum (installed pkg or
# the byte-identical vendored mirror in src/szl_mesh/_vendor).
sys.path.insert(0, os.path.join(HERE, "..", "src"))

from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)

import szl_mesh.quorum as Q  # noqa: E402  (resolves the REAL engine)
from szl_mesh.quorum import tally  # noqa: E402  (re-exported real engine fn)


def _vectors_path():
    for cand in (
        os.path.join(HERE, "..", "src", "szl_mesh", "_vendor", "vectors.json"),
        os.path.join(HERE, "..", "..", "vectors.json"),
        os.path.join(HERE, "..", "vectors.json"),
        os.path.join(HERE, "vectors.json"),
    ):
        if os.path.isfile(cand):
            return os.path.normpath(cand)
    raise FileNotFoundError("vectors.json not found")


def gen_keys(organs):
    """Generate REAL ECDSA-P256 witness keypairs (in memory; NEVER committed)."""
    priv, pub = {}, {}
    for o in organs:
        k = ec.generate_private_key(ec.SECP256R1())
        priv[o] = k.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        ).decode()
        pub[o] = k.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode()
    return priv, pub


# ─────────────────────────────────────────────────────────────────────────────
# 1. Vector-match: our wiring reproduces the engine's verdict on EVERY vector.
# ─────────────────────────────────────────────────────────────────────────────
def test_vectors_match():
    v = json.load(open(_vectors_path()))
    pubkeys = v["pubkeys"]
    ah = v["action_hash"]
    failures = []
    for case in v["cases"]:
        # Engine ground truth.
        engine = tally(ah, case["signatures"], pubkeys,
                       threshold=v["threshold"], n=v["n"])
        # Our verify_quorum re-checking a QC built straight from vector sigs.
        qc = {
            "action_hash": ah,
            "threshold": v["threshold"],
            "n": v["n"],
            "witnesses": [s for s in case["signatures"] if s is not None],
        }
        ver = Q.verify_quorum(qc, pubkeys)
        match = (
            ver.consensus_count == engine.consensus_count
            and ver.canonical == (engine.decision == "canonical")
            and ver.canonical == (case["expect"]["decision"] == "canonical")
            and ver.consensus_count == case["expect"]["consensus_count"]
        )
        print(f"[{'PASS' if match else 'FAIL'}] vector '{case['name']}': "
              f"{ver.consensus_count}-of-{v['n']} canonical={ver.canonical}")
        if not match:
            failures.append(case["name"])
    assert not failures, f"vector mismatches: {failures}"


# ─────────────────────────────────────────────────────────────────────────────
# 2. propose_action -> verify_quorum round trip with REAL freshly-generated keys.
# ─────────────────────────────────────────────────────────────────────────────
def test_propose_and_verify_all_allow():
    organs = list(Q.DEFAULT_ORGANS)
    priv, pub = gen_keys(organs)
    action = {
        "type": "szl-mesh/state-transition/v1",
        "crdt_document_id": "formation-001/platforms",
        "change_hash": "deadbeef" * 8,
        "transition_class": "COMMAND",
        "node_id": "node-alpha",
    }
    qc = Q.propose_action(action, witness_keys=priv)
    assert qc.canonical is True
    assert qc.consensus_count == 4
    # Every sig in the cert is real ECDSA-P256 — verify independently.
    ver = Q.verify_quorum(qc, pub)
    assert ver.canonical is True and ver.consensus_count == 4
    print(f"[PASS] propose/verify 4-of-4 canonical (real keys), ah={qc.action_hash[:16]}…")


# ─────────────────────────────────────────────────────────────────────────────
# 3. 3-of-4: a bad/missing 4th witness STILL yields canonical (tolerates f=1).
# ─────────────────────────────────────────────────────────────────────────────
def test_three_of_four_missing_fourth():
    organs = list(Q.DEFAULT_ORGANS)
    priv, pub = gen_keys(organs)
    # Drop the 4th witness entirely (offline/missing): no key supplied.
    missing = dict(priv)
    del missing[organs[3]]
    qc = Q.propose_action("a" * 64, witness_keys=missing)
    assert qc.canonical is True, "3 valid allow sigs must be canonical"
    assert qc.consensus_count == 3
    ver = Q.verify_quorum(qc, pub)
    assert ver.canonical is True and ver.consensus_count == 3
    print("[PASS] 3-of-4 (missing 4th witness) -> canonical")


def test_three_of_four_fourth_blocks():
    organs = list(Q.DEFAULT_ORGANS)
    priv, pub = gen_keys(organs)
    # 4th witness present but votes 'block' (dissent) — still 3 allow.
    qc = Q.propose_action("b" * 64, witness_keys=priv,
                          verdicts={organs[3]: "block"})
    assert qc.canonical is True and qc.consensus_count == 3
    ver = Q.verify_quorum(qc, pub)
    assert ver.canonical is True and ver.consensus_count == 3
    print("[PASS] 3-of-4 (4th witness blocks) -> canonical")


# ─────────────────────────────────────────────────────────────────────────────
# 4. 2-bad: TWO bad witnesses => NOT canonical (2-of-4 < threshold 3).
# ─────────────────────────────────────────────────────────────────────────────
def test_two_bad_not_canonical_blocks():
    organs = list(Q.DEFAULT_ORGANS)
    priv, pub = gen_keys(organs)
    qc = Q.propose_action("c" * 64, witness_keys=priv,
                          verdicts={organs[2]: "block", organs[3]: "block"})
    assert qc.canonical is False, "only 2 allow sigs must NOT be canonical"
    assert qc.consensus_count == 2
    ver = Q.verify_quorum(qc, pub)
    assert ver.canonical is False and ver.consensus_count == 2
    print("[PASS] 2-bad (two blocks) -> NOT canonical")


def test_two_bad_forged_sig_not_canonical():
    organs = list(Q.DEFAULT_ORGANS)
    priv, pub = gen_keys(organs)
    qc = Q.propose_action("d" * 64, witness_keys=priv)
    # Forge/corrupt two witnesses' signatures in the cert.
    d = qc.to_dict()
    bad = "MEUCIQzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzAiEAzzzzzzzzz"
    d["witnesses"][2]["sig"] = bad
    d["witnesses"][3]["sig"] = bad
    ver = Q.verify_quorum(d, pub)
    assert ver.canonical is False, "two forged sigs cannot reach quorum"
    assert ver.consensus_count == 2
    print("[PASS] 2-bad (two forged sigs excluded) -> NOT canonical")


def test_never_fabricate_wrong_hash_excluded():
    """A witness signing a DIFFERENT action hash does not count (no fabrication)."""
    organs = list(Q.DEFAULT_ORGANS)
    priv, pub = gen_keys(organs)
    ah = "e" * 64
    # Three sign the real hash; one signs a different hash.
    good = Q.propose_action(ah, witness_keys={o: priv[o] for o in organs[:3]})
    other = Q.propose_action("f" * 64, witness_keys={organs[3]: priv[organs[3]]})
    combined = good.to_dict()
    combined["witnesses"].extend(other.to_dict()["witnesses"])
    ver = Q.verify_quorum(combined, pub)
    # The wrong-hash sig does not count; 3 valid over the SAME hash remain.
    assert ver.consensus_count == 3 and ver.canonical is True
    print("[PASS] wrong-hash witness excluded; 3 over same hash -> canonical")


# ─────────────────────────────────────────────────────────────────────────────
# 5. Soft-safety AP corroboration (spec/04) — annotation only, never blocks.
# ─────────────────────────────────────────────────────────────────────────────
def test_corroboration_soft_safety_ap():
    ledger = Q.CorroborationLedger()
    assert ledger.soft_safety_ap is True
    assert ledger.blocks_writes is False  # NEVER blocks writes
    ch = "cafebabe" * 8
    # COMMAND policy k=2. One node -> PENDING (write already happened, AP).
    a1 = ledger.observe(ch, "node-1", transition_class="COMMAND")
    assert a1["status"] == "PENDING"
    # A second DISTINCT node -> CORROBORATED.
    a2 = ledger.observe(ch, "node-2", transition_class="COMMAND")
    assert a2["status"] == "CORROBORATED"
    # Re-observe by the same node must not double-count (CRDT set-union).
    a3 = ledger.observe(ch, "node-2", transition_class="COMMAND")
    assert a3["status"] == "CORROBORATED"
    assert len(set(a3["corroborating_nodes"])) == 2
    print("[PASS] corroboration: PENDING -> CORROBORATED at k=2 (soft-safety AP, never blocks)")


def test_corroboration_single_byzantine_cannot_corroborate():
    """k > f: a single Byzantine node alone cannot reach CORROBORATED at k=2."""
    ledger = Q.CorroborationLedger()
    ch = "deadc0de" * 8
    ann = ledger.observe(ch, "byz-node", transition_class="PLATFORM_STATUS")
    assert ann["status"] == "PENDING"  # one reporter < k=2
    print("[PASS] single Byzantine node cannot self-corroborate (k=2 > f=1)")


def test_combined_classification_table():
    assert "command-ready" in Q.combined_classification("AUTHORIZED", "CORROBORATED")
    assert Q.combined_classification("AUTHORIZED", "FAILED").startswith("Alert")
    print("[PASS] receipt × corroboration classification table matches spec/04 §6")


# ─────────────────────────────────────────────────────────────────────────────
# 6. Duplicate-organ robustness — quorum counts DISTINCT valid organs, so a peer
#    submitting duplicate organ entries can neither inflate nor deflate quorum.
# ─────────────────────────────────────────────────────────────────────────────
def test_quorum_deflation_forged_duplicate_cannot_demote():
    """A forged duplicate of a genuine organ must NOT deflate a real 3-of-4.

    Models a peer that front-runs a forged copy of an organ's record ahead of
    that organ's genuine signature. Distinct-organ counting keeps the honest
    quorum intact — a keep-first dedupe would have dropped the real entry and
    demoted the 3-of-4 to a 2-of-4.
    """
    organs = list(Q.DEFAULT_ORGANS)
    priv, pub = gen_keys(organs)
    # Genuine 3-of-4: the 4th witness is offline/missing.
    present = {o: priv[o] for o in organs[:3]}
    qc = Q.propose_action("a1" * 32, witness_keys=present)
    assert qc.canonical is True and qc.consensus_count == 3
    d = qc.to_dict()
    # Front-run a FORGED duplicate of the first organ ahead of its real record.
    bad = "MEUCIQzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzAiEAzzzzzzzzz"
    forged_dup = dict(d["witnesses"][0])
    forged_dup["sig"] = bad
    d["witnesses"].insert(0, forged_dup)
    ver = Q.verify_quorum(d, pub)
    assert ver.consensus_count == 3, "forged duplicate must not demote the real organ"
    assert ver.canonical is True
    print("[PASS] deflation: forged duplicate organ cannot demote a real 3-of-4")


def test_quorum_inflation_replayed_sig_counts_once():
    """One organ's valid signature replayed N times counts ONCE (no forgery).

    A Byzantine peer holding a single witness key cannot manufacture a quorum by
    duplicating its own valid record; distinct-organ counting caps it at 1.
    """
    organs = list(Q.DEFAULT_ORGANS)
    priv, pub = gen_keys(organs)
    qc = Q.propose_action("b2" * 32, witness_keys={organs[0]: priv[organs[0]]})
    assert qc.consensus_count == 1 and qc.canonical is False
    d = qc.to_dict()
    only = d["witnesses"][0]
    # Replay the SAME valid record three times.
    d["witnesses"] = [dict(only), dict(only), dict(only)]
    ver = Q.verify_quorum(d, pub)
    assert ver.consensus_count == 1, "replayed single-key sig must count once"
    assert ver.canonical is False, "one witness can never reach threshold 3"
    print("[PASS] inflation: replayed single-organ signature counts once (<threshold)")


def test_verify_quorum_malformed_input_fail_closed():
    """Structurally invalid certificates are fail-closed: never raise, never
    fabricate a quorum."""
    organs = list(Q.DEFAULT_ORGANS)
    _priv, pub = gen_keys(organs)
    # Not a QuorumCertificate / dict.
    for bad_qc in (None, "not-a-cert", 42, ["witnesses"]):
        ver = Q.verify_quorum(bad_qc, pub)
        assert ver.canonical is False and ver.consensus_count == 0
    # Missing / empty / non-string action_hash.
    for ah in (None, "", 123, {}):
        ver = Q.verify_quorum({"action_hash": ah, "witnesses": []}, pub)
        assert ver.canonical is False and ver.consensus_count == 0
    # witnesses not a list — tolerated, fail-closed.
    ver = Q.verify_quorum({"action_hash": "c" * 64, "witnesses": "nope"}, pub)
    assert ver.canonical is False and ver.consensus_count == 0
    # Non-dict witness entries are ignored; a dict without payload/sig cannot count.
    ver = Q.verify_quorum(
        {"action_hash": "c" * 64, "witnesses": [None, 7, "x", {"organ": "sentra"}]},
        pub,
    )
    assert ver.canonical is False and ver.consensus_count == 0
    print("[PASS] malformed certificate input is fail-closed (canonical=False, no raise)")


ALL = [
    test_vectors_match,
    test_propose_and_verify_all_allow,
    test_three_of_four_missing_fourth,
    test_three_of_four_fourth_blocks,
    test_two_bad_not_canonical_blocks,
    test_two_bad_forged_sig_not_canonical,
    test_never_fabricate_wrong_hash_excluded,
    test_corroboration_soft_safety_ap,
    test_corroboration_single_byzantine_cannot_corroborate,
    test_combined_classification_table,
    test_quorum_deflation_forged_duplicate_cannot_demote,
    test_quorum_inflation_replayed_sig_counts_once,
    test_verify_quorum_malformed_input_fail_closed,
]


if __name__ == "__main__":
    for t in ALL:
        t()
    print(f"\nALL {len(ALL)} QUORUM TESTS PASSED")
