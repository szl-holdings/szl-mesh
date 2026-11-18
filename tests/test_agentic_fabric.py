# SPDX-License-Identifier: Apache-2.0
"""No-network, stdlib-only admission-negative tests for eight source owners."""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from szl_mesh.agentic_fabric import (  # noqa: E402
    DOCTRINE, EDGES, FORMULAS21, INVARIANTS8, KERNEL_PIN, LAMBDA_STATUS,
    LOCKED8, ORGANS5, SCHEMA, SOURCE_PINS, compile_advisory, verify_advisory,
)

NOW = datetime(2026, 11, 18, 3, 40, tzinfo=timezone.utc)


def fixture():
    return {
        "schema": SCHEMA,
        "event_id": "synthetic-photo-event-1",
        "tenant": "synthetic-tenant",
        "sources": {
            owner: {
                "revision": sha,
                "digest": "a" * 64,
                "state": "OBSERVED",
                "tenant": "synthetic-tenant",
                "observed_utc": NOW.isoformat(),
            }
            for owner, (_, sha) in SOURCE_PINS.items()
        },
        "handles": [{
            "digest": "b" * 64,
            "source_revision": SOURCE_PINS["second_brain"][1],
            "tenant": "synthetic-tenant",
            "review_state": "REVIEWED_PUBLIC",
        }],
        "organs": {name: "UP" for name in ORGANS5},
        "formulas": ["lambda_bounded", "khipu_merkle_root"],
        "invariants": {name: "HOLDS" for name in INVARIANTS8},
        "hatun_tool": "szl_doctrine_lookup",
        "oro_steps": 3,
        "oro_terminated": True,
        "lambda_status": LAMBDA_STATUS,
        "locked8": sorted(LOCKED8),
    }


class SourceOnlyAgenticContract(unittest.TestCase):
    def test_positive_fixture_is_still_not_authority(self):
        out = compile_advisory(fixture(), now=NOW)
        self.assertEqual(out["state"], "PROPOSAL_READY_FOR_OWNER_REVIEW")
        self.assertFalse(out["source_witness_independently_authenticated"])
        self.assertFalse(out["lean_proofs_rechecked"])
        self.assertFalse(out["invariant_results_independently_recomputed"])
        self.assertFalse(out["receipt_signed"])
        self.assertFalse(out["production_ready"])
        self.assertEqual(out["authorized_effects"], 0)
        self.assertEqual(out["mcp_tools_executed"], 0)
        self.assertEqual(out["agent_actions_executed"], 0)
        self.assertEqual(out["formula_calls_executed"], 0)
        self.assertFalse(out["training_dispatched"])
        self.assertEqual(out["doctrine_version"], DOCTRINE)
        self.assertEqual(out["lean_kernel_context"], KERNEL_PIN)
        self.assertEqual(out["lambda_status"], LAMBDA_STATUS)
        self.assertTrue(verify_advisory(out))

    def test_source_counts_and_mathematical_statuses(self):
        self.assertEqual(len(SOURCE_PINS), 8)
        self.assertEqual(len(INVARIANTS8), 8)
        self.assertEqual(len(LOCKED8), 8)
        self.assertEqual(len(FORMULAS21), 21)
        self.assertEqual(len(ORGANS5), 5)
        self.assertEqual(len(EDGES), 7)

    def test_deterministic_replay(self):
        self.assertEqual(compile_advisory(fixture(), now=NOW), compile_advisory(fixture(), now=NOW))

    def test_signed_authority_cannot_be_forged_by_rehash(self):
        from hashlib import sha256
        import json
        out = compile_advisory(fixture(), now=NOW)
        out["state"] = "AUTHORIZED"
        core = {key: value for key, value in out.items() if key != "unsigned_sha256"}
        out["unsigned_sha256"] = sha256(json.dumps(core, sort_keys=True, separators=(",", ":"),
                                                ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()
        self.assertFalse(verify_advisory(out))

    def test_receipt_tamper_is_rejected(self):
        out = compile_advisory(fixture(), now=NOW)
        for k, v in [("state", "AUTHORIZED"), ("authorized_effects", 1),
                     ("receipt_signed", True), ("production_ready", True)]:
            changed = copy.deepcopy(out)
            changed[k] = v
            self.assertFalse(verify_advisory(changed), k)
        self.assertFalse(verify_advisory({**out, "unsigned_sha256": "f" * 64}))
        self.assertFalse(verify_advisory([]))

    def test_missing_sources_all_hold(self):
        p = fixture()
        p["sources"] = {}
        r = compile_advisory(p, now=NOW)
        self.assertEqual(r["state"], "HOLD")
        self.assertEqual(len([x for x in r["reasons"] if x.startswith("SOURCE_MISSING:")]), 8)
        self.assertTrue(verify_advisory(r))

    def test_every_single_source_pin_mismatch_holds(self):
        for name in SOURCE_PINS:
            with self.subTest(name=name):
                p = fixture()
                p["sources"][name]["revision"] = "c" * 40
                r = compile_advisory(p, now=NOW)
                self.assertIn("SOURCE_REVISION_MISMATCH:" + name, r["reasons"])
                self.assertEqual(r["authorized_effects"], 0)

    def test_source_tenant_taint_does_not_authorize(self):
        p = fixture()
        p["sources"]["anatomy"]["tenant"] = "other"
        self.assertIn("SOURCE_TENANT_MISMATCH:anatomy", compile_advisory(p, now=NOW)["reasons"])

    def test_source_digests_are_required(self):
        p = fixture()
        p["sources"]["lean"]["digest"] = "NOT-HEX"
        self.assertIn("SOURCE_DIGEST_UNAVAILABLE:lean", compile_advisory(p, now=NOW)["reasons"])

    def test_source_observation_is_not_source_authority(self):
        p = fixture()
        p["sources"]["hatun"]["state"] = "AUTHORIZED"
        r = compile_advisory(p, now=NOW)
        self.assertIn("SOURCE_UNOBSERVED:hatun", r["reasons"])
        self.assertFalse(r["source_witness_independently_authenticated"])

    def test_stale_future_and_unaware_source_evidence(self):
        for t in (NOW - timedelta(seconds=3601), NOW + timedelta(seconds=6)):
            p = fixture()
            p["sources"]["second_brain"]["observed_utc"] = t.isoformat()
            self.assertIn("SOURCE_STALE:second_brain", compile_advisory(p, now=NOW)["reasons"])
        p = fixture()
        p["sources"]["second_brain"]["observed_utc"] = "2026-11-18T03:40:00"
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            compile_advisory(p, now=NOW)

    def test_mixed_memory_tenant_holds(self):
        p = fixture()
        p["handles"][0]["tenant"] = "other"
        self.assertIn("MEMORY_SOURCE_OR_TENANT_MISMATCH", compile_advisory(p, now=NOW)["reasons"])

    def test_private_memory_content_is_rejected_before_any_effect(self):
        p = fixture()
        p["handles"][0]["text"] = "private secret"
        with self.assertRaisesRegex(ValueError, "memory handle"):
            compile_advisory(p, now=NOW)

    def test_unreviewed_and_duplicate_memory_holds(self):
        p = fixture()
        p["handles"][0]["review_state"] = "DISCOVERED_REVIEW_REQUIRED"
        self.assertIn("MEMORY_REVIEW_REQUIRED", compile_advisory(p, now=NOW)["reasons"])
        p = fixture()
        p["handles"].append(copy.deepcopy(p["handles"][0]))
        self.assertIn("MEMORY_DUPLICATE", compile_advisory(p, now=NOW)["reasons"])

    def test_bounded_memory(self):
        p = fixture()
        p["handles"] = [copy.deepcopy(p["handles"][0]) for _ in range(17)]
        with self.assertRaisesRegex(ValueError, "bounded public handles"):
            compile_advisory(p, now=NOW)

    def test_anatomy_veto_and_unavailable_holds(self):
        for organ in ORGANS5:
            for state in ("DOWN", "UNAVAILABLE"):
                p = fixture()
                p["organs"][organ] = state
                self.assertIn("ANATOMY_NOT_UP:" + organ, compile_advisory(p, now=NOW)["reasons"])

    def test_anatomy_missing_and_false_health_are_rejected(self):
        p = fixture()
        del p["organs"]["YUYAY"]
        with self.assertRaisesRegex(ValueError, "five named"):
            compile_advisory(p, now=NOW)
        p = fixture()
        p["organs"]["YUYAY"] = True
        with self.assertRaisesRegex(ValueError, "invalid organ"):
            compile_advisory(p, now=NOW)

    def test_each_invariant_failing_or_missing_holds(self):
        for name in INVARIANTS8:
            for state in ("VIOLATED", "KEY_ROTATED", "NO_DATA", "UNAVAILABLE"):
                p = fixture()
                p["invariants"][name] = state
                self.assertIn("INVARIANT_NOT_HOLDS:" + name,
                              compile_advisory(p, now=NOW)["reasons"])

    def test_invariant_report_requires_all_eight(self):
        p = fixture()
        p["invariants"].pop("flywheel-lineage")
        with self.assertRaisesRegex(ValueError, "exact eight"):
            compile_advisory(p, now=NOW)

    def test_unbounded_ouroboros_never_runs(self):
        for steps in (13, -1, True, "12"):
            p = fixture()
            p["oro_steps"] = steps
            with self.assertRaisesRegex(ValueError, "unbounded Ouroboros"):
                compile_advisory(p, now=NOW)
        p = fixture()
        p["oro_terminated"] = False
        self.assertIn("OUROBOROS_NOT_TERMINATED", compile_advisory(p, now=NOW)["reasons"])

    def test_hatun_mutating_tool_or_unknown_tool_hold(self):
        for tool in ("szl_killinchu_cue", "puriq_master_tool", "shell.execute"):
            p = fixture()
            p["hatun_tool"] = tool
            r = compile_advisory(p, now=NOW)
            self.assertIn("HATUN_TOOL_NOT_IN_READONLY_CATALOG", r["reasons"])
            self.assertEqual(r["mcp_tools_executed"], 0)

    def test_unknown_formula_is_rejected(self):
        for formula in ("F23_PROVED", "unknown_formula", "exec('foo')"):
            p = fixture()
            p["formulas"] = [formula]
            with self.assertRaisesRegex(ValueError, "unreviewed"):
                compile_advisory(p, now=NOW)
        p = fixture()
        p["formulas"] = ["lambda_bounded"] * 2
        self.assertIn("DUPLICATED_FORMULA", compile_advisory(p, now=NOW)["reasons"])

    def test_no_false_lean_theorem_or_locked_set(self):
        p = fixture()
        p["lambda_status"] = "THEOREM"
        with self.assertRaisesRegex(ValueError, "false mathematical"):
            compile_advisory(p, now=NOW)
        p = fixture()
        p["locked8"][0] = "F23"
        with self.assertRaisesRegex(ValueError, "false mathematical"):
            compile_advisory(p, now=NOW)

    def test_prompt_injection_cannot_supply_runtime_authority(self):
        for field, payload in [
            ("allow", True), ("signed", True), ("train", True),
            ("approved_by", "human"), ("raw_private_graph", "x"),
            ("tool_args", {"exec": "rm -rf"}), ("source_url", "https://evil.invalid"),
        ]:
            p = fixture()
            p[field] = payload
            with self.assertRaisesRegex(ValueError, "invalid packet shape"):
                compile_advisory(p, now=NOW)

    def test_extra_source_authority_field_rejected(self):
        p = fixture()
        p["sources"]["hatun"]["signed"] = True
        with self.assertRaisesRegex(ValueError, "invalid source shape"):
            compile_advisory(p, now=NOW)

    def test_acyclic_graph_and_cycle_refusal(self):
        p = fixture()
        p["edges"] = [list(e) for e in EDGES]
        self.assertEqual(compile_advisory(p, now=NOW)["state"], "PROPOSAL_READY_FOR_OWNER_REVIEW")
        p["edges"].append(["hatun", "second_brain"])
        self.assertIn("EVIDENCE_GRAPH_CYCLE", compile_advisory(p, now=NOW)["reasons"])

    def test_malformed_graph_never_passes(self):
        for edge in (["unknown", "lean"], ["hatun", "hatun"], ["khipu", 1]):
            p = fixture()
            p["edges"] = [edge]
            if edge[0] == edge[1]:
                self.assertIn("EVIDENCE_GRAPH_CYCLE", compile_advisory(p, now=NOW)["reasons"])
            else:
                with self.assertRaisesRegex(ValueError, "invalid graph edge"):
                    compile_advisory(p, now=NOW)

    def test_schema_source_and_timestamp_shapes_rejected(self):
        p = fixture()
        p["schema"] = "wrong"
        with self.assertRaisesRegex(ValueError, "wrong packet schema"):
            compile_advisory(p, now=NOW)
        p = fixture()
        p["sources"]["unknown"] = {}
        with self.assertRaisesRegex(ValueError, "unknown source"):
            compile_advisory(p, now=NOW)
        with self.assertRaisesRegex(ValueError, "independent aware clock"):
            compile_advisory(fixture(), now=datetime(2026, 11, 18, 3, 40))

    def test_oversized_payload_is_rejected(self):
        p = fixture()
        p["event_id"] = "x" * 40000
        with self.assertRaises(ValueError):
            compile_advisory(p, now=NOW)


if __name__ == "__main__":
    unittest.main()