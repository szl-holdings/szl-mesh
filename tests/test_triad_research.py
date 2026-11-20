# SPDX-License-Identifier: Apache-2.0
"""Synthetic negative controls; never invoke Kimi, Mistral, GPT or providers."""
from __future__ import annotations

import ast
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from szl_mesh import triad_research as triad  # noqa: E402

NOW = datetime(2026, 11, 20, 8, 30, tzinfo=timezone.utc)


def fixture():
    plan = {
        "schema": triad.PLAN_SCHEMA,
        "repository": "szl-holdings/szl-mesh",
        "source_sha": "a" * 40,
        "patch_sha256": "b" * 64,
        "rubric_sha256": "c" * 64,
        "case_digests": [f"{i+1:064x}" for i in range(5)],
        "cycle": 1,
        "prior_cycle_digest": None,
    }
    digest = triad.plan_digest(plan)
    roles = list(triad.ROLE_FAMILIES.items())
    reviews = []
    for i, (role, family) in enumerate(roles):
        reviews.append({
            "schema": triad.SUBMISSION_SCHEMA,
            "role": role,
            "model_family": family,
            "model_id": ["kimi-k3.1-pro:cloud", "mistral-large-4:cloud", "GPT-6-CHATGPT"][i],
            "operator_digest": f"{i+11:064x}",
            "source_sha": plan["source_sha"],
            "patch_sha256": plan["patch_sha256"],
            "plan_sha256": digest,
            "submission_sha256": f"{i+21:064x}",
            "response_sha256": f"{i+31:064x}",
            "observed_at_utc": (NOW - timedelta(seconds=8)).isoformat().replace("+00:00", "Z"),
            "rows": [{"case_sha256": case,
                      "verdict": "APPROVE", "reason": "NO_FINDINGS"}
                     for case in plan["case_digests"]],
        })
    return plan, reviews, digest


def compile_case(plan=None, reviews=None, digest=None, now=NOW):
    if plan is None or reviews is None:
        plan, reviews, digest = fixture()
    if digest is None:
        try:
            digest = triad.plan_digest(plan)
        except triad.TriadHold:
            digest = "1" * 64
    return triad.compile_triad(
        plan, reviews, expected_plan_sha256=digest,
        expected_source_sha="a" * 40, now=now,
    )


class TriadResearchTest(unittest.TestCase):
    def hold(self, plan, reviews, reason, *, digest=None):
        result = compile_case(plan, reviews, digest)
        self.assertEqual(result["state"], "HOLD")
        self.assertEqual(result["reason"], reason)
        self.assertFalse(result["merge_authorized"])
        return result

    def test_three_matrix_agreement_is_never_authenticated_authority(self):
        result = compile_case()
        self.assertEqual(result["state"], "HOLD")
        self.assertEqual(result["advisory_state"], "THREE_DECLARED_MATRIX_AGREEMENT_NOT_AUTHENTICATED")
        self.assertEqual(result["declared_unanimous_cases"], 5)
        self.assertEqual(result["frozen_cases"], 5)
        self.assertFalse(result["identity_authenticated"])
        self.assertFalse(result["training_authorized"])
        self.assertFalse(result["deployment_authorized"])
        self.assertEqual(len(result["unsigned_report_digest_not_signature"]), 64)
        self.assertNotIn(f"{1:064x}", json.dumps(result))

    def test_two_approvals_one_dissent_cannot_be_majority_promoted(self):
        plan, reviews, digest = fixture()
        reviews[1]["rows"][0].update(verdict="REJECT", reason="SAFETY_RISK")
        result = self.hold(plan, reviews, "OWNER_GATE_ALWAYS_REQUIRED", digest=digest)
        self.assertEqual(result["advisory_state"], "DECLARED_DISSENT")
        self.assertEqual(result["dissenting_cases"], 1)
        self.assertEqual(result["case_summaries"][0]["declared_approvals"], 2)
        self.assertEqual(result["case_summaries"][0]["state"], "HOLD_DISSENT")

    def test_no_submissions_mean_missing_not_consensus(self):
        plan, reviews, digest = fixture()
        result = self.hold(plan, [], "OWNER_GATE_ALWAYS_REQUIRED", digest=digest)
        self.assertEqual(len(result["missing_reviewer_slots"]), 3)
        self.assertEqual(result["advisory_state"], "MISSING_REVIEWER")
        self.assertEqual(result["declared_unanimous_cases"], 0)
        self.assertTrue(all(r["state"] == "HOLD_MISSING_REVIEWER" for r in result["case_summaries"]))

    def test_two_reviewers_with_dissent_preserves_both_facts(self):
        plan, reviews, digest = fixture()
        reviews[1]["rows"][2].update(verdict="REJECT", reason="EVIDENCE_CONFLICT")
        result = compile_case(plan, reviews[:2], digest)
        self.assertEqual(result["advisory_state"], "DECLARED_DISSENT")
        self.assertEqual(result["missing_reviewer_slots"], ["GPT6_REFEREE"])
        self.assertEqual(result["case_summaries"][2]["state"], "HOLD_DISSENT")
        self.assertEqual(result["case_summaries"][0]["state"], "HOLD_MISSING_REVIEWER")

    def test_missing_case_row_is_hold_not_implicit_approval(self):
        plan, reviews, digest = fixture()
        reviews[1]["rows"].pop()
        self.hold(plan, reviews, "REVIEW_POPULATION_INCOMPLETE", digest=digest)

    def test_duplicate_case_in_one_matrix_fails(self):
        plan, reviews, digest = fixture()
        reviews[1]["rows"][1]["case_sha256"] = reviews[1]["rows"][0]["case_sha256"]
        self.hold(plan, reviews, "DUPLICATE_REVIEW_CASE", digest=digest)

    def test_substituted_case_at_same_count_fails(self):
        plan, reviews, digest = fixture()
        reviews[1]["rows"][1]["case_sha256"] = "f" * 64
        self.hold(plan, reviews, "UNKNOWN_OR_SUBSTITUTED_CASE", digest=digest)

    def test_declared_family_role_swap_rejected(self):
        plan, reviews, digest = fixture()
        reviews[0]["model_family"] = "MISTRAL"
        self.hold(plan, reviews, "DECLARED_SLOT_FAMILY_MISMATCH", digest=digest)

    def test_two_submissions_same_role_rejected(self):
        plan, reviews, digest = fixture()
        reviews[1]["role"] = reviews[0]["role"]
        reviews[1]["model_family"] = reviews[0]["model_family"]
        self.hold(plan, reviews, "DUPLICATE_REVIEWER_SLOT", digest=digest)

    def test_shared_operator_digest_is_flagged_not_independence(self):
        plan, reviews, digest = fixture()
        reviews[2]["operator_digest"] = reviews[0]["operator_digest"]
        result = compile_case(plan, reviews, digest)
        self.assertIn("DECLARED_OPERATOR_COLLISION", result["suspicious_declarations"])
        self.assertEqual(result["advisory_state"], "SUSPICIOUS_DECLARATIONS")
        self.assertFalse(result["reviewers_independent_verified"])

    def test_replayed_submission_id_refused(self):
        plan, reviews, digest = fixture()
        reviews[2]["submission_sha256"] = reviews[0]["submission_sha256"]
        self.hold(plan, reviews, "REPLAYED_SUBMISSION_ID", digest=digest)

    def test_identical_response_digest_not_identity_proof(self):
        plan, reviews, digest = fixture()
        reviews[2]["response_sha256"] = reviews[0]["response_sha256"]
        result = compile_case(plan, reviews, digest)
        self.assertIn("DUPLICATE_RESPONSE_DIGEST", result["suspicious_declarations"])
        self.assertFalse(result["identity_authenticated"])

    def test_stale_or_future_timestamp_never_claims_freshness(self):
        for delta in (-901, 6):
            plan, reviews, digest = fixture()
            reviews[0]["observed_at_utc"] = (NOW + timedelta(seconds=delta)).isoformat().replace("+00:00", "Z")
            result = compile_case(plan, reviews, digest)
            self.assertIn("STALE_OR_FUTURE_DECLARATION", result["suspicious_declarations"])

    def test_changed_plan_population_is_not_same_frozen_task(self):
        plan, reviews, digest = fixture()
        plan["case_digests"].reverse()
        self.hold(plan, reviews, "FROZEN_PLAN_DIGEST_MISMATCH", digest=digest)

    def test_cycle_two_requires_predecessor_but_is_not_verified(self):
        plan, reviews, digest = fixture()
        plan["cycle"] = 2
        self.hold(plan, reviews, "CYCLE_PREDECESSOR_INVALID")
        plan["prior_cycle_digest"] = "e" * 64
        new_digest = triad.plan_digest(plan)
        for row in reviews:
            row["plan_sha256"] = new_digest
        result = compile_case(plan, reviews, new_digest)
        self.assertEqual(result["cycle"], 2)
        self.assertFalse(result["cycle_predecessor_independently_verified"])
        plan["cycle"] = 11
        self.hold(plan, reviews, "CYCLE_OUT_OF_BOUNDS")

    def test_malformed_verdict_and_reason_fail_closed(self):
        plan, reviews, digest = fixture()
        reviews[0]["rows"][0].update(verdict="APPROVE", reason="SAFETY_RISK")
        self.hold(plan, reviews, "REVIEW_DECISION_REASON_INVALID", digest=digest)
        reviews[0]["rows"][0].update(verdict="PROMOTE", reason="NO_FINDINGS")
        self.hold(plan, reviews, "REVIEW_DECISION_REASON_INVALID", digest=digest)

    def test_extra_model_prompt_or_auth_field_rejected(self):
        plan, reviews, digest = fixture()
        reviews[0]["raw_prompt"] = "sensitive prompt"
        self.hold(plan, reviews, "SUBMISSION_SCHEMA_INVALID", digest=digest)
        plan, reviews, digest = fixture()
        plan["auto_merge"] = True
        self.hold(plan, reviews, "PLAN_SCHEMA_INVALID")

    def test_boolean_confusion_and_bad_hashes_refused(self):
        plan, reviews, digest = fixture()
        plan["cycle"] = True
        self.hold(plan, reviews, "CYCLE_OUT_OF_BOUNDS")
        plan, reviews, digest = fixture()
        reviews[0]["operator_digest"] = "0" * 64
        self.hold(plan, reviews, "REVIEW_DIGEST_INVALID", digest=digest)
        plan, reviews, digest = fixture()
        reviews[0]["source_sha"] = "wrong"
        self.hold(plan, reviews, "REVIEW_SOURCE_OR_PLAN_MISMATCH", digest=digest)

    def test_missing_evidence_is_not_approval(self):
        plan, reviews, digest = fixture()
        reviews[0]["rows"][0].update(verdict="UNAVAILABLE", reason="REVIEW_UNAVAILABLE")
        result = compile_case(plan, reviews, digest)
        self.assertEqual(result["advisory_state"], "DECLARED_UNAVAILABLE")
        self.assertEqual(result["case_summaries"][0]["state"], "HOLD_UNAVAILABLE")

    def test_no_private_case_ids_no_mutation_and_determinism(self):
        plan, reviews, digest = fixture()
        before = deepcopy((plan, reviews))
        r1 = compile_case(plan, reviews, digest)
        r2 = compile_case(plan, list(reversed(reviews)), digest)
        self.assertEqual(r1, r2)
        self.assertEqual((plan, reviews), before)
        self.assertNotIn(f"{1:064x}", json.dumps(r1))

    def test_oversized_population_and_duplicate_plan_case(self):
        plan, reviews, digest = fixture()
        plan["case_digests"] = [f"{i+1:064x}" for i in range(257)]
        self.hold(plan, reviews, "CASE_POPULATION_INVALID")
        plan, reviews, digest = fixture()
        plan["case_digests"][1] = plan["case_digests"][0]
        self.hold(plan, reviews, "DUPLICATE_CASE")

    def test_no_effectful_imports_present(self):
        source = (ROOT / "src/szl_mesh/triad_research.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        forbidden = {"subprocess", "requests", "httpx", "urllib", "socket", "os", "torch", "trl", "huggingface_hub"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                self.assertFalse(forbidden.intersection(a.name.split(".")[0] for a in node.names))
            if isinstance(node, ast.ImportFrom):
                self.assertNotIn(node.module.split(".")[0], forbidden)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, {"open", "eval", "exec"})

    def test_duplicate_json_keys_and_nonfinite_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            file = Path(td) / "record.json"
            file.write_text('{"x": 1, "x": 2}', encoding="utf-8")
            with self.assertRaises(triad.TriadHold):
                triad.load_json(file)
            file.write_text('{"x": NaN}', encoding="utf-8")
            with self.assertRaises(triad.TriadHold):
                triad.load_json(file)


if __name__ == "__main__":
    unittest.main()
