# SPDX-License-Identifier: Apache-2.0
"""Verify cross-civilization math can join the existing eight-organ advisory only."""
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from test_agentic_fabric import fixture as organ_fixture
from test_heritage_math import fixture as heritage_fixture
from szl_mesh.heritage_math import compile_joint_advisory, verify_joint_advisory

NOW = datetime(2026, 11, 18, 3, 40, tzinfo=timezone.utc)


def good():
    organ = organ_fixture()
    heritage = heritage_fixture()
    heritage["tenant"] = organ["tenant"]
    return organ, heritage


class JointSourceOnlyTests(unittest.TestCase):
    def test_join_succeeds_only_as_proposal(self):
        a, b = good()
        result = compile_joint_advisory(a, b, now=NOW)
        self.assertEqual(result["state"], "JOINT_PROPOSAL_READY_FOR_OWNER_REVIEW")
        self.assertEqual(result["source_count_reported_by_organ_advisory"], 8)
        self.assertEqual(result["math_source_refs_count"], 4)
        self.assertTrue(verify_joint_advisory(result))
        for k in ("authorized_effects", "tools_invoked", "sql_writes", "agent_actions_executed"):
            self.assertEqual(result[k], 0)

    def test_cross_tenant_refused(self):
        a, b = good()
        b["tenant"] = "different-tenant"
        result = compile_joint_advisory(a, b, now=NOW)
        self.assertIn("CROSS_TENANT_EVIDENCE_REFUSED", result["reasons"])
        self.assertEqual(result["state"], "HOLD")

    def test_anatomy_down_propagates_hold(self):
        a, b = good()
        a["organs"]["YUYAY"] = "DOWN"
        result = compile_joint_advisory(a, b, now=NOW)
        self.assertIn("EIGHT_ORGAN_EVIDENCE_NOT_ADMITTED", result["reasons"])

    def test_math_mismatch_propagates_hold(self):
        a, b = good()
        b["babylonian_digits"][2] = 44
        result = compile_joint_advisory(a, b, now=NOW)
        self.assertIn("HERITAGE_NUMERIC_WITNESS_NOT_ADMITTED", result["reasons"])

    def test_rehashed_forged_authority_is_not_verified(self):
        a, b = good()
        result = compile_joint_advisory(a, b, now=NOW)
        result["authorized_effects"] = 1
        core = {k: v for k, v in result.items() if k != "unsigned_sha256"}
        result["unsigned_sha256"] = sha256(json.dumps(core, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("ascii")).hexdigest()
        self.assertFalse(verify_joint_advisory(result))

    def test_untrusted_extra_source_grant_refuses(self):
        a, b = good()
        a["signed"] = True
        with self.assertRaisesRegex(ValueError, "packet shape"):
            compile_joint_advisory(a, b, now=NOW)


if __name__ == "__main__":
    unittest.main()
