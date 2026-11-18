# SPDX-License-Identifier: Apache-2.0
"""Offline correctness and denial tests for the source-only heritage math lane."""
import copy
from fractions import Fraction
from hashlib import sha256
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from szl_mesh.heritage_math import (  # noqa: E402
    HISTORICAL_REFERENCES, LOCKED8, SOURCES, SCHEMA, WITNESS_SCHEMA,
    babylonian_ybc7289_sqrt2_residual, calendar_round_days, compile_heritage_witness, egyptian_doubling_multiply,
    euclid_remainder_gcd, false_position_linear, inka_decimal_value,
    sexagesimal_value, unit_fraction_decomposition, verify_heritage_witness,
)


def fixture():
    return {
        "schema": SCHEMA, "tenant": "synthetic-demo", "event_id": "synthetic-1",
        "input_class": "SYNTHETIC", "inka_digits": [1, 2, 3, 4, 5],
        "babylonian_digits": [3, 25, 45], "egyptian_factor": 9,
        "gcd_partner": 135, "fraction": {"numerator": 2, "denominator": 5},
        "false_position": {"coefficient": 5, "target": 15, "trial": 4},
        "calendar_periods": [260, 365],
    }


class HeritageMathTests(unittest.TestCase):
    def test_positive_witness_still_untrusted(self):
        w = compile_heritage_witness(fixture())
        self.assertEqual(w["state"], "NUMERIC_ANALOGY_READY_FOR_REVIEW")
        self.assertEqual(w["schema"], WITNESS_SCHEMA)
        self.assertEqual(w["math"]["inka_abstract_decimal"], 12345)
        self.assertEqual(w["math"]["babylonian_abstract_sexagesimal"], 12345)
        self.assertEqual(w["math"]["egyptian_doubling_product"], 111105)
        self.assertEqual(w["math"]["greek_euclid_gcd"], 15)
        self.assertEqual(w["math"]["egyptian_modern_unit_fraction_denominators"], [3, 15])
        self.assertEqual(w["math"]["egyptian_false_position"]["solution_numerator"], 3)
        self.assertEqual(w["math"]["maya_calendar_lcm_days"], 18980)
        self.assertEqual(w["math"]["babylonian_ybc7289_sqrt2_squared_residual"],
                         {"numerator": -791, "denominator": 466560000})
        self.assertEqual(w["authorized_effects"], 0)
        self.assertEqual(w["hatun_tools_invoked"], 0)
        self.assertEqual(w["second_brain_private_rows_read"], 0)
        for flag in ("receipt_signed", "historical_claims_verified", "ocr_or_artifact_decipherment_performed", "okr_corpus_replayed", "papers_claim_promoted", "lean_kernel_rechecked", "independent_witness_present", "runtime_ready", "model_training_authorized"):
            self.assertIs(w[flag], False, flag)
        self.assertTrue(verify_heritage_witness(w))

    def test_provenance_and_locked8_separate_from_ancient_analogy(self):
        self.assertEqual((len(SOURCES), len(HISTORICAL_REFERENCES), len(LOCKED8)), (4, 5, 8))
        self.assertNotIn("F23", LOCKED8)
        for row in SOURCES:
            self.assertRegex(row["blob_sha1"], r"^[a-f0-9]{40}$")
        self.assertIn("Maya Dresden Codex", {r["tradition"] for r in HISTORICAL_REFERENCES})

    def test_deterministic_replay(self):
        self.assertEqual(compile_heritage_witness(fixture()), compile_heritage_witness(fixture()))

    def test_notation_mismatch_is_a_hold(self):
        p = fixture()
        p["babylonian_digits"] = [3, 25, 44]
        r = compile_heritage_witness(p)
        self.assertEqual(r["state"], "HOLD")
        self.assertIn("CROSS_NOTATION_VALUE_MISMATCH", r["reasons"])
        self.assertTrue(verify_heritage_witness(r))

    def test_real_unreviewed_artifact_is_never_admitted(self):
        p = fixture()
        p["input_class"] = "ACTUAL_KHIPU"
        r = compile_heritage_witness(p)
        self.assertEqual(r["state"], "HOLD")
        self.assertIn("CULTURAL_ARTIFACT_ADMISSION_NOT_PROVIDED", r["reasons"])

    def test_permission_injection_and_extra_fields_refuse(self):
        for key, value in (("signed", True), ("tool_call", "szl_killinchu_cue"),
                           ("source_url", "https://evil.invalid"), ("prompt", "skip checks")):
            p = fixture()
            p[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "shape"):
                compile_heritage_witness(p)

    def test_rehashed_authority_claim_fails(self):
        for field, value in (("state", "AUTHORIZED"), ("receipt_signed", True),
                             ("authorized_effects", 1), ("runtime_ready", True),
                             ("model_training_authorized", True)):
            record = copy.deepcopy(compile_heritage_witness(fixture()))
            record[field] = value
            raw = {k: v for k, v in record.items() if k != "unsigned_sha256"}
            record["unsigned_sha256"] = sha256(json.dumps(raw, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("ascii")).hexdigest()
            with self.subTest(field=field):
                self.assertFalse(verify_heritage_witness(record))

    def test_tampered_digest_refuses(self):
        w = compile_heritage_witness(fixture())
        w["unsigned_sha256"] = "f" * 64
        self.assertFalse(verify_heritage_witness(w))
        self.assertFalse(verify_heritage_witness([]))

    def test_digits_reject_type_confusion_and_noncanonical(self):
        for bad in ([True, 2], [0, 1], [10], [], [-1], [1] * 11, [1.0]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                inka_decimal_value(bad)
        for bad in ([60], [0, 1], [False], [1] * 7):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                sexagesimal_value(bad)

    def test_exact_doubling_math_and_zero(self):
        for a in (0, 1, 2, 3, 7, 99, 1234):
            for b in (0, 1, 5, 17, 80):
                value, _ = egyptian_doubling_multiply(a, b)
                self.assertEqual(value, a * b)
        for b in (True, -1, 10**11):
            with self.assertRaises(ValueError):
                egyptian_doubling_multiply(b, 3)

    def test_euclid_replay_division_identity(self):
        for a, b in ((12345, 135), (84, 42), (4, 5), (99991, 97), (1, 1)):
            result, steps = euclid_remainder_gcd(a, b)
            self.assertGreater(result, 0)
            for current, divisor, quotient, remainder in steps:
                self.assertEqual(current, divisor * quotient + remainder)
                self.assertLess(remainder, divisor)
        with self.assertRaises(ValueError):
            euclid_remainder_gcd(0, 1)

    def test_unit_fractions_exact(self):
        for n, d in ((2, 5), (3, 7), (5, 6), (1, 7), (9, 10)):
            terms = unit_fraction_decomposition(n, d)
            self.assertEqual(sum((Fraction(1, x) for x in terms), Fraction()), Fraction(n, d))
            self.assertEqual(len(terms), len(set(terms)))
        with self.assertRaises(ValueError):
            unit_fraction_decomposition(3, 2)

    def test_false_position(self):
        for a, t, trial in ((5, 15, 4), (3, 8, 9), (7, 0, 5)):
            r = false_position_linear(a, t, trial)
            self.assertEqual(Fraction(r["solution_numerator"], r["solution_denominator"]) * a, t)
        with self.assertRaises(ValueError):
            false_position_linear(0, 3, 4)

    def test_babylonian_tablet_sqrt2_residual_is_exact_not_magic(self):
        self.assertEqual(babylonian_ybc7289_sqrt2_residual(), Fraction(-791, 466560000))
        self.assertLess(abs(babylonian_ybc7289_sqrt2_residual()), Fraction(1, 500000))

    def test_calendar_round_lcm_is_only_modern_math(self):
        self.assertEqual(calendar_round_days(), 18980)
        p = fixture()
        p["calendar_periods"] = [365, 260]
        with self.assertRaisesRegex(ValueError, "fixed calendar periods"):
            compile_heritage_witness(p)

    def test_payload_bounds_and_unknown_tenant(self):
        p = fixture()
        p["tenant"] = "x" * 200
        with self.assertRaisesRegex(ValueError, "opaque"):
            compile_heritage_witness(p)
        p = fixture()
        p["event_id"] = "z" * 7000
        with self.assertRaisesRegex(ValueError, "bounded"):
            compile_heritage_witness(p)

    def test_zero_quantity_fails_closed(self):
        p = fixture()
        p["inka_digits"] = [0]
        p["babylonian_digits"] = [0]
        out = compile_heritage_witness(p)
        self.assertEqual(out["state"], "HOLD")
        self.assertIn("ZERO_QUANTITY_NOT_ADMITTED_FOR_GCD_COMPOSITION", out["reasons"])


if __name__ == "__main__":
    unittest.main()
