"""The keyless hello example must not manufacture authorization evidence.

Repair provenance: OpenAI Codex, implementing the owner's repository audit.
"""

import base64
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


EXAMPLE = Path(__file__).resolve().parents[1] / "examples/hello-mesh/hello_mesh.py"
SPEC = importlib.util.spec_from_file_location("hello_mesh_example", EXAMPLE)
hello = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hello)


def event_from_output(output):
    start = output.index('{\n  "event_type"')
    return json.JSONDecoder().raw_decode(output[start:])[0]


class HelloMeshExampleTests(unittest.TestCase):
    def make_statement(self):
        return hello.build_state_transition_statement(
            "demo/platforms", "0" * 64, [], ["0" * 64], "not-an-enrolled-node"
        )

    def run_preview(self):
        output = io.StringIO()
        with patch.dict(os.environ, {}, clear=True), contextlib.redirect_stdout(output):
            result = hello.main()
        self.assertEqual(result, 0)
        return event_from_output(output.getvalue())

    def test_envelope_without_signer_has_no_signatures(self):
        stmt = self.make_statement()
        envelope = hello.build_dsse_envelope(stmt, stmt["node_id"])
        self.assertEqual(envelope["signatures"], [])

    def test_unsigned_payload_preserves_statement_and_locked_context(self):
        stmt = self.make_statement()
        envelope = hello.build_dsse_envelope(stmt, stmt["node_id"])
        payload = envelope["payload"]
        decoded = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        self.assertEqual(decoded, stmt)
        self.assertEqual(envelope["payloadType"], "application/vnd.szl.mesh.state-transition+json")
        self.assertEqual(decoded["doctrine_version"], "749/14/163")
        self.assertEqual(decoded["kernel_commit"], "c7c0ba17")
        self.assertEqual(decoded["policy_context"]["slsa_level"], "L1")
        self.assertEqual(len(decoded["policy_context"]["section_889_vendors"]), 5)

    def test_preview_event_is_observed(self):
        self.assertEqual(self.run_preview()["track"], "OBSERVED")

    def test_preview_has_no_authorized_receipt(self):
        self.assertEqual(self.run_preview()["receipt_status"], "RECEIPT_MISSING")

    def test_preview_is_explicitly_simulated_and_unpublished(self):
        event = self.run_preview()
        self.assertEqual(event.get("labels", {}).get("simulated"), "true")
        self.assertEqual(event.get("labels", {}).get("published"), "false")
        self.assertEqual(event["labels"]["receipt_evaluated"], "false")

    def test_preview_does_not_claim_measured_latency(self):
        event = self.run_preview()
        self.assertNotIn("latency_ms", event)
        self.assertEqual(event["labels"]["latency_status"], "UNAVAILABLE")

    def test_preview_does_not_claim_corroboration(self):
        event = self.run_preview()
        self.assertEqual(event["corroboration_status"], "CORROBORATION_STATUS_UNSPECIFIED")
        self.assertEqual(event["labels"]["corroboration_evaluated"], "false")

    def test_cli_needs_no_credentials_and_writes_no_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            completed = subprocess.run(
                [sys.executable, str(EXAMPLE)], cwd=directory,
                env={"PYTHONIOENCODING": "utf-8"}, capture_output=True, text=True,
                timeout=15, check=True,
            )
            self.assertEqual(event_from_output(completed.stdout)["event_type"],
                             "szl_mesh_state_transition")
            self.assertEqual(list(Path(directory).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
