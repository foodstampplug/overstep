import json
import unittest

from overstep import report
from overstep.capture import CapturedRequest
from overstep.diff import BYPASSED, ENFORCED
from overstep.identities import IdentitySet
from overstep.replay import run as replay_run
from overstep.scope import Scope
from tests.mock_target import mock_target

IDENTS = {
    "identities": [
        {"name": "alice", "role": "owner", "headers": {"Cookie": "session=ALICE"}},
        {"name": "bob", "role": "peer", "headers": {"Cookie": "session=BOB"}},
        {"name": "low", "role": "lowpriv", "headers": {"Cookie": "session=LOW"}},
        {"name": "anon", "role": "unauth", "headers": {}},
    ]
}


def verdict_for(run, path_substr, identity):
    for f in run.findings:
        if path_substr in f.request_label and f.identity_name == identity:
            return f
    return None


class EndToEndTest(unittest.TestCase):
    def _run(self, base):
        reqs = [
            CapturedRequest("GET", f"{base}/orders/1001", {"Cookie": "session=ALICE"}),
            CapturedRequest("GET", f"{base}/admin/report", {"Cookie": "session=ALICE"}),
            CapturedRequest("GET", f"{base}/my/settings", {"Cookie": "session=ALICE"}),
            CapturedRequest("GET", f"{base}/public/status", {"Cookie": "session=ALICE"}),
            CapturedRequest("POST", f"{base}/orders/1001", {"Cookie": "session=ALICE"}),
            CapturedRequest("GET", "https://evil.example/x", {}),  # out of scope
        ]
        idset = IdentitySet.from_dict(IDENTS)
        scope = Scope.from_lines(["127.0.0.1"])
        return replay_run(reqs, idset, scope, delay=0.0, version="test")

    def test_full_matrix(self):
        with mock_target() as base:
            run = self._run(base)

        # BOLA: a peer and a low-priv user both read the owner's order
        self.assertEqual(verdict_for(run, "/orders/1001", "bob").verdict, BYPASSED)
        self.assertIn("BOLA", verdict_for(run, "/orders/1001", "bob").label)
        self.assertEqual(verdict_for(run, "/orders/1001", "low").verdict, BYPASSED)
        # ...but an unauthenticated user is blocked
        self.assertEqual(verdict_for(run, "/orders/1001", "anon").verdict, ENFORCED)

        # Privilege escalation: low-priv reaches an admin function; peer is blocked
        self.assertEqual(verdict_for(run, "/admin/report", "low").verdict, BYPASSED)
        self.assertIn("Privilege", verdict_for(run, "/admin/report", "low").label)
        self.assertEqual(verdict_for(run, "/admin/report", "bob").verdict, ENFORCED)
        self.assertEqual(verdict_for(run, "/admin/report", "anon").verdict, ENFORCED)

        # Properly scoped per-user data: nobody is flagged
        self.assertEqual(verdict_for(run, "/my/settings", "bob").verdict, ENFORCED)
        self.assertEqual(verdict_for(run, "/my/settings", "anon").verdict, ENFORCED)

        # Public endpoint: unauth gets 200 → flagged as missing authentication
        self.assertEqual(verdict_for(run, "/public/status", "anon").verdict, BYPASSED)
        self.assertIn("Missing authentication", verdict_for(run, "/public/status", "anon").label)

    def test_writes_skipped_by_default(self):
        with mock_target() as base:
            run = self._run(base)
        self.assertTrue(any("POST /orders/1001" in s.request_label for s in run.skipped))
        # no finding should exist for the POST
        self.assertFalse(any(f.method == "POST" for f in run.findings))

    def test_out_of_scope_request_skipped_not_sent(self):
        with mock_target() as base:
            run = self._run(base)
        self.assertTrue(any("evil.example" in s.url for s in run.skipped))

    def test_json_report_parses(self):
        with mock_target() as base:
            run = self._run(base)
        doc = json.loads(report.to_json(run))
        self.assertEqual(doc["tool"], "overstep")
        self.assertTrue(len(doc["findings"]) >= 3)

    def test_markdown_report_has_findings(self):
        with mock_target() as base:
            run = self._run(base)
        md = report.to_markdown(run)
        self.assertIn("BOLA", md)
        self.assertIn("Privilege escalation", md)


if __name__ == "__main__":
    unittest.main()
