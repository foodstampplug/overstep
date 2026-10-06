import json
import unittest

from overstep import gui
from tests.mock_target import mock_target

IDENTS = json.dumps(
    {
        "identities": [
            {"name": "alice", "role": "owner", "headers": {"Cookie": "session=ALICE"}},
            {"name": "bob", "role": "peer", "headers": {"Cookie": "session=BOB"}},
            {"name": "anon", "role": "unauth", "headers": {}},
        ]
    }
)


class GuiRunTest(unittest.TestCase):
    def test_do_run_detects_bola(self):
        with mock_target() as base:
            host = base.split("//", 1)[1]  # 127.0.0.1:PORT
            reqs = f"GET /orders/1001 HTTP/1.1\nHost: {host}\nCookie: session=ALICE\n\n"
            res = gui._do_run(
                {"scope": "127.0.0.1", "identities": IDENTS, "requests": reqs,
                 "scheme": "http", "delay": 0}
            )
        self.assertGreaterEqual(res["counts"].get("BYPASSED", 0), 1)
        self.assertTrue(
            any("BOLA" in f["label"] for f in res["findings"] if f["verdict"] == "BYPASSED")
        )
        self.assertIn("markdown", res)
        self.assertIn("json", res)

    def test_do_run_requires_scope(self):
        with self.assertRaises(gui._RunError):
            gui._do_run({"scope": "", "identities": IDENTS, "requests": "x"})

    def test_do_run_rejects_bad_identities(self):
        with self.assertRaises(gui._RunError):
            gui._do_run(
                {"scope": "127.0.0.1", "identities": "{not valid json}",
                 "requests": "GET / HTTP/1.1\nHost: 127.0.0.1\n\n"}
            )

    def test_do_run_requires_requests(self):
        with self.assertRaises(gui._RunError):
            gui._do_run({"scope": "127.0.0.1", "identities": IDENTS, "requests": ""})

    def test_page_injects_token_and_version(self):
        page = gui._page("DEADBEEFCAFE")
        self.assertIn("DEADBEEFCAFE", page)
        self.assertNotIn("__OVERSTEP_TOKEN__", page)
        self.assertNotIn("__OVERSTEP_VERSION__", page)


if __name__ == "__main__":
    unittest.main()
