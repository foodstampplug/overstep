import json
import unittest

from overstep.capture import parse_har, parse_raw


class HarTest(unittest.TestCase):
    def test_parse_har_basic(self):
        doc = {
            "log": {
                "entries": [
                    {
                        "request": {
                            "method": "get",
                            "url": "https://api.target.com/orders/5",
                            "headers": [
                                {"name": "Cookie", "value": "session=ALICE"},
                                {"name": ":authority", "value": "api.target.com"},
                            ],
                        }
                    },
                    {
                        "request": {
                            "method": "POST",
                            "url": "https://api.target.com/orders",
                            "headers": [{"name": "Content-Type", "value": "application/json"}],
                            "postData": {"text": "{\"x\":1}"},
                        }
                    },
                ]
            }
        }
        reqs = parse_har(json.dumps(doc))
        self.assertEqual(len(reqs), 2)
        self.assertEqual(reqs[0].method, "GET")
        self.assertEqual(reqs[0].url, "https://api.target.com/orders/5")
        self.assertIn("Cookie", reqs[0].headers)
        # pseudo-headers (":authority") are dropped
        self.assertNotIn(":authority", reqs[0].headers)
        self.assertEqual(reqs[1].body, b'{"x":1}')


class RawTest(unittest.TestCase):
    def test_parse_raw_get(self):
        raw = "GET /orders/1 HTTP/1.1\nHost: api.target.com\nCookie: session=ALICE\n\n"
        reqs = parse_raw(raw)
        self.assertEqual(len(reqs), 1)
        self.assertEqual(reqs[0].method, "GET")
        self.assertEqual(reqs[0].url, "https://api.target.com/orders/1")
        self.assertEqual(reqs[0].headers.get("Cookie"), "session=ALICE")
        self.assertIsNone(reqs[0].body)

    def test_parse_raw_post_with_body(self):
        raw = (
            "POST /api/x HTTP/1.1\nHost: api.target.com\n"
            "Content-Type: application/json\n\n{\"a\":1}"
        )
        reqs = parse_raw(raw)
        self.assertEqual(reqs[0].method, "POST")
        self.assertEqual(reqs[0].body, b'{"a":1}')

    def test_parse_raw_scheme_override(self):
        raw = "GET /x HTTP/1.1\nHost: internal.local\n\n"
        reqs = parse_raw(raw, scheme="http")
        self.assertEqual(reqs[0].url, "http://internal.local/x")

    def test_parse_raw_multiple(self):
        raw = (
            "GET /a HTTP/1.1\nHost: t.com\n\n"
            "\n>>>>\n"
            "GET /b HTTP/1.1\nHost: t.com\n\n"
        )
        reqs = parse_raw(raw)
        self.assertEqual(len(reqs), 2)
        self.assertEqual(reqs[0].url, "https://t.com/a")
        self.assertEqual(reqs[1].url, "https://t.com/b")


if __name__ == "__main__":
    unittest.main()
