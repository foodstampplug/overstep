import unittest

from overstep.capture import CapturedRequest
from overstep.enumerate import EnumError, enumerate_ids, expand_ids
from overstep.identities import IdentitySet
from overstep.scope import Scope
from tests.mock_target import mock_target

IDSET = IdentitySet.from_dict(
    {
        "identities": [
            {"name": "alice", "role": "owner", "headers": {"Cookie": "session=ALICE"}},
            {"name": "bob", "role": "peer", "headers": {"Cookie": "session=BOB"}},
        ]
    }
)


class ExpandTest(unittest.TestCase):
    def test_range(self):
        self.assertEqual(expand_ids("1000-1003"), ["1000", "1001", "1002", "1003"])

    def test_range_with_step(self):
        self.assertEqual(expand_ids("0-10:5"), ["0", "5", "10"])

    def test_csv_and_dedupe(self):
        self.assertEqual(expand_ids(None, "7,8,7,9"), ["7", "8", "9"])

    def test_cap_enforced(self):
        with self.assertRaises(EnumError):
            expand_ids("1-300", cap=200)

    def test_empty_raises(self):
        with self.assertRaises(EnumError):
            expand_ids(None, None, None)


class EnumerateTest(unittest.TestCase):
    def test_mass_bola_detected(self):
        bob = next(i for i in IDSET.identities if i.name == "bob")
        with mock_target() as base_url:
            base = CapturedRequest("GET", f"{base_url}/api/record/§ID§", {}, None)
            scope = Scope.from_lines(["127.0.0.1"])
            ids = expand_ids("1-60")
            result = enumerate_ids(base, bob, IDSET.auth_headers, scope, ids, delay=0.0)
        self.assertEqual(result.n_hit, 50)          # records 1..50 exist
        self.assertEqual(result.n_miss, 10)         # 51..60 → 404
        self.assertEqual(result.distinct, 50)       # every record body differs
        self.assertTrue(result.mass_bola)
        self.assertEqual(result.hit_ids()[0], "1")

    def test_marker_missing_raises(self):
        bob = next(i for i in IDSET.identities if i.name == "bob")
        base = CapturedRequest("GET", "https://api.target.com/orders/5", {}, None)
        scope = Scope.from_lines(["*.target.com"])
        with self.assertRaises(EnumError):
            enumerate_ids(base, bob, IDSET.auth_headers, scope, ["1"], delay=0.0)


if __name__ == "__main__":
    unittest.main()
