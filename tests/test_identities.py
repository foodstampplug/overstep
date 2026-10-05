import json
import unittest

from overstep.identities import IdentityError, IdentitySet, template


def base(idents):
    return {"identities": idents}


class IdentitiesTest(unittest.TestCase):
    def test_load_and_roles(self):
        s = IdentitySet.from_dict(
            base(
                [
                    {"name": "alice", "role": "owner", "headers": {"Cookie": "s=A"}},
                    {"name": "bob", "role": "peer", "headers": {"Cookie": "s=B"}},
                    {"name": "anon", "role": "unauth", "headers": {}},
                ]
            )
        )
        self.assertEqual(s.owner().name, "alice")
        self.assertEqual({c.name for c in s.candidates()}, {"bob", "anon"})

    def test_template_is_valid_and_has_single_owner(self):
        doc = json.loads(template())
        s = IdentitySet.from_dict(doc)
        self.assertEqual(s.owner().role, "owner")

    def test_requires_exactly_one_owner(self):
        with self.assertRaises(IdentityError):
            IdentitySet.from_dict(base([{"name": "a", "role": "peer", "headers": {}}]))
        with self.assertRaises(IdentityError):
            IdentitySet.from_dict(
                base(
                    [
                        {"name": "a", "role": "owner", "headers": {}},
                        {"name": "b", "role": "owner", "headers": {}},
                    ]
                )
            )

    def test_unique_names(self):
        with self.assertRaises(IdentityError):
            IdentitySet.from_dict(
                base(
                    [
                        {"name": "dup", "role": "owner", "headers": {}},
                        {"name": "dup", "role": "peer", "headers": {}},
                    ]
                )
            )

    def test_bad_role_rejected(self):
        with self.assertRaises(IdentityError):
            IdentitySet.from_dict(base([{"name": "a", "role": "admin", "headers": {}}]))


if __name__ == "__main__":
    unittest.main()
