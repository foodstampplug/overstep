import unittest

from overstep.diff import (
    BYPASSED,
    ENFORCED,
    OWNER_FAILED,
    UNCLEAR,
    classify,
    length_ratio,
    similarity,
)
from overstep.http import Response


def resp(status, body=b"", headers=None):
    return Response(status=status, body=body, headers=headers or {})


class HelpersTest(unittest.TestCase):
    def test_similarity_identical(self):
        self.assertEqual(similarity("abc", "abc"), 1.0)

    def test_similarity_disjoint(self):
        self.assertEqual(similarity("A" * 50, "B" * 50), 0.0)

    def test_length_ratio(self):
        self.assertEqual(length_ratio(100, 100), 1.0)
        self.assertEqual(length_ratio(50, 100), 0.5)
        self.assertEqual(length_ratio(0, 0), 1.0)


class ClassifyTest(unittest.TestCase):
    def test_bypassed_same_success(self):
        owner = resp(200, b"account 1001 balance $500 name Alice")
        cand = resp(200, b"account 1001 balance $500 name Alice")
        self.assertEqual(classify(owner, cand).verdict, BYPASSED)

    def test_enforced_403(self):
        owner = resp(200, b"secret data")
        cand = resp(403, b"forbidden")
        self.assertEqual(classify(owner, cand).verdict, ENFORCED)

    def test_enforced_login_redirect(self):
        owner = resp(200, b"secret data")
        cand = resp(302, b"", headers={"location": "https://x/login?next=/a"})
        self.assertEqual(classify(owner, cand).verdict, ENFORCED)

    def test_enforced_different_content(self):
        owner = resp(200, b"A" * 100)
        cand = resp(200, b"B" * 100)
        self.assertEqual(classify(owner, cand).verdict, ENFORCED)

    def test_unclear_partial_similarity(self):
        owner = resp(200, b"A" * 100)
        cand = resp(200, b"A" * 70 + b"B" * 30)  # ~0.70 similar
        self.assertEqual(classify(owner, cand).verdict, UNCLEAR)

    def test_owner_failed_when_baseline_not_success(self):
        owner = resp(403, b"forbidden")
        cand = resp(200, b"anything")
        self.assertEqual(classify(owner, cand).verdict, OWNER_FAILED)

    def test_owner_transport_error_is_owner_failed(self):
        owner = Response(error="ConnectionError: boom")
        cand = resp(200, b"x")
        self.assertEqual(classify(owner, cand).verdict, OWNER_FAILED)


if __name__ == "__main__":
    unittest.main()
