import unittest

from overstep.scope import OutOfScope, Scope


class ScopeTest(unittest.TestCase):
    def test_exact_host(self):
        s = Scope.from_lines(["api.target.com"])
        self.assertTrue(s.contains("https://api.target.com/x"))
        self.assertFalse(s.contains("https://www.target.com/x"))

    def test_wildcard_includes_base_and_subs(self):
        s = Scope.from_lines(["*.target.com"])
        self.assertTrue(s.contains("https://target.com/"))
        self.assertTrue(s.contains("https://api.target.com/"))
        self.assertTrue(s.contains("https://a.b.target.com/"))
        self.assertFalse(s.contains("https://target.com.evil.com/"))

    def test_parser_differential_blocked(self):
        s = Scope.from_lines(["*.target.com"])
        # host is evil.com, not target.com — must not be fooled by the path
        self.assertFalse(s.contains("https://evil.com/.target.com"))

    def test_exclusion_always_wins(self):
        s = Scope.from_lines(["*.target.com", "!admin.target.com"])
        self.assertTrue(s.contains("https://api.target.com/"))
        self.assertFalse(s.contains("https://admin.target.com/"))

    def test_cidr_matches_literal_ip(self):
        s = Scope.from_lines(["10.0.0.0/8"])
        self.assertTrue(s.contains("http://10.1.2.3/"))
        self.assertFalse(s.contains("http://11.0.0.1/"))

    def test_authorize_raises_out_of_scope(self):
        s = Scope.from_lines(["api.target.com"])
        with self.assertRaises(OutOfScope):
            s.authorize("https://not-in-scope.com/")

    def test_empty_host_not_in_scope(self):
        s = Scope.from_lines(["api.target.com"])
        self.assertFalse(s.contains("not a url"))


if __name__ == "__main__":
    unittest.main()
