import unittest

from egress_analyzer import (
    EgressRule,
    Request,
    analyze,
    find_shadowed_rules,
    host_matches,
    match_request,
    suggest_order,
)


def make_rules():
    return [
        EgressRule(name="wildcard-example", hosts=["*.example.com"],
                   ports=[443], protocol="HTTPS", tls_mode="PASSTHROUGH"),
        EgressRule(name="exact-api", hosts=["api.example.com"],
                   ports=[443], protocol="HTTPS", tls_mode="SIMPLE",
                   sni="api.example.com"),
        EgressRule(name="payments-8443", hosts=["pay.example.com"],
                   ports=[8443], protocol="TLS", tls_mode="MUTUAL",
                   source_workload={"team": "payments"}),
    ]


class HostMatchingTest(unittest.TestCase):
    def test_exact_match_is_case_insensitive(self):
        self.assertTrue(host_matches("api.example.com", "API.Example.COM"))
        self.assertTrue(host_matches("API.EXAMPLE.COM", "api.example.com"))

    def test_trailing_root_dot_is_ignored(self):
        self.assertTrue(host_matches("api.example.com.", "api.example.com"))

    def test_wildcard_matches_subdomains(self):
        self.assertTrue(host_matches("*.example.com", "api.example.com"))
        self.assertTrue(host_matches("*.example.com", "a.b.example.com"))

    def test_wildcard_does_not_match_apex_or_sibling(self):
        self.assertFalse(host_matches("*.example.com", "example.com"))
        self.assertFalse(host_matches("*.example.com", "example.org"))
        self.assertFalse(host_matches("*.example.com", "notexample.com"))


class RouteMatchingTest(unittest.TestCase):
    def setUp(self):
        self.rules = make_rules()

    def test_wildcard_shadows_exact_rule(self):
        # First-match-wins: the wildcard rule wins even for api.example.com.
        result = match_request(self.rules, Request(host="api.example.com"))
        self.assertEqual(result.rule.name, "wildcard-example")
        shadowed = find_shadowed_rules(self.rules)
        self.assertIn(("exact-api", "wildcard-example"), shadowed)

    def test_exact_rule_wins_after_reorder(self):
        ordered = suggest_order(self.rules)
        names = [r.name for r in ordered]
        self.assertLess(names.index("exact-api"), names.index("wildcard-example"))
        result = match_request(ordered, Request(host="api.example.com"))
        self.assertEqual(result.rule.name, "exact-api")

    def test_mixed_case_host_still_matches(self):
        result = match_request(self.rules, Request(host="API.EXAMPLE.COM"))
        self.assertIsNotNone(result.rule)

    def test_port_difference_changes_match(self):
        # pay.example.com:443 hits the wildcard; :8443 hits the payments rule.
        on_443 = match_request(self.rules, Request(
            host="pay.example.com", port=443, protocol="HTTPS",
            workload_labels={"team": "payments"}))
        self.assertEqual(on_443.rule.name, "wildcard-example")
        on_8443 = match_request(self.rules, Request(
            host="pay.example.com", port=8443, protocol="TLS",
            workload_labels={"team": "payments"}))
        self.assertEqual(on_8443.rule.name, "payments-8443")

    def test_wrong_workload_does_not_match_scoped_rule(self):
        result = match_request(self.rules, Request(
            host="pay.example.com", port=8443, protocol="TLS",
            workload_labels={"team": "other"}))
        self.assertNotEqual(result.rule.name if result.rule else None,
                            "payments-8443")

    def test_no_matching_route(self):
        result = match_request(self.rules, Request(host="unknown.other.com"))
        self.assertIsNone(result.rule)


class SniHostConflictTest(unittest.TestCase):
    def test_passthrough_conflict_prefers_sni(self):
        rules = [EgressRule(name="wild", hosts=["*.example.com"],
                            tls_mode="PASSTHROUGH")]
        result = match_request(rules, Request(
            host="a.example.com", sni="b.example.com"))
        self.assertIsNotNone(result.sni_host_conflict)
        self.assertEqual(result.effective_sni, "b.example.com")

    def test_origination_conflict_prefers_host(self):
        rules = [EgressRule(name="exact", hosts=["a.example.com"],
                            tls_mode="SIMPLE", sni="a.example.com")]
        result = match_request(rules, Request(
            host="a.example.com", sni="evil.example.com"))
        self.assertIsNotNone(result.sni_host_conflict)
        self.assertEqual(result.effective_sni, "a.example.com")

    def test_matching_sni_and_host_no_conflict(self):
        rules = [EgressRule(name="exact", hosts=["a.example.com"],
                            tls_mode="PASSTHROUGH")]
        result = match_request(rules, Request(
            host="A.example.com", sni="a.example.com"))
        self.assertIsNone(result.sni_host_conflict)


class AnalyzeReportTest(unittest.TestCase):
    def test_report_contains_all_sections(self):
        rules = make_rules()
        report = analyze(rules, [Request(host="api.example.com"),
                                 Request(host="nope.other.io")])
        self.assertEqual(len(report["matches"]), 2)
        self.assertTrue(report["shadowed"])
        self.assertIsInstance(report["sni_host_conflicts"], list)
        order = report["suggested_order"]
        self.assertLess(order.index("exact-api"), order.index("wildcard-example"))


if __name__ == "__main__":
    unittest.main()
