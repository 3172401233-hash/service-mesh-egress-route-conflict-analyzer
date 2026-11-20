"""Egress gateway route conflict analyzer (static configuration only).

Analyzes an ordered list of egress routing rules and computes, for each
candidate domain, which rule finally matches. Matching dimensions:

- FQDN / wildcard hosts (case-insensitive, ``*.example.com`` matches any
  subdomain but not the apex itself)
- SNI (TLS passthrough routes on SNI; TLS origination routes on Host)
- port
- protocol
- source workload labels
- TLS validation policy (DISABLE / PASSTHROUGH / SIMPLE / MUTUAL)

The first matching rule wins, so a broad wildcard rule placed before an
exact rule shadows the exact rule.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

TLS_MODES = ("DISABLE", "PASSTHROUGH", "SIMPLE", "MUTUAL")


def normalize_host(host):
    # FQDN matching is case-insensitive; strip a trailing root dot.
    return host.strip().lower().rstrip(".")


def host_matches(pattern, host):
    """True if a rule host pattern matches a concrete request host."""
    pattern = normalize_host(pattern)
    host = normalize_host(host)
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        return host.endswith(suffix) and host != pattern[2:]
    return pattern == host


def host_covers(pattern_a, pattern_b):
    """True if every host matched by pattern_b is also matched by pattern_a."""
    pattern_a = normalize_host(pattern_a)
    pattern_b = normalize_host(pattern_b)
    if pattern_a == pattern_b:
        return True
    if pattern_a.startswith("*."):
        suffix_a = pattern_a[1:]
        if pattern_b.startswith("*."):
            # "*.foo.example.com" is covered by "*.example.com"
            return pattern_b[1:].endswith(suffix_a)
        # exact host covered if it is a subdomain of the wildcard suffix
        return pattern_b.endswith(suffix_a) and pattern_b != pattern_a[2:]
    return False


def host_specificity(pattern):
    """Higher is more specific: exact hosts beat wildcards, longer beats shorter."""
    pattern = normalize_host(pattern)
    labels = len(pattern.split("."))
    return (1 if not pattern.startswith("*.") else 0, labels)


@dataclass
class EgressRule:
    name: str
    hosts: List[str]
    ports: Optional[List[int]] = None          # None = any port
    protocol: Optional[str] = None             # None = any protocol
    source_workload: Optional[Dict[str, str]] = None  # None = any workload
    tls_mode: str = "PASSTHROUGH"
    tls_validate: bool = True
    sni: Optional[str] = None                  # SNI sent upstream on origination

    def matches(self, request):
        if not any(host_matches(p, request.host) for p in self.hosts):
            return False
        if self.ports is not None and request.port not in self.ports:
            return False
        if self.protocol is not None and self.protocol != request.protocol:
            return False
        if self.source_workload is not None:
            for key, value in self.source_workload.items():
                if request.workload_labels.get(key) != value:
                    return False
        return True

    def covers(self, other):
        """True if this rule's match set is a superset of another rule's."""
        for host_b in other.hosts:
            if not any(host_covers(a, host_b) for a in self.hosts):
                return False
        if self.ports is not None:
            if other.ports is None:
                return False
            if not set(other.ports).issubset(set(self.ports)):
                return False
        if self.protocol is not None and self.protocol != other.protocol:
            return False
        if self.source_workload is not None:
            if other.source_workload is None:
                return False
            for key, value in self.source_workload.items():
                if other.source_workload.get(key) != value:
                    return False
        return True

    def specificity(self):
        host_spec = max(host_specificity(h) for h in self.hosts)
        port_spec = 1 if self.ports is not None else 0
        proto_spec = 1 if self.protocol is not None else 0
        workload_spec = len(self.source_workload or {})
        return (host_spec, port_spec, proto_spec, workload_spec)


@dataclass
class Request:
    host: str
    port: int = 443
    protocol: str = "HTTPS"
    sni: Optional[str] = None
    workload_labels: Dict[str, str] = field(default_factory=dict)


@dataclass
class MatchResult:
    request: Request
    rule: Optional[EgressRule]
    effective_sni: Optional[str]
    sni_host_conflict: Optional[str]


def effective_sni(rule, request):
    """Which name actually decides routing / is sent upstream."""
    if rule is None:
        return request.sni or normalize_host(request.host)
    if rule.tls_mode == "PASSTHROUGH":
        # Gateway routes on the client SNI; Host header is ignored.
        return request.sni or normalize_host(request.host)
    if rule.tls_mode in ("SIMPLE", "MUTUAL"):
        # Gateway terminates and re-originates TLS.
        return rule.sni or normalize_host(request.host)
    return None  # DISABLE: plain HTTP, no SNI involved


def detect_sni_host_conflict(rule, request):
    if request.sni is None:
        return None
    sni = normalize_host(request.sni)
    host = normalize_host(request.host)
    if sni == host:
        return None
    if rule is not None and rule.tls_mode == "PASSTHROUGH":
        return ("SNI '%s' != Host '%s': PASSTHROUGH routes on SNI, "
                "Host header is ignored" % (sni, host))
    if rule is not None and rule.tls_mode in ("SIMPLE", "MUTUAL"):
        return ("SNI '%s' != Host '%s': TLS origination routes on Host, "
                "upstream SNI is '%s'" % (sni, host, effective_sni(rule, request)))
    return "SNI '%s' != Host '%s'" % (sni, host)


def match_request(rules, request):
    for rule in rules:
        if rule.matches(request):
            return MatchResult(request, rule, effective_sni(rule, request),
                               detect_sni_host_conflict(rule, request))
    return MatchResult(request, None, request.sni or normalize_host(request.host),
                       detect_sni_host_conflict(None, request))


def find_shadowed_rules(rules):
    """Rules that can never match because an earlier rule covers them."""
    shadowed = []
    for i, rule in enumerate(rules):
        for earlier in rules[:i]:
            if earlier.covers(rule):
                shadowed.append((rule.name, earlier.name))
                break
    return shadowed


def suggest_order(rules):
    """Stable sort: most specific rules first, so exact FQDNs beat wildcards."""
    return sorted(rules, key=lambda r: r.specificity(), reverse=True)


def analyze(rules, requests):
    results = [match_request(rules, r) for r in requests]
    return {
        "matches": results,
        "shadowed": find_shadowed_rules(rules),
        "sni_host_conflicts": [r.sni_host_conflict for r in results
                               if r.sni_host_conflict],
        "suggested_order": [r.name for r in suggest_order(rules)],
    }


def _demo():
    rules = [
        EgressRule(name="wildcard-example", hosts=["*.example.com"],
                   ports=[443], protocol="HTTPS", tls_mode="PASSTHROUGH"),
        EgressRule(name="exact-api", hosts=["api.example.com"],
                   ports=[443], protocol="HTTPS", tls_mode="SIMPLE",
                   sni="api.example.com", tls_validate=True),
        EgressRule(name="payments-team", hosts=["pay.example.com"],
                   ports=[8443], protocol="TLS", tls_mode="MUTUAL",
                   source_workload={"team": "payments"}),
    ]
    requests = [
        Request(host="API.example.com", port=443, protocol="HTTPS",
                sni="api.example.com",
                workload_labels={"team": "payments"}),
        Request(host="pay.example.com", port=8443, protocol="TLS",
                sni="pay-internal.example.com",
                workload_labels={"team": "payments"}),
        Request(host="unknown.other.com", port=443, protocol="HTTPS"),
    ]
    report = analyze(rules, requests)
    print("== Final route per domain ==")
    for m in report["matches"]:
        rule = m.rule.name if m.rule else "<no match>"
        print("  %s:%s -> %s (effective SNI: %s)"
              % (m.request.host, m.request.port, rule, m.effective_sni))
    print("== Shadowed rules ==")
    for shadowed, by in report["shadowed"]:
        print("  '%s' is shadowed by '%s'" % (shadowed, by))
    print("== SNI / Host conflicts ==")
    for conflict in report["sni_host_conflicts"]:
        print("  " + conflict)
    print("== Suggested order ==")
    print("  " + " -> ".join(report["suggested_order"]))


if __name__ == "__main__":
    _demo()
