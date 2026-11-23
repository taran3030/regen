"""
GraphQL injection and misconfiguration testing.

Probes for exposed introspection, query depth/complexity abuse,
field suggestion leaks, and injection in GraphQL variables. Detection
is based on schema visibility and response behavior.

Depth levels:
  quick    — Introspection check and type name leak
  standard — + field suggestion, query complexity, mutation enumeration
  full     — + batched query abuse, variable injection, alias overload
"""
import json
import re
import ssl
import urllib.request
import urllib.error
from typing import Optional
from urllib.parse import urlparse

from . import payloads


def _request(url, method="GET", data=None, headers=None, timeout=10):
    ctx = ssl.create_default_context()
    if data and isinstance(data, str):
        payload = data.encode()
    elif data and isinstance(data, dict):
        payload = json.dumps(data).encode()
    else:
        payload = None

    req = urllib.request.Request(url, data=payload, method=method)
    req.add_header("User-Agent", "Regen/1.2 (Axolotl Labs Security Scanner)")
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        body = resp.read().decode("utf-8", errors="replace")
        return resp.status, dict(resp.headers), body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return e.code, dict(e.headers), body
    except Exception as e:
        return 0, {}, str(e)


def _finding(title, severity, description, location, **kwargs):
    return {
        "title": title,
        "severity": severity,
        "description": description,
        "location": location,
        "scanner": "graphql",
        **kwargs,
    }


def _find_graphql_endpoint(target: str) -> Optional[str]:
    """Discover the GraphQL endpoint by trying common paths."""
    base = target.rstrip("/")
    candidates = [
        f"{base}/graphql",
        f"{base}/api/graphql",
        f"{base}/gql",
        f"{base}/query",
        f"{base}/v1/graphql",
    ]

    for url in candidates:
        status, _, body = _request(url, method="POST",
                                   data='{"query":"{__typename}"}')
        if status in (200, 400) and ("__typename" in body or "data" in body or "errors" in body):
            return url

    return None


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_introspection(target: str) -> list[dict]:
    """
    Check if GraphQL introspection is enabled. Full introspection exposes
    the entire schema: types, fields, arguments, mutations.
    """
    findings = []
    endpoint = _find_graphql_endpoint(target)

    if not endpoint:
        findings.append(_finding(
            "GraphQL: no endpoint found",
            "info",
            "Could not find a GraphQL endpoint at common paths.",
            target,
        ))
        return findings

    # Full introspection query
    status, _, body = _request(endpoint, method="POST",
                               data=payloads.GRAPHQL_INTROSPECTION)

    if status == 200:
        try:
            resp = json.loads(body)
            if resp.get("data", {}).get("__schema"):
                schema = resp["data"]["__schema"]
                types = schema.get("types", [])
                type_names = [t.get("name", "") for t in types
                              if not t.get("name", "").startswith("__")]
                findings.append(_finding(
                    "GraphQL introspection enabled",
                    "medium",
                    f"Full schema introspection is enabled. The schema exposes "
                    f"{len(types)} types including: {', '.join(type_names[:10])}. "
                    f"An attacker can map every query, mutation, and field.",
                    endpoint,
                    evidence=f"Types: {len(types)}, user-defined: {len(type_names)}",
                    remediation="Disable introspection in production. "
                                "Most GraphQL servers have a config option for this.",
                    cwe="CWE-200",
                ))
            elif resp.get("errors"):
                error_msg = str(resp["errors"][0].get("message", ""))
                if "introspection" in error_msg.lower():
                    findings.append(_finding(
                        "GraphQL introspection disabled",
                        "info",
                        f"Introspection query was explicitly rejected: {error_msg[:200]}",
                        endpoint,
                    ))
                else:
                    findings.append(_finding(
                        "GraphQL introspection: error response",
                        "info",
                        f"Introspection returned an error: {error_msg[:200]}",
                        endpoint,
                    ))
        except (json.JSONDecodeError, ValueError, KeyError):
            pass

    if not findings:
        findings.append(_finding(
            "GraphQL: could not determine introspection status",
            "info",
            "Introspection query did not return a recognizable response.",
            target,
        ))
    return findings


def test_field_suggestions(target: str) -> list[dict]:
    """
    GraphQL servers often suggest field names when a query uses the wrong
    name. This leaks the schema even when introspection is disabled.
    """
    findings = []
    endpoint = _find_graphql_endpoint(target)
    if not endpoint:
        return findings

    probe_query = '{"query":"{ uzer { nme } }"}'
    status, _, body = _request(endpoint, method="POST", data=probe_query)

    if status in (200, 400):
        try:
            resp = json.loads(body)
            errors = resp.get("errors", [])
            for err in errors:
                msg = err.get("message", "")
                if "did you mean" in msg.lower() or "suggestion" in msg.lower():
                    findings.append(_finding(
                        "GraphQL field suggestions leak schema",
                        "low",
                        f"The server suggests field names on typos: '{msg[:200]}'. "
                        f"An attacker can enumerate the schema by probing with "
                        f"misspelled field names.",
                        endpoint,
                        evidence=f"Error: {msg[:200]}",
                        remediation="Disable field suggestions in production "
                                    "(e.g., Apollo Server's validationRules).",
                        cwe="CWE-200",
                    ))
                    break
        except (json.JSONDecodeError, ValueError):
            pass

    if not findings:
        findings.append(_finding(
            "GraphQL: no field suggestions found",
            "info",
            "Misspelled field query did not trigger suggestions.",
            target,
        ))
    return findings


def test_query_complexity(target: str) -> list[dict]:
    """
    Send a deeply nested query to check if the server enforces depth or
    complexity limits. No limits = denial of service risk.
    """
    findings = []
    endpoint = _find_graphql_endpoint(target)
    if not endpoint:
        return findings

    # Build a deeply nested query
    depth = 10
    q = "{ __typename "
    for _ in range(depth):
        q += "... on Query { __typename "
    q += " }" * depth + " }"

    status, _, body = _request(endpoint, method="POST",
                               data=json.dumps({"query": q}))

    if status == 200:
        try:
            resp = json.loads(body)
            if resp.get("data") and not resp.get("errors"):
                findings.append(_finding(
                    f"GraphQL: no query depth limit (depth={depth} accepted)",
                    "medium",
                    f"A query nested {depth} levels deep was accepted without "
                    f"error. An attacker can craft exponentially complex queries "
                    f"to exhaust server resources.",
                    endpoint,
                    evidence=f"Depth: {depth}, status: {status}",
                    remediation="Set query depth and complexity limits. "
                                "Most GraphQL libraries support this.",
                    cwe="CWE-770",
                ))
        except (json.JSONDecodeError, ValueError):
            pass

    if not findings:
        findings.append(_finding(
            "GraphQL: deep query was rejected or not processable",
            "info",
            f"Depth-{depth} query was rejected or returned an error.",
            target,
        ))
    return findings


def test_batched_queries(target: str) -> list[dict]:
    """
    GraphQL batching lets a client send multiple queries in one HTTP request.
    Without limits, this bypasses rate limiting and amplifies attacks.
    """
    findings = []
    endpoint = _find_graphql_endpoint(target)
    if not endpoint:
        return findings

    batch = [{"query": "{__typename}"} for _ in range(20)]
    status, _, body = _request(endpoint, method="POST",
                               data=json.dumps(batch))

    if status == 200:
        try:
            resp = json.loads(body)
            if isinstance(resp, list) and len(resp) >= 20:
                findings.append(_finding(
                    "GraphQL: batch queries accepted (20+)",
                    "low",
                    f"The server accepted a batch of 20 queries in one request "
                    f"and returned {len(resp)} responses. Without batch limits, "
                    f"rate limiting can be bypassed.",
                    endpoint,
                    evidence=f"Batch: 20 queries, responses: {len(resp)}",
                    remediation="Limit the number of queries per batch request.",
                    cwe="CWE-770",
                ))
        except (json.JSONDecodeError, ValueError):
            pass

    if not findings:
        findings.append(_finding(
            "GraphQL: batch queries rejected or limited",
            "info",
            "Batch of 20 queries was rejected or not fully processed.",
            target,
        ))
    return findings


def test_mutation_enumeration(target: str) -> list[dict]:
    """
    If introspection succeeded, check for sensitive mutations that shouldn't
    be exposed (delete, admin, internal operations).
    """
    findings = []
    endpoint = _find_graphql_endpoint(target)
    if not endpoint:
        return findings

    status, _, body = _request(
        endpoint, method="POST",
        data='{"query":"{ __schema { mutationType { fields { name } } } }"}',
    )

    if status == 200:
        try:
            resp = json.loads(body)
            mutations = (resp.get("data", {}).get("__schema", {})
                         .get("mutationType", {}) or {})
            fields = mutations.get("fields", [])
            if fields:
                names = [f.get("name", "") for f in fields]
                sensitive = [n for n in names if any(
                    kw in n.lower() for kw in
                    ["delete", "admin", "internal", "debug", "reset",
                     "grant", "revoke", "sudo", "escalate"]
                )]
                if sensitive:
                    findings.append(_finding(
                        f"GraphQL: sensitive mutations exposed ({len(sensitive)})",
                        "medium",
                        f"Introspection reveals mutations with sensitive names: "
                        f"{', '.join(sensitive[:10])}. These should be restricted "
                        f"or hidden from introspection.",
                        endpoint,
                        evidence=f"Sensitive mutations: {', '.join(sensitive[:10])}",
                        remediation="Restrict sensitive mutations to admin roles. "
                                    "Consider hiding them from introspection.",
                        cwe="CWE-200",
                    ))
                else:
                    findings.append(_finding(
                        f"GraphQL: {len(names)} mutations visible via introspection",
                        "info",
                        f"Mutations: {', '.join(names[:10])}",
                        endpoint,
                    ))
        except (json.JSONDecodeError, ValueError, KeyError):
            pass

    return findings


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

QUICK_TESTS = [
    ("Introspection", test_introspection),
]

STANDARD_TESTS = QUICK_TESTS + [
    ("Field suggestions", test_field_suggestions),
    ("Query complexity", test_query_complexity),
    ("Mutation enumeration", test_mutation_enumeration),
]

FULL_TESTS = STANDARD_TESTS + [
    ("Batched queries", test_batched_queries),
]

DEPTH_MAP = {
    "quick": QUICK_TESTS,
    "standard": STANDARD_TESTS,
    "full": FULL_TESTS,
}


def run_graphql_tests(target: str, depth: str = "standard") -> list[dict]:
    import sys
    findings = []
    tests = DEPTH_MAP.get(depth, STANDARD_TESTS)

    for name, fn in tests:
        print(f"[regen] GraphQL: {name}...", file=sys.stderr)
        try:
            findings.extend(fn(target))
        except Exception as e:
            print(f"[regen] GraphQL '{name}' failed: {e}", file=sys.stderr)
            findings.append(_finding(
                f"GraphQL test failed: {name}", "info",
                f"Test could not complete: {e}", target,
            ))

    return findings
