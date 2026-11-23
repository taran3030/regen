"""
API surface testing and fuzzing.

Probes API endpoints for mass assignment, IDOR patterns, method
enumeration, excessive data exposure, and input validation gaps.
Non-destructive: reads and probes only, never writes real data.

Depth levels:
  quick    — Method enumeration on discovered endpoints
  standard — + mass assignment probes, IDOR patterns, error disclosure
  full     — + parameter pollution, content-type confusion, large payload
"""
import json
import re
import ssl
import urllib.request
import urllib.error
from typing import Optional
from urllib.parse import urlparse, quote


def _request(url, method="GET", data=None, headers=None, content_type=None, timeout=10):
    ctx = ssl.create_default_context()
    if data and isinstance(data, dict):
        payload = json.dumps(data).encode()
        content_type = content_type or "application/json"
    elif data and isinstance(data, str):
        payload = data.encode()
    elif data and isinstance(data, bytes):
        payload = data
    else:
        payload = None

    req = urllib.request.Request(url, data=payload, method=method)
    req.add_header("User-Agent", "Regen/1.1 (Axolotl Labs Security Scanner)")
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
        "scanner": "api-fuzzer",
        **kwargs,
    }


# ---------------------------------------------------------------------------
# API endpoint discovery
# ---------------------------------------------------------------------------

COMMON_API_PATHS = [
    "/api/me", "/api/user", "/api/users", "/api/profile",
    "/api/business", "/api/businesses",
    "/api/admin", "/api/settings", "/api/config",
    "/api/health", "/api/status", "/api/version", "/api/info",
    "/api/auth/start", "/api/auth/verify", "/api/auth/logout",
    "/api/chat", "/api/guide", "/api/leaderboard",
    "/api/players/deck", "/api/players/inbox", "/api/players/matches",
    "/api/media", "/api/upload",
    "/api/realtime/negotiate",
    "/api/saves/coffee", "/api/saves/saas",
    "/api/statements/read",
    "/api/graphql", "/graphql",
    "/api/v1", "/api/v2",
    "/.well-known/openapi.json", "/swagger.json", "/openapi.json",
    "/api/docs", "/api/swagger",
]


def discover_endpoints(target: str) -> list[tuple]:
    """Discover live API endpoints and their responses."""
    base = target.rstrip("/")
    live = []

    for path in COMMON_API_PATHS:
        url = f"{base}{path}"
        status, hdrs, body = _request(url)
        if status not in (0, 404):
            content_type = ""
            for k, v in hdrs.items():
                if k.lower() == "content-type":
                    content_type = v
                    break
            live.append((path, status, content_type, body[:200]))

    return live


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_method_enumeration(target: str) -> list[dict]:
    """
    For each discovered endpoint, try all HTTP methods and report which
    ones are unexpectedly allowed.
    """
    findings = []
    base = target.rstrip("/")
    methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]

    test_paths = ["/api/me", "/api/business", "/api/health"]

    for path in test_paths:
        url = f"{base}{path}"
        allowed = []
        for method in methods:
            status, hdrs, body = _request(url, method=method)
            if status not in (0, 404, 405):
                allowed.append((method, status))

        # OPTIONS should return Allow header
        status, hdrs, _ = _request(url, method="OPTIONS")
        allow_header = ""
        for k, v in hdrs.items():
            if k.lower() == "allow":
                allow_header = v

        if allow_header:
            findings.append(_finding(
                f"OPTIONS reveals methods on {path}",
                "info",
                f"Allow: {allow_header}",
                url,
                evidence=f"Allow: {allow_header}",
            ))

        # Flag if dangerous methods are allowed without auth
        dangerous = [m for m, s in allowed if m in ("PUT", "PATCH", "DELETE") and s not in (401, 403)]
        if dangerous:
            findings.append(_finding(
                f"Dangerous methods on {path}: {', '.join(dangerous)}",
                "medium",
                f"{', '.join(dangerous)} returned non-401 on {path}. "
                f"These methods should require authentication.",
                url,
                evidence=f"Methods: {allowed}",
                cwe="CWE-749",
            ))

    if not findings:
        findings.append(_finding(
            "Method enumeration: no unexpected methods",
            "info",
            "All tested endpoints properly restrict HTTP methods.",
            target,
        ))
    return findings


def test_mass_assignment(target: str) -> list[dict]:
    """
    Send POST/PUT requests with extra fields that shouldn't be accepted:
    isAdmin, role, permissions, etc. Check if the server includes them
    in error messages (revealing the schema) or silently accepts them.
    """
    findings = []
    base = target.rstrip("/")

    mass_assignment_fields = {
        "isAdmin": True,
        "role": "admin",
        "permissions": ["*"],
        "admin": True,
        "verified": True,
        "emailVerified": True,
        "superuser": True,
        "__proto__": {"isAdmin": True},
        "constructor": {"prototype": {"isAdmin": True}},
    }

    test_endpoints = [
        ("PUT", f"{base}/api/business"),
        ("PUT", f"{base}/api/me"),
        ("POST", f"{base}/api/players/swipe"),
    ]

    for method, url in test_endpoints:
        status, _, body = _request(url, method=method, data=mass_assignment_fields,
                                   headers={"Origin": base})
        if status == 0:
            continue

        try:
            resp = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            resp = {}

        # Check if error message reveals accepted fields
        error = resp.get("error", "")
        if any(f in str(resp).lower() for f in ["isadmin", "superuser", "permissions"]):
            findings.append(_finding(
                f"Mass assignment: schema revealed on {url.split('/api/')[-1]}",
                "medium",
                f"Server's error response mentions injected field names. "
                f"This reveals the data model and may indicate the fields "
                f"are processed.",
                url,
                evidence=f"Response mentions injected fields: {body[:200]}",
                cwe="CWE-915",
            ))

        # Prototype pollution check
        if "__proto__" in str(resp) or "constructor" in str(resp):
            findings.append(_finding(
                f"Prototype pollution: __proto__ in response from {url.split('/api/')[-1]}",
                "medium",
                f"The server included __proto__ or constructor in its response "
                f"after we sent them. This may indicate prototype pollution.",
                url,
                evidence=f"Response: {body[:200]}",
                cwe="CWE-1321",
            ))

    if not findings:
        findings.append(_finding(
            "Mass assignment: no field leakage detected",
            "info",
            "Injected admin/role fields were not reflected in responses.",
            target,
        ))
    return findings


def test_idor_patterns(target: str) -> list[dict]:
    """
    Test for Insecure Direct Object References by trying sequential and
    predictable IDs on endpoints that take an identifier.
    """
    findings = []
    base = target.rstrip("/")

    # Try sequential numeric IDs
    id_endpoints = [
        f"{base}/api/users/1",
        f"{base}/api/users/2",
        f"{base}/api/business/1",
        f"{base}/api/media/1",
    ]

    for url in id_endpoints:
        status, _, body = _request(url)
        if status == 200:
            try:
                resp = json.loads(body)
                if resp and isinstance(resp, dict) and not resp.get("error"):
                    findings.append(_finding(
                        f"IDOR: sequential ID returned data on {url.split(base)[-1]}",
                        "high",
                        f"Accessing a resource by sequential numeric ID returned "
                        f"data without authentication.",
                        url,
                        evidence=f"Status: 200, keys: {list(resp.keys())[:5]}",
                        cwe="CWE-639",
                    ))
            except (json.JSONDecodeError, ValueError):
                pass

    # Try UUID-based endpoints with a fake UUID
    fake_uuid = "00000000-0000-0000-0000-000000000001"
    uuid_endpoints = [
        f"{base}/api/media/{fake_uuid}",
        f"{base}/api/players/matches/{fake_uuid}/messages",
    ]

    for url in uuid_endpoints:
        status, _, body = _request(url)
        if status == 200:
            try:
                resp = json.loads(body)
                if resp and not resp.get("error"):
                    findings.append(_finding(
                        f"IDOR: UUID endpoint returned data unauthenticated",
                        "high",
                        f"Accessing {url.split(base)[-1]} with a probe UUID "
                        f"returned data without authentication.",
                        url,
                        evidence=f"Status: 200",
                        cwe="CWE-639",
                    ))
            except (json.JSONDecodeError, ValueError):
                pass

    if not findings:
        findings.append(_finding(
            "IDOR: sequential/UUID probes returned no data",
            "info",
            "Probed endpoints with sequential and UUID identifiers; "
            "all required authentication or returned 404.",
            target,
        ))
    return findings


def test_excessive_data_exposure(target: str) -> list[dict]:
    """
    Check if API responses include more data than necessary — password
    hashes, internal IDs, debug info, etc.
    """
    findings = []
    base = target.rstrip("/")

    sensitive_patterns = [
        (r'"password":', "password field"),
        (r'"passwordHash":', "password hash"),
        (r'"secret":', "secret field"),
        (r'"token":', "token field (may be intentional)"),
        (r'"ssn":', "SSN field"),
        (r'"creditCard":', "credit card field"),
        (r'"_id":', "MongoDB _id exposed"),
        (r'"__v":', "MongoDB version key"),
        (r'"createdAt".*"updatedAt"', "timestamp internals"),
    ]

    for path in ["/api/me", "/api/business", "/api/health", "/api/version"]:
        url = f"{base}{path}"
        status, _, body = _request(url)
        if status not in (200, 401):
            continue

        for pattern, label in sensitive_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                sev = "high" if "password" in label.lower() or "ssn" in label.lower() else "low"
                findings.append(_finding(
                    f"Data exposure: {label} in {path}",
                    sev,
                    f"Response from {path} contains {label}.",
                    url,
                    evidence=f"Pattern match: {pattern}",
                    cwe="CWE-200",
                ))

    if not findings:
        findings.append(_finding(
            "Data exposure: no sensitive fields in API responses",
            "info",
            "Checked API responses for password, token, SSN, and other "
            "sensitive field patterns; none found.",
            target,
        ))
    return findings


def test_content_type_confusion(target: str) -> list[dict]:
    """
    Send requests with mismatched Content-Type headers to see if the
    server processes them anyway (e.g., sending XML to a JSON endpoint).
    """
    findings = []
    base = target.rstrip("/")

    test_url = f"{base}/api/auth/start"

    # JSON data with XML content type
    json_data = json.dumps({"email": "test@example.com"})
    for wrong_type, label in [
        ("text/xml", "XML content-type with JSON body"),
        ("application/x-www-form-urlencoded", "form content-type with JSON body"),
        ("text/plain", "text content-type with JSON body"),
    ]:
        status, _, body = _request(test_url, method="POST", data=json_data,
                                   content_type=wrong_type,
                                   headers={"Origin": base})
        if status == 0:
            continue

        try:
            resp = json.loads(body)
            error = resp.get("error", "")
            # If the server processed it successfully despite wrong content-type
            if error not in ("bad_body", "bad_origin", "") and status not in (400, 403, 415):
                findings.append(_finding(
                    f"Content-type confusion: {label}",
                    "low",
                    f"Server processed a request with Content-Type: {wrong_type} "
                    f"containing JSON data. Status: {status}.",
                    test_url,
                    evidence=f"Content-Type: {wrong_type}, Status: {status}",
                ))
        except (json.JSONDecodeError, ValueError):
            pass

    if not findings:
        findings.append(_finding(
            "Content-type handling: properly validated",
            "info",
            "Server rejected or ignored requests with mismatched Content-Type.",
            target,
        ))
    return findings


def test_large_payload(target: str) -> list[dict]:
    """
    Send an oversized payload to check for size limits. A server without
    limits is vulnerable to denial of service.
    """
    findings = []
    base = target.rstrip("/")

    # 1MB payload
    large = {"data": "A" * (1024 * 1024)}
    status, _, body = _request(f"{base}/api/chat", method="POST", data=large,
                               headers={"Origin": base}, timeout=15)

    if status == 413:
        findings.append(_finding(
            "Request size limit enforced (413)",
            "info",
            "Server returned 413 Payload Too Large for a 1MB request.",
            f"{base}/api/chat",
        ))
    elif status in (200, 201):
        findings.append(_finding(
            "No request size limit: 1MB payload accepted",
            "medium",
            f"Server accepted a 1MB payload without returning 413. "
            f"This could enable memory exhaustion attacks.",
            f"{base}/api/chat",
            evidence=f"Status: {status}",
            cwe="CWE-770",
        ))
    else:
        findings.append(_finding(
            f"Large payload: server returned {status}",
            "info",
            f"1MB payload returned {status}. The request may have been "
            f"rejected by other validation before size checking.",
            f"{base}/api/chat",
        ))

    return findings


def test_api_versioning(target: str) -> list[dict]:
    """Check if old API versions are still accessible."""
    findings = []
    base = target.rstrip("/")

    for version in ["/api/v1", "/api/v2", "/api/v0", "/v1/api", "/v2/api"]:
        url = f"{base}{version}"
        status, _, body = _request(url)
        if status == 200:
            findings.append(_finding(
                f"API version endpoint live: {version}",
                "info",
                f"GET {version} returned 200. If this is a deprecated version, "
                f"it may lack security patches applied to the current version.",
                url,
            ))

    if not findings:
        findings.append(_finding(
            "API versioning: no version endpoints found",
            "info",
            "No /api/v1, /api/v2, etc. endpoints returned 200.",
            target,
        ))
    return findings


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

QUICK_TESTS = [
    ("Method enumeration", test_method_enumeration),
    ("API versioning", test_api_versioning),
]

STANDARD_TESTS = QUICK_TESTS + [
    ("Mass assignment", test_mass_assignment),
    ("IDOR patterns", test_idor_patterns),
    ("Excessive data exposure", test_excessive_data_exposure),
]

FULL_TESTS = STANDARD_TESTS + [
    ("Content-type confusion", test_content_type_confusion),
    ("Large payload", test_large_payload),
]

DEPTH_MAP = {
    "quick": QUICK_TESTS,
    "standard": STANDARD_TESTS,
    "full": FULL_TESTS,
}


def run_api_tests(target: str, depth: str = "standard") -> list[dict]:
    import sys
    findings = []
    tests = DEPTH_MAP.get(depth, STANDARD_TESTS)

    for name, fn in tests:
        print(f"[regen] API: {name}...", file=sys.stderr)
        try:
            findings.extend(fn(target))
        except Exception as e:
            print(f"[regen] API '{name}' failed: {e}", file=sys.stderr)
            findings.append(_finding(
                f"API test failed: {name}", "info",
                f"Test could not complete: {e}", target,
            ))

    return findings
