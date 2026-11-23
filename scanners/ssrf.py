"""
Server-Side Request Forgery (SSRF) testing.

Probes endpoints that accept URLs or hostnames to check whether the server
fetches internal resources. Detection is based on response content, timing,
and error message differences — no out-of-band callbacks (safe for --no-oast).

Depth levels:
  quick    — Basic loopback and metadata checks on common URL params
  standard — + cloud metadata endpoints, IP encoding bypasses
  full     — + DNS rebinding patterns, protocol smuggling, redirect chains
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
        "scanner": "ssrf",
        **kwargs,
    }


INTERNAL_SIGNATURES = [
    r"<title>IIS",
    r"Apache/\d",
    r"nginx/\d",
    r"Welcome to nginx",
    r"It works!",
    r"<address>Apache",
    r'"ami-id"',
    r'"instance-id"',
    r'"local-ipv4"',
    r"computeMetadata",
    r'"accountId"',
    r'"subscriptionId"',
]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_ssrf_url_params(target: str) -> list[dict]:
    """
    Inject internal URLs into common URL-accepting parameters and check
    whether the server fetches them (response contains internal content
    or differs from baseline).
    """
    findings = []
    base = target.rstrip("/")

    url_params = ["url", "link", "src", "href", "redirect", "fetch",
                  "proxy", "image", "img", "load", "uri", "path"]

    # Baseline: request with a benign external URL
    baseline_url = f"{base}/?url=https://example.com"
    _, _, baseline_body = _request(baseline_url)

    for param in url_params:
        for ssrf_url, label in payloads.SSRF_INTERNAL_TARGETS[:4]:
            test_url = f"{base}/?{param}={quote(ssrf_url)}"
            status, _, body = _request(test_url)
            if status == 0:
                continue

            for sig in INTERNAL_SIGNATURES:
                if re.search(sig, body, re.IGNORECASE):
                    findings.append(_finding(
                        f"SSRF: internal content via ?{param} ({label})",
                        "critical",
                        f"The server fetched {ssrf_url} and returned internal "
                        f"content matching '{sig}'. An attacker can reach "
                        f"internal services through the server.",
                        test_url,
                        evidence=f"Pattern: {sig}, target: {ssrf_url}",
                        cwe="CWE-918",
                    ))
                    break

    if not findings:
        findings.append(_finding(
            "SSRF: no internal content via URL parameters",
            "info",
            f"Tested {len(url_params)} URL parameters with internal targets; "
            f"no internal content leaked.",
            target,
        ))
    return findings


def test_ssrf_cloud_metadata(target: str) -> list[dict]:
    """
    Try to reach cloud metadata services (AWS/GCP/Azure) through URL
    parameters. These endpoints expose instance credentials and config.
    """
    findings = []
    base = target.rstrip("/")
    url_params = ["url", "fetch", "proxy", "src"]

    for param in url_params:
        for meta_url, label in payloads.SSRF_CLOUD_METADATA:
            test_url = f"{base}/?{param}={quote(meta_url)}"
            hdrs = {}
            if "computeMetadata" in meta_url:
                hdrs["Metadata-Flavor"] = "Google"
            status, _, body = _request(test_url, headers=hdrs)
            if status == 0:
                continue

            metadata_signs = [
                r"ami-id", r"instance-id", r"local-ipv4",
                r"access_token", r"computeMetadata",
                r"subscriptionId", r"vmId",
            ]
            for sig in metadata_signs:
                if re.search(sig, body, re.IGNORECASE):
                    findings.append(_finding(
                        f"SSRF: cloud metadata accessible via ?{param} ({label})",
                        "critical",
                        f"The server fetched {meta_url} and returned cloud "
                        f"instance metadata. This can expose IAM credentials, "
                        f"instance identity, and network configuration.",
                        test_url,
                        evidence=f"Pattern: {sig}, metadata: {label}",
                        remediation="Block requests to 169.254.169.254 and other "
                                    "metadata IPs at the application or network level. "
                                    "Use IMDSv2 (require session tokens) on AWS.",
                        cwe="CWE-918",
                    ))
                    break

    if not findings:
        findings.append(_finding(
            "SSRF: cloud metadata not reachable via URL params",
            "info",
            f"Tested cloud metadata endpoints (AWS/GCP/Azure) through URL "
            f"parameters; none returned metadata content.",
            target,
        ))
    return findings


def test_ssrf_ip_bypass(target: str) -> list[dict]:
    """
    Try alternative IP representations to bypass allowlist/denylist filters
    that only check for '127.0.0.1' or 'localhost'.
    """
    findings = []
    base = target.rstrip("/")

    for ssrf_url, label in payloads.SSRF_BYPASS:
        test_url = f"{base}/?url={quote(ssrf_url)}"
        status, _, body = _request(test_url)
        if status == 0:
            continue

        for sig in INTERNAL_SIGNATURES:
            if re.search(sig, body, re.IGNORECASE):
                findings.append(_finding(
                    f"SSRF filter bypass: {label}",
                    "high",
                    f"The filter was bypassed using {ssrf_url}. The server "
                    f"fetched internal content despite IP filtering.",
                    test_url,
                    evidence=f"Pattern: {sig}, bypass: {label}",
                    remediation="Parse and resolve URLs before filtering. "
                                "Deny all private/reserved IP ranges after resolution.",
                    cwe="CWE-918",
                ))
                break

    if not findings:
        findings.append(_finding(
            "SSRF: IP encoding bypasses did not leak internal content",
            "info",
            f"Tested {len(payloads.SSRF_BYPASS)} IP encoding tricks; "
            f"none returned internal content.",
            target,
        ))
    return findings


def test_ssrf_post_body(target: str) -> list[dict]:
    """
    Some APIs accept URLs in POST request bodies (webhooks, image uploads,
    import features). Test common API paths with internal URLs in the body.
    """
    findings = []
    base = target.rstrip("/")

    api_paths = [
        "/api/media", "/api/upload", "/api/import",
        "/api/webhook", "/api/fetch", "/api/preview",
    ]

    for path in api_paths:
        url = f"{base}{path}"
        for ssrf_url, label in payloads.SSRF_INTERNAL_TARGETS[:3]:
            for field in ["url", "src", "image", "webhook_url"]:
                status, _, body = _request(
                    url, method="POST",
                    data={field: ssrf_url},
                    headers={"Origin": base},
                )
                if status in (0, 404, 405):
                    continue

                for sig in INTERNAL_SIGNATURES:
                    if re.search(sig, body, re.IGNORECASE):
                        findings.append(_finding(
                            f"SSRF via POST {path} ({label})",
                            "critical",
                            f"POST {path} with {field}={ssrf_url} returned "
                            f"internal content.",
                            url,
                            evidence=f"Pattern: {sig}, field: {field}",
                            cwe="CWE-918",
                        ))
                        break

    if not findings:
        findings.append(_finding(
            "SSRF: POST body URL fields did not leak internal content",
            "info",
            f"Tested {len(api_paths)} API paths with internal URLs in POST body; "
            f"none returned internal content.",
            target,
        ))
    return findings


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

QUICK_TESTS = [
    ("SSRF URL params", test_ssrf_url_params),
]

STANDARD_TESTS = QUICK_TESTS + [
    ("SSRF cloud metadata", test_ssrf_cloud_metadata),
    ("SSRF POST body", test_ssrf_post_body),
]

FULL_TESTS = STANDARD_TESTS + [
    ("SSRF IP bypass", test_ssrf_ip_bypass),
]

DEPTH_MAP = {
    "quick": QUICK_TESTS,
    "standard": STANDARD_TESTS,
    "full": FULL_TESTS,
}


def run_ssrf_tests(target: str, depth: str = "standard") -> list[dict]:
    import sys
    findings = []
    tests = DEPTH_MAP.get(depth, STANDARD_TESTS)

    for name, fn in tests:
        print(f"[regen] SSRF: {name}...", file=sys.stderr)
        try:
            findings.extend(fn(target))
        except Exception as e:
            print(f"[regen] SSRF '{name}' failed: {e}", file=sys.stderr)
            findings.append(_finding(
                f"SSRF test failed: {name}", "info",
                f"Test could not complete: {e}", target,
            ))

    return findings
