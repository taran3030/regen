"""
Injection testing scanner.

Probes for reflected XSS, SQL injection, server-side template injection,
and command injection using safe, non-destructive payloads. Each payload
is designed to be detectable in the response without causing damage:
canary strings instead of real exploits, error-based detection instead
of data extraction.

Depth levels:
  quick    — Reflected XSS canary on query params only
  standard — + SQLi error detection, SSTI probe, header injection
  full     — + command injection timing, polyglot payloads, encoded variants
"""
import json
import re
import ssl
import time
import urllib.request
import urllib.error
from typing import Optional
from urllib.parse import urlparse, urlencode, quote


def _get(url, headers=None, timeout=10):
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", "Regen/1.1 (Axolotl Labs Security Scanner)")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return resp.status, dict(resp.headers), resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return e.code, dict(e.headers), body
    except Exception as e:
        return 0, {}, str(e)


def _post(url, data, content_type="application/json", headers=None, timeout=10):
    ctx = ssl.create_default_context()
    if content_type == "application/json":
        payload = json.dumps(data).encode()
    else:
        payload = urlencode(data).encode() if isinstance(data, dict) else data.encode()
    req = urllib.request.Request(url, data=payload, method="POST")
    req.add_header("User-Agent", "Regen/1.1 (Axolotl Labs Security Scanner)")
    req.add_header("Content-Type", content_type)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return resp.status, dict(resp.headers), resp.read().decode("utf-8", errors="replace")
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
        "scanner": "injection",
        **kwargs,
    }


# ---------------------------------------------------------------------------
# XSS detection
# ---------------------------------------------------------------------------

from . import payloads

CANARY = payloads.CANARY


def test_reflected_xss(target: str, depth: str = "standard") -> list[dict]:
    """
    Inject XSS canary strings in URL parameters and check if they appear
    unescaped in the response body. Payload count scales with depth.
    """
    findings = []
    base = target.rstrip("/")
    param_names = payloads.INJECT_PARAMS[:9]
    xss_payloads = payloads.XSS_DEPTH.get(depth, payloads.XSS_STANDARD)

    for param in param_names:
        for payload, label in xss_payloads:
            test_url = f"{base}/?{param}={quote(payload)}"
            status, _, body = _get(test_url)
            if status == 0:
                continue

            if payload in body:
                findings.append(_finding(
                    f"Reflected XSS via ?{param} ({label})",
                    "high",
                    f"The payload was reflected unescaped in the response body. "
                    f"An attacker can craft a URL that executes JavaScript in "
                    f"the victim's browser.",
                    test_url,
                    evidence=f"Payload reflected: {payload[:60]}",
                    cwe="CWE-79",
                ))
                break

            canary_idx = body.find(CANARY)
            if canary_idx >= 0:
                context = body[max(0, canary_idx - 10):canary_idx]
                if "<" not in context:
                    findings.append(_finding(
                        f"Partial XSS reflection via ?{param} ({label})",
                        "low",
                        f"The canary string was reflected but HTML tags appear "
                        f"stripped. The filter may be bypassable with encoding tricks.",
                        test_url,
                        evidence=f"Canary '{CANARY}' found, tags stripped",
                        cwe="CWE-79",
                    ))
                    break

    if not findings:
        findings.append(_finding(
            "Reflected XSS: no reflection found",
            "info",
            f"Tested {len(param_names)} parameter names with {len(xss_payloads)} "
            f"XSS payloads; none were reflected unescaped.",
            target,
        ))
    return findings


# ---------------------------------------------------------------------------
# SQL injection
# ---------------------------------------------------------------------------

def test_sqli_error_based(target: str, depth: str = "standard") -> list[dict]:
    """
    Send SQL-triggering strings in URL parameters and POST bodies. Check
    for database error messages in the response. Uses DB-specific payloads
    from PayloadsAllTheThings at standard+ depth.
    """
    findings = []
    base = target.rstrip("/")
    sqli_payloads = payloads.SQLI_DEPTH.get(depth, payloads.SQLI_STANDARD)

    test_endpoints = [
        ("GET", f"{base}/?id={{payload}}", None),
        ("GET", f"{base}/api/me?id={{payload}}", None),
    ]

    for method, url_tpl, body_tpl in test_endpoints:
        for payload, label, detection in sqli_payloads:
            if detection == "timing":
                continue  # Timing payloads handled separately at full depth

            if method == "GET":
                url = url_tpl.replace("{payload}", quote(payload))
                status, _, body = _get(url)
            else:
                url = url_tpl
                status, _, body = _post(url, body_tpl.replace("{payload}", payload))

            if status == 0:
                continue

            for pattern, db_engine in payloads.SQLI_ERROR_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    findings.append(_finding(
                        f"SQL injection ({db_engine}): {label}",
                        "critical",
                        f"Database error from {db_engine} found in response after "
                        f"sending SQL payload ({label}). The backend may be "
                        f"concatenating user input into SQL queries.",
                        url,
                        evidence=f"Engine: {db_engine}, pattern: {pattern}, payload: {payload[:60]}",
                        cwe="CWE-89",
                    ))
                    break

    if not findings:
        findings.append(_finding(
            "SQL injection: no database errors triggered",
            "info",
            f"Tested {len([p for p in sqli_payloads if p[2] != 'timing'])} "
            f"SQL payloads (error-based); no database error messages appeared.",
            target,
        ))
    return findings


# ---------------------------------------------------------------------------
# SSTI (Server-Side Template Injection)
# ---------------------------------------------------------------------------

def test_ssti(target: str, depth: str = "standard") -> list[dict]:
    """
    Inject template syntax in URL parameters. If the server evaluates
    the expression and returns the result, it's vulnerable to SSTI.
    Payload count scales with depth.
    """
    findings = []
    base = target.rstrip("/")
    ssti_payloads = payloads.SSTI_DEPTH.get(depth, payloads.SSTI_STANDARD)

    for payload, expected, engine in ssti_payloads:
        url = f"{base}/?name={quote(payload)}"
        status, _, body = _get(url)
        if status == 0:
            continue

        if expected in body and payload not in body:
            findings.append(_finding(
                f"SSTI: {engine} expression evaluated",
                "critical",
                f"Template expression '{payload}' was evaluated to '{expected}'. "
                f"An attacker can execute arbitrary code on the server.",
                url,
                evidence=f"Sent: {payload}, found: {expected}, engine: {engine}",
                cwe="CWE-1336",
            ))
            break

    if not findings:
        findings.append(_finding(
            "SSTI: no template evaluation detected",
            "info",
            f"Tested {len(ssti_payloads)} SSTI payloads in ?name=; "
            f"none were evaluated.",
            target,
        ))
    return findings


# ---------------------------------------------------------------------------
# Header injection (CRLF)
# ---------------------------------------------------------------------------

def test_header_injection(target: str) -> list[dict]:
    """
    Try CRLF injection in URL parameters to see if we can inject
    response headers.
    """
    findings = []
    base = target.rstrip("/")

    crlf_payloads = [
        ("%0d%0aX-Regen-Injected: true", "URL-encoded CRLF"),
        ("%0aX-Regen-Injected: true", "LF only"),
        ("\r\nX-Regen-Injected: true", "raw CRLF"),
    ]

    for payload, label in crlf_payloads:
        url = f"{base}/?redirect={payload}"
        status, hdrs, _ = _get(url)

        for k in hdrs:
            if k.lower() == "x-regen-injected":
                findings.append(_finding(
                    f"Header injection via CRLF ({label})",
                    "high",
                    f"Injected X-Regen-Injected header appeared in the response. "
                    f"An attacker can set arbitrary headers, enabling session "
                    f"fixation, cache poisoning, or XSS via injected content.",
                    url,
                    evidence=f"X-Regen-Injected: {hdrs[k]}",
                    cwe="CWE-113",
                ))
                break

    if not findings:
        findings.append(_finding(
            "Header injection: CRLF payloads not reflected",
            "info",
            f"Tested {len(crlf_payloads)} CRLF injection payloads; "
            f"none produced injected headers.",
            target,
        ))
    return findings


# ---------------------------------------------------------------------------
# Command injection (timing-based, full depth only)
# ---------------------------------------------------------------------------

def test_sqli_timing(target: str) -> list[dict]:
    """
    Time-based blind SQL injection. Send DB-specific sleep payloads and
    compare response times. Full depth only.
    """
    findings = []
    base = target.rstrip("/")

    timing_payloads = [p for p in payloads.SQLI_FULL if p[2] == "timing"]

    # Baseline
    t0 = time.monotonic()
    _get(f"{base}/?id=1")
    baseline = time.monotonic() - t0

    for payload, label, _ in timing_payloads:
        t0 = time.monotonic()
        _get(f"{base}/?id={quote(payload)}")
        elapsed = time.monotonic() - t0

        if elapsed > baseline + 2.5:
            db = "MySQL" if "SLEEP" in payload.upper() else \
                 "MSSQL" if "WAITFOR" in payload.upper() else \
                 "PostgreSQL" if "pg_sleep" in payload else "SQLite"
            findings.append(_finding(
                f"Blind SQLi timing ({db}): {label}",
                "critical",
                f"Response took {elapsed:.1f}s (baseline {baseline:.1f}s) after "
                f"a {db} sleep payload. The database may be executing injected SQL.",
                f"{base}/?id={quote(payload)}",
                evidence=f"Baseline: {baseline:.1f}s, payload: {elapsed:.1f}s, engine: {db}",
                cwe="CWE-89",
            ))
            break

    if not findings:
        findings.append(_finding(
            "Blind SQLi timing: no delays detected",
            "info",
            f"Tested {len(timing_payloads)} timing payloads; "
            f"none exceeded baseline + 2.5s.",
            target,
        ))
    return findings


def test_command_injection_timing(target: str) -> list[dict]:
    """
    Send payloads that would cause a sleep if command injection is present.
    Compare response times. We use a 3-second sleep to minimize false
    positives while keeping total test time reasonable.
    """
    findings = []
    base = target.rstrip("/")

    sleep_payloads = [
        ("; sleep 3 #", "semicolon-sleep"),
        ("| sleep 3 #", "pipe-sleep"),
        ("$(sleep 3)", "subshell-sleep"),
        ("`sleep 3`", "backtick-sleep"),
    ]

    # Baseline timing
    t0 = time.monotonic()
    _get(f"{base}/?cmd=regen_baseline")
    baseline = time.monotonic() - t0

    for payload, label in sleep_payloads:
        t0 = time.monotonic()
        _get(f"{base}/?cmd={quote(payload)}")
        elapsed = time.monotonic() - t0

        # If the response took 2.5+ seconds longer than baseline, suspicious
        if elapsed > baseline + 2.5:
            findings.append(_finding(
                f"Possible command injection ({label})",
                "critical",
                f"Response took {elapsed:.1f}s (baseline {baseline:.1f}s) after "
                f"sending a sleep payload. This suggests the server may be "
                f"executing the injected command.",
                f"{base}/?cmd={quote(payload)}",
                evidence=f"Baseline: {baseline:.1f}s, payload: {elapsed:.1f}s",
                cwe="CWE-78",
            ))
            break

    if not findings:
        findings.append(_finding(
            "Command injection: no timing anomalies",
            "info",
            f"Tested {len(sleep_payloads)} sleep payloads; "
            f"no response exceeded baseline + 2.5s.",
            target,
        ))
    return findings


# ---------------------------------------------------------------------------
# Open redirect
# ---------------------------------------------------------------------------

def test_open_redirect(target: str) -> list[dict]:
    """
    Check common redirect parameters for open redirect vulnerabilities.
    """
    findings = []
    base = target.rstrip("/")

    redirect_params = ["redirect", "next", "url", "return", "returnTo", "goto", "continue"]
    evil_urls = [
        "https://evil.example.com",
        "//evil.example.com",
        "/\\evil.example.com",
        "https://evil.example.com%2f.example.com",
    ]

    for param in redirect_params:
        for evil in evil_urls:
            url = f"{base}/?{param}={quote(evil)}"
            try:
                ctx = ssl.create_default_context()
                req = urllib.request.Request(url, method="GET")
                req.add_header("User-Agent", "Regen/1.1")
                # Use a handler that doesn't follow redirects
                import http.client
                parsed = urlparse(url)
                conn = http.client.HTTPSConnection(parsed.netloc, timeout=10, context=ctx)
                conn.request("GET", f"{parsed.path}?{parsed.query}", headers={"Host": parsed.netloc, "User-Agent": "Regen/1.1"})
                resp = conn.getresponse()
                location = resp.getheader("Location", "")
                resp.read()
                conn.close()

                if resp.status in (301, 302, 303, 307, 308):
                    if "evil.example.com" in location:
                        findings.append(_finding(
                            f"Open redirect via ?{param}",
                            "medium",
                            f"The server redirected to {location} when given an "
                            f"external URL in the {param} parameter. This can be "
                            f"used for phishing.",
                            url,
                            evidence=f"Location: {location}",
                            cwe="CWE-601",
                        ))
                        break
            except Exception:
                continue

    if not findings:
        findings.append(_finding(
            "Open redirect: none found",
            "info",
            f"Tested {len(redirect_params)} redirect parameters with "
            f"{len(evil_urls)} payloads; no open redirects.",
            target,
        ))
    return findings


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

QUICK_TESTS = [
    ("Reflected XSS", test_reflected_xss, True),
]

STANDARD_TESTS = QUICK_TESTS + [
    ("SQL injection (error-based)", test_sqli_error_based, True),
    ("SSTI", test_ssti, True),
    ("Header injection (CRLF)", test_header_injection, False),
    ("Open redirect", test_open_redirect, False),
]

FULL_TESTS = STANDARD_TESTS + [
    ("SQL injection (timing-based)", test_sqli_timing, False),
    ("Command injection (timing)", test_command_injection_timing, False),
]

DEPTH_MAP = {
    "quick": QUICK_TESTS,
    "standard": STANDARD_TESTS,
    "full": FULL_TESTS,
}


def run_injection_tests(target: str, depth: str = "standard") -> list[dict]:
    import sys
    findings = []
    tests = DEPTH_MAP.get(depth, STANDARD_TESTS)

    for name, fn, accepts_depth in tests:
        print(f"[regen] Injection: {name}...", file=sys.stderr)
        try:
            if accepts_depth:
                findings.extend(fn(target, depth=depth))
            else:
                findings.extend(fn(target))
        except Exception as e:
            print(f"[regen] Injection '{name}' failed: {e}", file=sys.stderr)
            findings.append(_finding(
                f"Injection test failed: {name}", "info",
                f"Test could not complete: {e}", target,
            ))

    return findings
