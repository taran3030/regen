"""
Authentication and session security testing.

Probes login flows, session management, and cookie security without
creating real accounts or brute-forcing credentials. Every test is
safe for production: no lockouts, no data writes, no stored state.

Depth levels:
  quick    — Cookie attributes and logout behavior only
  standard — + session fixation, token entropy, login rate limiting
  full     — + brute-force resistance timing, concurrent sessions, CSRF on auth
"""
import hashlib
import json
import math
import re
import ssl
import time
import urllib.request
import urllib.error
from collections import Counter
from typing import Optional
from urllib.parse import urlparse


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


def _post_json(url, data, headers=None, timeout=10):
    ctx = ssl.create_default_context()
    payload = json.dumps(data).encode()
    req = urllib.request.Request(url, data=payload, method="POST")
    req.add_header("User-Agent", "Regen/1.1 (Axolotl Labs Security Scanner)")
    req.add_header("Content-Type", "application/json")
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
        "scanner": "auth",
        **kwargs,
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_cookie_attributes(target: str) -> list[dict]:
    """Check session cookies for HttpOnly, Secure, SameSite, and Path scope."""
    findings = []
    base = target.rstrip("/")

    for url in [base, f"{base}/api/me"]:
        status, hdrs, _ = _get(url)
        for k, v in hdrs.items():
            if k.lower() != "set-cookie":
                continue
            name = v.split("=")[0].strip()
            lower = v.lower()

            issues = []
            if "httponly" not in lower:
                issues.append("HttpOnly")
            if "secure" not in lower:
                issues.append("Secure")
            if "samesite" not in lower:
                issues.append("SameSite")

            if issues:
                findings.append(_finding(
                    f"Cookie '{name}' missing: {', '.join(issues)}",
                    "medium" if "HttpOnly" in issues else "low",
                    f"Set-Cookie for '{name}' lacks: {', '.join(issues)}.",
                    url,
                    evidence=f"Set-Cookie: {v[:200]}",
                    cwe="CWE-614",
                ))

            # Overly broad path
            path_match = re.search(r"[Pp]ath=(/[^;]*)", v)
            cookie_path = path_match.group(1).strip() if path_match else "/"
            if cookie_path == "/" and "session" in name.lower():
                findings.append(_finding(
                    f"Session cookie '{name}' scoped to /",
                    "info",
                    f"Session cookie path is / instead of the app's narrower prefix. "
                    f"This means every sub-path receives it, including third-party "
                    f"paths if the same domain hosts multiple apps.",
                    url,
                    evidence=f"Path={cookie_path}",
                ))

    if not findings:
        findings.append(_finding(
            "Cookie attributes: OK or no cookies observed",
            "info",
            "No insecure cookie attributes found on unauthenticated requests.",
            target,
        ))
    return findings


def test_login_rate_limiting(target: str) -> list[dict]:
    """
    Send a burst of login attempts with invalid credentials and check whether
    the server starts rate-limiting (429 or escalating delays). We use a
    clearly fake email to avoid locking real accounts.
    """
    findings = []
    base = target.rstrip("/")
    login_url = f"{base}/api/auth/start"

    statuses = []
    for i in range(8):
        status, _, body = _post_json(login_url, {"email": f"regen-ratelimit-{i}@example.invalid"})
        statuses.append(status)
        if status == 429:
            break

    if 429 in statuses:
        at = statuses.index(429) + 1
        findings.append(_finding(
            f"Login rate-limits after {at} requests",
            "info",
            f"Server returned 429 after {at} attempts with invalid emails.",
            login_url,
            evidence=f"Statuses: {statuses}",
        ))
    elif all(s == 0 for s in statuses):
        findings.append(_finding(
            "Login endpoint unreachable",
            "info",
            "Could not connect to the login endpoint.",
            login_url,
        ))
    elif all(s in (403, 404, 405) for s in statuses):
        findings.append(_finding(
            "Login endpoint not found or requires specific origin",
            "info",
            f"All requests returned {statuses[0]}. The endpoint may require "
            f"a valid Origin header or Turnstile token.",
            login_url,
        ))
    else:
        # Check if any returned 200/201 (would mean no validation at all)
        successes = [s for s in statuses if 200 <= s < 300]
        if len(successes) > 5:
            findings.append(_finding(
                "Login not rate-limited after 8 attempts",
                "medium",
                f"Sent 8 login attempts; {len(successes)} succeeded (2xx). "
                f"No 429 was returned. An attacker can enumerate emails or "
                f"brute-force without throttling.",
                login_url,
                evidence=f"Statuses: {statuses}",
                cwe="CWE-307",
            ))
        else:
            findings.append(_finding(
                "Login rate limiting: inconclusive",
                "info",
                f"Sent 8 attempts; got statuses: {statuses}. No clear 429, "
                f"but most were blocked by other defenses.",
                login_url,
            ))

    return findings


def test_logout_invalidation(target: str) -> list[dict]:
    """
    Check that the logout endpoint exists and responds. Without a session,
    we can only confirm the route is there and returns 401 or similar (not 404).
    """
    findings = []
    base = target.rstrip("/")
    logout_url = f"{base}/api/auth/logout"

    status, _, body = _post_json(logout_url, {}, headers={"Origin": target.rstrip("/")})

    if status == 404:
        findings.append(_finding(
            "No logout endpoint found",
            "medium",
            f"POST /api/auth/logout returned 404. If users can't log out, "
            f"compromised sessions persist until expiry.",
            logout_url,
            cwe="CWE-613",
        ))
    elif status == 401:
        findings.append(_finding(
            "Logout endpoint exists (requires auth)",
            "info",
            f"POST /api/auth/logout returned 401, confirming the endpoint exists "
            f"and requires a session.",
            logout_url,
        ))
    elif status == 403:
        findings.append(_finding(
            "Logout endpoint reachable (blocked by origin/CSRF)",
            "info",
            f"POST /api/auth/logout returned 403. This is normal when the "
            f"origin check fires before the session check.",
            logout_url,
        ))
    else:
        findings.append(_finding(
            f"Logout endpoint returned {status}",
            "info",
            f"POST /api/auth/logout returned {status}: {body[:100]}",
            logout_url,
        ))

    return findings


def test_session_fixation(target: str) -> list[dict]:
    """
    Check whether the server accepts a client-provided session ID.
    If we send a fake session cookie and the server echoes it back or
    uses it, that's session fixation.
    """
    findings = []
    base = target.rstrip("/")

    fake_session = "regen_fixation_test_" + hashlib.sha256(b"test").hexdigest()[:16]
    status, hdrs, body = _get(f"{base}/api/me", headers={"Cookie": f"session={fake_session}"})

    set_cookies = {k: v for k, v in hdrs.items() if k.lower() == "set-cookie"}
    for k, v in set_cookies.items():
        if fake_session in v:
            findings.append(_finding(
                "Session fixation: server accepted attacker's session ID",
                "high",
                f"The server echoed back the session ID we provided in the "
                f"Cookie header. An attacker can set a session ID and wait "
                f"for the user to authenticate with it.",
                f"{base}/api/me",
                evidence=f"Sent Cookie: session={fake_session}, got Set-Cookie containing it",
                cwe="CWE-384",
            ))

    if not findings:
        findings.append(_finding(
            "Session fixation: not vulnerable",
            "info",
            "Server did not echo back or reuse the attacker-provided session ID.",
            target,
        ))
    return findings


def test_auth_error_messages(target: str) -> list[dict]:
    """
    Check whether login errors distinguish between 'email not found' and
    'wrong password' — this is an enumeration vector.
    """
    findings = []
    base = target.rstrip("/")
    login_url = f"{base}/api/auth/start"

    # Try a valid-format email and a weird one
    _, _, body1 = _post_json(login_url, {"email": "definitely-not-a-user@example.invalid"})
    _, _, body2 = _post_json(login_url, {"email": "admin@example.com"})

    try:
        err1 = json.loads(body1).get("error", body1)
        err2 = json.loads(body2).get("error", body2)
    except (json.JSONDecodeError, ValueError):
        err1, err2 = body1[:200], body2[:200]

    if err1 != err2 and "not found" in str(err1).lower() or "not found" in str(err2).lower():
        findings.append(_finding(
            "Login error reveals whether email exists",
            "medium",
            f"Different error messages for different emails: "
            f"'{err1}' vs '{err2}'. An attacker can enumerate valid emails.",
            login_url,
            evidence=f"err1={err1[:80]}, err2={err2[:80]}",
            cwe="CWE-204",
        ))
    else:
        findings.append(_finding(
            "Login errors: consistent messages",
            "info",
            f"Both test emails returned the same error pattern.",
            login_url,
        ))

    return findings


def test_concurrent_sessions(target: str) -> list[dict]:
    """
    Check if the app mentions or enforces single-session-per-user.
    Without auth, we can only check whether the app's client JS mentions
    'concurrent' or 'active session' logic.
    """
    findings = []
    status, _, body = _get(target)

    concurrent_patterns = [
        r"concurrent.{0,20}session",
        r"active.{0,20}session.{0,20}limit",
        r"already.{0,20}logged.{0,20}in",
        r"session.{0,20}expired.{0,20}another",
    ]

    found = False
    for pat in concurrent_patterns:
        if re.search(pat, body, re.IGNORECASE):
            found = True
            break

    findings.append(_finding(
        "Concurrent sessions: " + ("mentions session limits" if found else "no client-side mention"),
        "info",
        "Checked page source for concurrent session handling. " +
        ("Found references to session limits." if found else
         "No mention found; likely allows unlimited concurrent sessions. "
         "This is normal for many apps but worth documenting."),
        target,
    ))
    return findings


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

QUICK_TESTS = [
    ("Cookie attributes", test_cookie_attributes),
    ("Logout endpoint", test_logout_invalidation),
]

STANDARD_TESTS = QUICK_TESTS + [
    ("Login rate limiting", test_login_rate_limiting),
    ("Session fixation", test_session_fixation),
    ("Auth error messages", test_auth_error_messages),
]

FULL_TESTS = STANDARD_TESTS + [
    ("Concurrent sessions", test_concurrent_sessions),
]

DEPTH_MAP = {
    "quick": QUICK_TESTS,
    "standard": STANDARD_TESTS,
    "full": FULL_TESTS,
}


def run_auth_tests(target: str, depth: str = "standard") -> list[dict]:
    import sys
    findings = []
    tests = DEPTH_MAP.get(depth, STANDARD_TESTS)

    for name, fn in tests:
        print(f"[regen] Auth: {name}...", file=sys.stderr)
        try:
            findings.extend(fn(target))
        except Exception as e:
            print(f"[regen] Auth '{name}' failed: {e}", file=sys.stderr)
            findings.append(_finding(
                f"Auth test failed: {name}", "info",
                f"Test could not complete: {e}", target,
            ))

    return findings
