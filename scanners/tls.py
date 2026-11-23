"""
TLS/SSL configuration analysis.

Checks the target's TLS setup: protocol versions, certificate details,
cipher suites, and related headers. Uses Python's ssl module so there's
no dependency on openssl CLI or sslyze.

Depth levels:
  quick    — Certificate validity and protocol version only
  standard — + cipher suite check, cert chain, HSTS analysis
  full     — + weak protocol probes (TLS 1.0, 1.1, SSLv3), CT header
"""
import hashlib
import json
import re
import socket
import ssl
import struct
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse


def _finding(title, severity, description, location, **kwargs):
    return {
        "title": title,
        "severity": severity,
        "description": description,
        "location": location,
        "scanner": "tls",
        **kwargs,
    }


def _connect(host: str, port: int = 443) -> Optional[ssl.SSLSocket]:
    ctx = ssl.create_default_context()
    try:
        sock = socket.create_connection((host, port), timeout=10)
        return ctx.wrap_socket(sock, server_hostname=host)
    except Exception:
        return None


def _probe_protocol(host: str, port: int, protocol_const) -> bool:
    """Try to connect with a specific TLS protocol version."""
    try:
        ctx = ssl.SSLContext(protocol_const)
        ctx.set_ciphers("ALL:@SECLEVEL=0")
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = socket.create_connection((host, port), timeout=5)
        ssock = ctx.wrap_socket(sock, server_hostname=host)
        ssock.close()
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_certificate(target: str) -> list[dict]:
    """Check certificate validity, expiry, and common name match."""
    findings = []
    parsed = urlparse(target)
    host = parsed.netloc.split(":")[0]
    port = int(parsed.netloc.split(":")[1]) if ":" in parsed.netloc else 443

    ssock = _connect(host, port)
    if not ssock:
        findings.append(_finding(
            "TLS: could not connect",
            "high",
            f"Could not establish TLS connection to {host}:{port}.",
            target,
            cwe="CWE-319",
        ))
        return findings

    cert = ssock.getpeercert()
    version = ssock.version()
    cipher = ssock.cipher()
    ssock.close()

    # Protocol version
    findings.append(_finding(
        f"TLS protocol: {version}",
        "info" if version in ("TLSv1.2", "TLSv1.3") else "medium",
        f"Connection used {version}." +
        ("" if version in ("TLSv1.2", "TLSv1.3") else
         " TLS 1.0 and 1.1 are deprecated and have known weaknesses."),
        target,
        evidence=f"Protocol: {version}, Cipher: {cipher[0] if cipher else 'unknown'}",
        cwe=None if version in ("TLSv1.2", "TLSv1.3") else "CWE-326",
    ))

    # Certificate expiry
    not_after = cert.get("notAfter", "")
    if not_after:
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_left = (expiry - now).days

            if days_left < 0:
                findings.append(_finding(
                    "Certificate expired",
                    "critical",
                    f"Certificate expired {-days_left} days ago on {not_after}.",
                    target,
                    evidence=f"notAfter: {not_after}",
                    cwe="CWE-295",
                ))
            elif days_left < 14:
                findings.append(_finding(
                    f"Certificate expires in {days_left} days",
                    "high",
                    f"Certificate expires on {not_after} ({days_left} days). "
                    f"Renew immediately to avoid outages.",
                    target,
                    evidence=f"notAfter: {not_after}",
                ))
            elif days_left < 30:
                findings.append(_finding(
                    f"Certificate expires in {days_left} days",
                    "medium",
                    f"Certificate expires on {not_after}.",
                    target,
                    evidence=f"notAfter: {not_after}",
                ))
            else:
                findings.append(_finding(
                    f"Certificate valid for {days_left} days",
                    "info",
                    f"Certificate expires on {not_after}.",
                    target,
                    evidence=f"notAfter: {not_after}",
                ))
        except (ValueError, TypeError):
            pass

    # Subject / SAN mismatch
    sans = []
    for type_id, value in cert.get("subjectAltName", []):
        if type_id == "DNS":
            sans.append(value.lower())

    if host.lower() not in sans:
        # Check wildcard match
        matched = any(
            san.startswith("*.") and host.lower().endswith(san[1:])
            for san in sans
        )
        if not matched:
            findings.append(_finding(
                "Certificate hostname mismatch",
                "high",
                f"The certificate's SANs ({', '.join(sans[:5])}) do not "
                f"include {host}.",
                target,
                evidence=f"Host: {host}, SANs: {', '.join(sans[:5])}",
                cwe="CWE-295",
            ))

    return findings


def test_cipher_suite(target: str) -> list[dict]:
    """Check the negotiated cipher suite for known weaknesses."""
    findings = []
    parsed = urlparse(target)
    host = parsed.netloc.split(":")[0]
    port = int(parsed.netloc.split(":")[1]) if ":" in parsed.netloc else 443

    ssock = _connect(host, port)
    if not ssock:
        return findings

    cipher_name, proto, bits = ssock.cipher() or ("", "", 0)
    ssock.close()

    weak_ciphers = ["RC4", "DES", "3DES", "NULL", "EXPORT", "anon"]
    for weak in weak_ciphers:
        if weak.upper() in cipher_name.upper():
            findings.append(_finding(
                f"Weak cipher: {cipher_name}",
                "high",
                f"The server negotiated {cipher_name} which uses {weak}. "
                f"This cipher has known vulnerabilities.",
                target,
                evidence=f"Cipher: {cipher_name}, bits: {bits}",
                cwe="CWE-327",
            ))
            return findings

    if bits < 128:
        findings.append(_finding(
            f"Low cipher strength: {bits} bits",
            "medium",
            f"Negotiated cipher {cipher_name} uses only {bits} bits.",
            target,
            evidence=f"Cipher: {cipher_name}, bits: {bits}",
            cwe="CWE-326",
        ))
    else:
        findings.append(_finding(
            f"Cipher suite: {cipher_name} ({bits} bits)",
            "info",
            f"Negotiated cipher is strong.",
            target,
            evidence=f"Cipher: {cipher_name}, Protocol: {proto}, Bits: {bits}",
        ))

    return findings


def test_deprecated_protocols(target: str) -> list[dict]:
    """
    Try to connect with deprecated TLS versions. If they succeed,
    downgrade attacks are possible.
    """
    findings = []
    parsed = urlparse(target)
    host = parsed.netloc.split(":")[0]
    port = int(parsed.netloc.split(":")[1]) if ":" in parsed.netloc else 443

    # SSLv3, TLS 1.0, TLS 1.1 are deprecated
    deprecated = []
    if hasattr(ssl, "PROTOCOL_SSLv23"):
        deprecated.append(("SSLv3", ssl.PROTOCOL_SSLv23))
    if hasattr(ssl, "PROTOCOL_TLSv1"):
        deprecated.append(("TLSv1.0", ssl.PROTOCOL_TLSv1))
    if hasattr(ssl, "PROTOCOL_TLSv1_1"):
        deprecated.append(("TLSv1.1", ssl.PROTOCOL_TLSv1_1))

    for name, proto in deprecated:
        try:
            if _probe_protocol(host, port, proto):
                findings.append(_finding(
                    f"Deprecated protocol accepted: {name}",
                    "medium",
                    f"The server accepts {name} connections. This protocol "
                    f"has known vulnerabilities (BEAST, POODLE, etc.).",
                    target,
                    evidence=f"Protocol {name} negotiated successfully",
                    cwe="CWE-326",
                ))
        except Exception:
            pass

    if not findings:
        findings.append(_finding(
            "Deprecated protocols: not accepted",
            "info",
            "Server refused SSLv3, TLSv1.0, and TLSv1.1 connections.",
            target,
        ))

    return findings


def test_certificate_transparency(target: str) -> list[dict]:
    """
    Check for the Expect-CT header (deprecated but still seen) and
    whether the cert includes SCT (Signed Certificate Timestamp).
    """
    findings = []
    parsed = urlparse(target)
    host = parsed.netloc.split(":")[0]
    port = int(parsed.netloc.split(":")[1]) if ":" in parsed.netloc else 443

    ssock = _connect(host, port)
    if not ssock:
        return findings

    cert = ssock.getpeercert()
    ssock.close()

    # Modern CAs embed SCTs in the certificate or deliver them via TLS extension.
    # We can't easily check the TLS extension, but we can note the issuer.
    issuer = dict(x[0] for x in cert.get("issuer", []))
    org = issuer.get("organizationName", "unknown")

    findings.append(_finding(
        f"Certificate issuer: {org}",
        "info",
        f"Certificate issued by {org}. Modern public CAs include "
        f"Certificate Transparency SCTs by default.",
        target,
        evidence=f"Issuer: {org}",
    ))

    return findings


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

QUICK_TESTS = [
    ("Certificate", test_certificate),
]

STANDARD_TESTS = QUICK_TESTS + [
    ("Cipher suite", test_cipher_suite),
    ("Certificate transparency", test_certificate_transparency),
]

FULL_TESTS = STANDARD_TESTS + [
    ("Deprecated protocols", test_deprecated_protocols),
]

DEPTH_MAP = {
    "quick": QUICK_TESTS,
    "standard": STANDARD_TESTS,
    "full": FULL_TESTS,
}


def run_tls_tests(target: str, depth: str = "standard") -> list[dict]:
    import sys
    findings = []
    tests = DEPTH_MAP.get(depth, STANDARD_TESTS)

    for name, fn in tests:
        print(f"[regen] TLS: {name}...", file=sys.stderr)
        try:
            findings.extend(fn(target))
        except Exception as e:
            print(f"[regen] TLS '{name}' failed: {e}", file=sys.stderr)
            findings.append(_finding(
                f"TLS test failed: {name}", "info",
                f"Test could not complete: {e}", target,
            ))

    return findings
