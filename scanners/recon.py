"""
Reconnaissance scanner.

Maps the attack surface of a web target:
- HTTP headers and security headers analysis
- Technology fingerprinting
- Subdomain enumeration (if in scope)
- Port scanning (common web ports)
"""
import json
import re
import subprocess
import urllib.request
import urllib.error
import ssl
from pathlib import Path


SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]


def scan_headers(target: str) -> list[dict]:
    """Check for missing security headers."""
    findings = []
    ctx = ssl.create_default_context()
    try:
        req = urllib.request.Request(target, method="HEAD")
        req.add_header("User-Agent", "Regen/0.1 (Axolotl Labs Security Scanner)")
        resp = urllib.request.urlopen(req, timeout=10, context=ctx)
        headers = {k.lower(): v for k, v in resp.headers.items()}
    except Exception as e:
        return [{
            "title": "Target unreachable",
            "severity": "info",
            "description": f"Could not connect to {target}: {e}",
            "location": target,
            "scanner": "header-check",
            "evidence": str(e),
            "remediation": "Verify the target URL is correct and accessible",
        }]

    for header in SECURITY_HEADERS:
        if header.lower() not in headers:
            findings.append({
                "title": f"Missing security header: {header}",
                "severity": "medium" if header in ("Strict-Transport-Security", "Content-Security-Policy") else "low",
                "description": f"The {header} header is not set on {target}",
                "location": target,
                "scanner": "header-check",
                "evidence": f"Header {header} absent from response",
                "remediation": f"Add the {header} header to your server configuration",
            })

    server = headers.get("server", "")
    if server and any(v in server.lower() for v in ["apache/", "nginx/", "iis/"]):
        findings.append({
            "title": "Server version disclosure",
            "severity": "low",
            "description": f"Server header reveals version: {server}",
            "location": target,
            "scanner": "header-check",
            "evidence": f"Server: {server}",
            "remediation": "Remove or genericize the Server header",
        })

    return findings


def scan_ports(target: str, output_dir: str) -> list[dict]:
    """Run nmap against common web ports."""
    findings = []
    domain = re.sub(r"https?://", "", target).split("/")[0].split(":")[0]
    out_file = Path(output_dir) / "nmap-output.xml"

    result = subprocess.run(
        ["nmap", "-sV", "--top-ports", "100", "-oX", str(out_file), domain],
        capture_output=True, text=True, timeout=120,
    )

    if out_file.exists():
        content = out_file.read_text()
        open_ports = re.findall(
            r'<port protocol="(\w+)" portid="(\d+)">.*?<state state="open".*?<service name="(\w+)".*?/>',
            content, re.DOTALL
        )
        for proto, port, service in open_ports:
            if int(port) not in (80, 443):
                findings.append({
                    "title": f"Open port: {port}/{proto} ({service})",
                    "severity": "info",
                    "description": f"Port {port}/{proto} is open running {service}",
                    "location": f"{domain}:{port}",
                    "scanner": "nmap",
                    "evidence": f"{proto}/{port} open {service}",
                    "remediation": f"Verify port {port} should be publicly accessible",
                })

    return findings
