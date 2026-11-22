"""
Dependency vulnerability scanner.

Checks package manifests (package.json, requirements.txt, go.sum, etc.)
against known vulnerability databases using osv-scanner.
"""
import json
import subprocess
from pathlib import Path


def scan_dependencies(project_dir: str, output_dir: str) -> list[dict]:
    """Run osv-scanner against a project directory."""
    findings = []
    result = subprocess.run(
        ["osv-scanner", "--json", "--recursive", project_dir],
        capture_output=True, text=True,
    )
    if result.returncode != 0 and not result.stdout:
        return findings

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return findings

    for vuln_result in data.get("results", []):
        source = vuln_result.get("source", {}).get("path", "unknown")
        for package in vuln_result.get("packages", []):
            pkg_info = package.get("package", {})
            pkg_name = pkg_info.get("name", "unknown")
            pkg_version = pkg_info.get("version", "unknown")
            for vuln in package.get("vulnerabilities", []):
                severity_data = vuln.get("database_specific", {}).get("severity", "MODERATE")
                findings.append({
                    "title": f"Vulnerable dependency: {pkg_name}@{pkg_version}",
                    "severity": _map_severity(severity_data),
                    "description": vuln.get("summary", vuln.get("id", "Unknown vulnerability")),
                    "location": source,
                    "scanner": "osv-scanner",
                    "evidence": f"Package: {pkg_name}@{pkg_version}, ID: {vuln.get('id', 'N/A')}",
                    "remediation": _get_fix(vuln),
                    "cwe": None,
                })
    return findings


def _map_severity(sev: str) -> str:
    mapping = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "LOW": "low"}
    return mapping.get(sev.upper(), "medium")


def _get_fix(vuln: dict) -> str:
    for affected in vuln.get("affected", []):
        for r in affected.get("ranges", []):
            for event in r.get("events", []):
                if "fixed" in event:
                    return f"Upgrade to {event['fixed']}"
    return "Check advisory for fix version"
