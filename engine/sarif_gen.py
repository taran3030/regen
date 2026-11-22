#!/usr/bin/env python3
"""Generate SARIF from Regen scan results directory.

Usage: python3 sarif_gen.py <results_dir> <target_url>

Reads nuclei JSONL, npm-audit JSON, osv-scanner JSON, and text outputs
from the results directory and produces a unified SARIF file.
"""
import json
import re
import sys
from pathlib import Path
from datetime import datetime, timezone


def parse_nuclei(results_dir: Path) -> list[dict]:
    findings = []
    jsonl = results_dir / "nuclei-results.jsonl"
    if not jsonl.exists():
        return findings
    with open(jsonl) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            info = r.get("info", {})
            sev = info.get("severity", "info").lower()
            level = "error" if sev in ("critical", "high") else "warning" if sev == "medium" else "note"
            cwes = info.get("classification", {}).get("cwe-id", [])
            result = {
                "ruleId": f"regen/nuclei/{info.get('name', 'unknown').lower().replace(' ', '-')}",
                "level": level,
                "message": {"text": info.get("description", info.get("name", ""))},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": r.get("matched-at", "")}}}],
                "properties": {
                    "severity": sev,
                    "scanner": "nuclei",
                    "template": r.get("template-id", ""),
                    "remediation": info.get("remediation", ""),
                },
            }
            if cwes:
                result["taxa"] = [{"toolComponent": {"name": "cwe"}, "id": c} for c in cwes]
            findings.append(result)
    return findings


def parse_npm_audit(results_dir: Path) -> list[dict]:
    findings = []
    audit_file = results_dir / "npm-audit.json"
    if not audit_file.exists():
        return findings
    with open(audit_file) as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            return findings
    for name, vuln in data.get("vulnerabilities", {}).items():
        sev = vuln.get("severity", "info").lower()
        level = "error" if sev in ("critical", "high") else "warning" if sev == "medium" else "note"
        findings.append({
            "ruleId": f"regen/npm-audit/{name}",
            "level": level,
            "message": {"text": f"Vulnerable dependency: {name} ({vuln.get('range', '')})"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "package.json"}}}],
            "properties": {
                "severity": sev,
                "scanner": "npm-audit",
                "fixAvailable": str(vuln.get("fixAvailable", False)),
            },
        })
    return findings


def parse_osv(results_dir: Path) -> list[dict]:
    findings = []
    osv_file = results_dir / "osv-results.json"
    if not osv_file.exists():
        return findings
    with open(osv_file) as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            return findings
    for result in data.get("results", []):
        source = result.get("source", {}).get("path", "")
        for pkg in result.get("packages", []):
            pkg_info = pkg.get("package", {})
            for vuln in pkg.get("vulnerabilities", []):
                vuln_id = vuln.get("id", "unknown")
                sev_list = vuln.get("database_specific", {}).get("severity", "MODERATE")
                sev = sev_list.lower() if isinstance(sev_list, str) else "medium"
                sev = {"moderate": "medium"}.get(sev, sev)
                level = "error" if sev in ("critical", "high") else "warning" if sev == "medium" else "note"
                findings.append({
                    "ruleId": f"regen/osv/{vuln_id}",
                    "level": level,
                    "message": {"text": vuln.get("summary", vuln_id)},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": source}}}],
                    "properties": {
                        "severity": sev,
                        "scanner": "osv-scanner",
                        "package": f"{pkg_info.get('name', '')}@{pkg_info.get('version', '')}",
                        "aliases": vuln.get("aliases", []),
                    },
                })
    return findings


def parse_headers(results_dir: Path, target: str) -> list[dict]:
    findings = []
    headers_file = results_dir / "headers.txt"
    if not headers_file.exists():
        return findings
    text = headers_file.read_text()
    for line in text.splitlines():
        if line.startswith("[") and "Missing:" in line:
            sev_match = line.split("]")[0].lstrip("[")
            header_name = line.split("Missing:")[-1].strip()
            sev = sev_match.lower()
            level = "error" if sev == "high" else "warning" if sev == "medium" else "note"
            findings.append({
                "ruleId": f"regen/headers/missing-{header_name.lower()}",
                "level": level,
                "message": {"text": f"Missing security header: {header_name}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": target}}}],
                "properties": {"severity": sev, "scanner": "headers"},
            })
    return findings


def parse_exposed_paths(results_dir: Path) -> list[dict]:
    findings = []
    paths_file = results_dir / "exposed-paths.txt"
    if not paths_file.exists():
        return findings
    for line in paths_file.read_text().splitlines():
        m = re.match(r"\[(\w+)\] \[(\d{3})\] (\S+)", line)
        if not m:
            continue
        sev, code, url = m.group(1).lower(), m.group(2), m.group(3)
        if sev == "info":
            continue
        level = "error" if sev in ("critical", "high") else "warning" if sev == "medium" else "note"
        findings.append({
            "ruleId": f"regen/paths/exposed-{url.rsplit('/', 1)[-1].lower() or 'root'}",
            "level": level,
            "message": {"text": f"Path answers {code} and shouldn't be public: {url}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": url}}}],
            "properties": {"severity": sev, "scanner": "paths"},
        })
    return findings


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <results_dir> <target_url>", file=sys.stderr)
        sys.exit(1)

    results_dir = Path(sys.argv[1])
    target = sys.argv[2]

    all_findings = []
    all_findings.extend(parse_headers(results_dir, target))
    all_findings.extend(parse_exposed_paths(results_dir))
    all_findings.extend(parse_npm_audit(results_dir))
    all_findings.extend(parse_osv(results_dir))
    all_findings.extend(parse_nuclei(results_dir))

    sarif = {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Regen",
                    "organization": "Axolotl Labs",
                    "version": "0.1.0",
                    "semanticVersion": "0.1.0",
                }
            },
            "results": all_findings,
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                "properties": {"target": target},
            }]
        }]
    }

    output_path = results_dir / "regen-results.sarif.json"
    with open(output_path, "w") as f:
        json.dump(sarif, f, indent=2)

    print(f"[regen] SARIF report: {output_path} ({len(all_findings)} findings)")


if __name__ == "__main__":
    main()
