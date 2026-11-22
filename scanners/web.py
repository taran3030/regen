"""
Web vulnerability scanner.

Wraps nuclei for template-based vulnerability detection
against web targets.
"""
import json
import subprocess
from pathlib import Path


def scan_web(target: str, output_dir: str, templates: list[str] = None, severity: str = "medium,high,critical") -> list[dict]:
    """Run nuclei against a web target."""
    findings = []
    out_file = Path(output_dir) / "nuclei-output.jsonl"

    cmd = [
        "nuclei",
        "-target", target,
        "-jsonl",
        "-output", str(out_file),
        "-severity", severity,
        "-silent",
    ]
    if templates:
        for t in templates:
            cmd.extend(["-t", t])

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

    if out_file.exists():
        for line in out_file.read_text().strip().split("\n"):
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            findings.append({
                "title": entry.get("info", {}).get("name", "Unknown"),
                "severity": entry.get("info", {}).get("severity", "medium"),
                "description": entry.get("info", {}).get("description", ""),
                "location": entry.get("matched-at", target),
                "scanner": "nuclei",
                "evidence": entry.get("extracted-results", entry.get("matcher-name", "")),
                "remediation": entry.get("info", {}).get("remediation", ""),
                "cwe": _extract_cwe(entry),
            })
    return findings


def _extract_cwe(entry: dict) -> str:
    classification = entry.get("info", {}).get("classification", {})
    cwe_ids = classification.get("cwe-id", [])
    return cwe_ids[0] if cwe_ids else None
