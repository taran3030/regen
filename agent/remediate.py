"""
Remediation engine — generates fix suggestions using Claude.

Given a finding from any scanner, this module asks Claude to produce:
1. A plain-language explanation of the risk
2. Specific remediation steps
3. Code snippets or configuration changes when applicable

This is a tool the agent can invoke for any finding it wants to
provide remediation for, or it can be called standalone on a SARIF file.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Optional


REMEDIATION_PROMPT = """\
You are a security engineer writing remediation guidance for a vulnerability finding.

Finding:
  Title: {title}
  Severity: {severity}
  Scanner: {scanner}
  Location: {location}
  Description: {description}
  Evidence: {evidence}
  CWE: {cwe}

Target context:
  Technologies: {technologies}
  Server: {server}

Write a concise remediation that includes:
1. RISK — one sentence on what an attacker can do with this.
2. FIX — specific steps to fix it. If it's a header, give the header value. If it's code, give the code change. If it's config, give the config.
3. VERIFY — how to confirm the fix worked.

Be specific to the technology stack. Don't give generic advice.
Keep it under 300 words.\
"""


def generate_remediation(
    finding: dict,
    technologies: list[str] | None = None,
    server: str = "",
    model: str = "claude-sonnet-4-20250514",
) -> str:
    """Generate remediation guidance for a single finding."""
    try:
        import anthropic
        client = anthropic.Anthropic()
    except ImportError:
        return "Install the anthropic package for AI-generated remediation: pip install anthropic"
    except Exception as e:
        return f"Could not create Anthropic client: {e}"

    prompt = REMEDIATION_PROMPT.format(
        title=finding.get("title", ""),
        severity=finding.get("severity", ""),
        scanner=finding.get("scanner", ""),
        location=finding.get("location", ""),
        description=finding.get("description", ""),
        evidence=finding.get("evidence", ""),
        cwe=finding.get("cwe", "N/A"),
        technologies=", ".join(technologies or []),
        server=server,
    )

    response = client.messages.create(
        model=model,
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}],
    )

    return response.content[0].text


def remediate_findings(
    findings: list[dict],
    technologies: list[str] | None = None,
    server: str = "",
    model: str = "claude-sonnet-4-20250514",
    min_severity: str = "low",
) -> list[dict]:
    """Generate remediation for all findings at or above min_severity."""
    severity_order = ["info", "low", "medium", "high", "critical"]
    min_idx = severity_order.index(min_severity) if min_severity in severity_order else 0

    results = []
    for f in findings:
        sev = f.get("severity", "info").lower()
        if severity_order.index(sev) < min_idx:
            continue
        if f.get("false_positive"):
            continue

        remediation = generate_remediation(f, technologies, server, model)
        results.append({
            **f,
            "remediation_ai": remediation,
        })

    return results


def remediate_sarif(
    sarif_path: str,
    output_path: Optional[str] = None,
    model: str = "claude-sonnet-4-20250514",
    min_severity: str = "medium",
) -> str:
    """Read a SARIF file, generate remediation for findings, write enriched output."""
    with open(sarif_path) as f:
        sarif = json.load(f)

    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            sev = result.get("properties", {}).get("severity", "info").lower()
            severity_order = ["info", "low", "medium", "high", "critical"]
            if severity_order.index(sev) < severity_order.index(min_severity):
                continue

            finding = {
                "title": result.get("ruleId", "").split("/")[-1],
                "severity": sev,
                "scanner": result.get("properties", {}).get("scanner", ""),
                "location": result.get("locations", [{}])[0]
                    .get("physicalLocation", {})
                    .get("artifactLocation", {})
                    .get("uri", ""),
                "description": result.get("message", {}).get("text", ""),
                "evidence": result.get("properties", {}).get("evidence", ""),
                "cwe": (result.get("taxa", [{}])[0].get("id", "")
                        if result.get("taxa") else ""),
            }

            remediation = generate_remediation(finding, model=model)
            if "properties" not in result:
                result["properties"] = {}
            result["properties"]["remediation_ai"] = remediation

    out = output_path or sarif_path.replace(".sarif.json", "-remediated.sarif.json")
    with open(out, "w") as f:
        json.dump(sarif, f, indent=2)

    return out
