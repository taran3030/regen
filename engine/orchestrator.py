"""
Regen scan orchestrator.

Drives the adversarial testing loop:
  1. Reconnaissance - map the attack surface
  2. Planning - choose test strategies based on findings
  3. Execution - run scanners against identified targets
  4. Analysis - interpret results, deduplicate, assess severity
  5. Reporting - produce SARIF + human-readable findings
"""
import json
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

VERSION = (Path(__file__).resolve().parent.parent / "VERSION").read_text().strip()


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    title: str
    severity: Severity
    description: str
    location: str
    scanner: str
    evidence: str = ""
    remediation: str = ""
    cwe: Optional[str] = None
    cvss: Optional[float] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_sarif_result(self):
        result = {
            "ruleId": f"regen/{self.scanner}/{self.title.lower().replace(chr(32), '-')}",
            "level": "error" if self.severity in (Severity.CRITICAL, Severity.HIGH) else "warning" if self.severity == Severity.MEDIUM else "note",
            "message": {"text": self.description},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": self.location}
                }
            }],
            "properties": {
                "severity": self.severity.value,
                "scanner": self.scanner,
                "evidence": self.evidence,
                "remediation": self.remediation,
            }
        }
        if self.cwe:
            result["taxa"] = [{"toolComponent": {"name": "cwe"}, "id": self.cwe}]
        return result


@dataclass
class ScanConfig:
    target: str
    scope: list[str] = field(default_factory=list)
    scan_types: list[str] = field(default_factory=lambda: ["recon", "vuln", "dependency"])
    output_dir: str = "./regen-results"
    timeout_minutes: int = 30


@dataclass
class ScanResult:
    config: ScanConfig
    findings: list[Finding] = field(default_factory=list)
    start_time: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    end_time: Optional[str] = None
    status: str = "running"
    scanner_outputs: dict = field(default_factory=dict)

    def to_sarif(self) -> dict:
        return {
            "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Regen",
                        "organization": "Axolotl Labs",
                        "version": VERSION,
                        "semanticVersion": VERSION,
                    }
                },
                "results": [f.to_sarif_result() for f in self.findings],
                "invocations": [{
                    "executionSuccessful": self.status == "complete",
                    "startTimeUtc": self.start_time,
                    "endTimeUtc": self.end_time or datetime.now(timezone.utc).isoformat(),
                    "properties": {
                        "target": self.config.target,
                        "scope": self.config.scope,
                        "scan_types": self.config.scan_types,
                    }
                }]
            }]
        }

    def summary(self) -> str:
        counts = {}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        lines = [
            f"Regen Scan: {self.config.target}",
            f"Status: {self.status}",
            f"Findings: {len(self.findings)} total",
        ]
        for sev in Severity:
            if sev.value in counts:
                lines.append(f"  {sev.value}: {counts[sev.value]}")
        return "\n".join(lines)


class ScanOrchestrator:
    """Coordinates scanners and aggregates findings."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.result = ScanResult(config=config)
        self.output_dir = Path(config.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def run_scanner(self, scanner_name: str, cmd: list[str], timeout: int = 300) -> dict:
        print(f"[regen] Running {scanner_name}...", file=sys.stderr)
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
            )
            output = {
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "returncode": proc.returncode,
            }
            self.result.scanner_outputs[scanner_name] = output
            return output
        except subprocess.TimeoutExpired:
            return {"stdout": "", "stderr": f"Timeout after {timeout}s", "returncode": -1}
        except FileNotFoundError:
            return {"stdout": "", "stderr": f"{cmd[0]} not found", "returncode": -1}

    def add_finding(self, finding: Finding):
        self.result.findings.append(finding)

    def save_results(self):
        self.result.end_time = datetime.now(timezone.utc).isoformat()
        self.result.status = "complete"

        sarif_path = self.output_dir / "regen-results.sarif.json"
        with open(sarif_path, "w") as f:
            json.dump(self.result.to_sarif(), f, indent=2)

        summary_path = self.output_dir / "regen-summary.txt"
        with open(summary_path, "w") as f:
            f.write(self.result.summary())

        findings_path = self.output_dir / "regen-findings.json"
        with open(findings_path, "w") as f:
            json.dump([asdict(finding) for finding in self.result.findings], f, indent=2)

        print(f"[regen] Results saved to {self.output_dir}/", file=sys.stderr)
        return sarif_path
