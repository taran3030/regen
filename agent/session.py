"""
Scan session — carries state across the agentic loop.

A session starts with a target and scope, accumulates recon data, findings,
and decisions, and ends with a structured report. The agent reads from and
writes to the session at every step.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional


class Phase(str, Enum):
    RECON = "recon"
    ANALYSIS = "analysis"
    TESTING = "testing"
    EXPLOITATION = "exploitation"
    ESCALATION = "escalation"
    VERIFICATION = "verification"
    REMEDIATION = "remediation"
    REPORTING = "reporting"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    title: str
    severity: str
    description: str
    location: str
    scanner: str
    evidence: str = ""
    remediation: str = ""
    cwe: Optional[str] = None
    verified: bool = False
    false_positive: bool = False
    fix_generated: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ReconData:
    """Attack surface information gathered during reconnaissance."""
    headers: dict[str, str] = field(default_factory=dict)
    technologies: list[str] = field(default_factory=list)
    exposed_paths: list[str] = field(default_factory=list)
    api_endpoints: list[str] = field(default_factory=list)
    has_graphql: bool = False
    has_api: bool = False
    has_auth: bool = False
    has_forms: bool = False
    server_info: str = ""
    tls_info: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    def summary(self) -> str:
        lines = []
        if self.technologies:
            lines.append(f"Technologies: {', '.join(self.technologies)}")
        if self.server_info:
            lines.append(f"Server: {self.server_info}")
        if self.exposed_paths:
            lines.append(f"Exposed paths: {', '.join(self.exposed_paths[:10])}")
        if self.api_endpoints:
            lines.append(f"API endpoints: {', '.join(self.api_endpoints[:10])}")
        lines.append(f"GraphQL: {self.has_graphql}, API: {self.has_api}, Auth: {self.has_auth}")
        if self.notes:
            lines.append(f"Notes: {'; '.join(self.notes)}")
        return "\n".join(lines) if lines else "No recon data yet."


@dataclass
class Session:
    """Mutable state that travels through the entire scan."""
    target: str
    scope: list[str] = field(default_factory=list)
    depth: str = "standard"
    project_dir: Optional[str] = None

    # State
    phase: Phase = Phase.RECON
    recon: ReconData = field(default_factory=ReconData)
    findings: list[Finding] = field(default_factory=list)
    actions_taken: list[dict] = field(default_factory=list)
    messages: list[dict] = field(default_factory=list)

    # Timing
    start_time: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    end_time: Optional[str] = None

    # Agent memory — the LLM can store reasoning here between turns
    scratchpad: list[str] = field(default_factory=list)

    # Exploitation state
    exploit_attempts: list[dict] = field(default_factory=list)
    attack_chains: list[dict] = field(default_factory=list)
    access_level: str = "none"

    def add_finding(self, finding: Finding):
        self.findings.append(finding)

    def add_findings(self, findings: list[dict]):
        for f in findings:
            self.findings.append(Finding(**{
                k: v for k, v in f.items()
                if k in Finding.__dataclass_fields__
            }))

    def log_action(self, tool: str, args: dict, result_summary: str):
        self.actions_taken.append({
            "tool": tool,
            "args": args,
            "result": result_summary,
            "time": datetime.now(timezone.utc).isoformat(),
        })

    def finding_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            if not f.false_positive:
                counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def has_critical_or_high(self) -> bool:
        return any(
            f.severity in ("critical", "high") and not f.false_positive
            for f in self.findings
        )

    def add_exploit_attempt(self, attempt: dict):
        self.exploit_attempts.append(attempt)
        from .exploits.engine import access_rank
        if access_rank(attempt.get("access_gained", "none")) > access_rank(self.access_level):
            self.access_level = attempt["access_gained"]

    def add_attack_chain(self, chain: dict):
        self.attack_chains.append(chain)

    def state_summary(self) -> str:
        """Compact summary the agent sees at each turn."""
        counts = self.finding_counts()
        count_str = ", ".join(f"{s}: {n}" for s, n in counts.items()) or "none"
        lines = [
            f"Target: {self.target}",
            f"Phase: {self.phase.value}",
            f"Depth: {self.depth}",
            f"Findings: {count_str}",
            f"Actions taken: {len(self.actions_taken)}",
        ]
        if self.exploit_attempts:
            successes = sum(1 for a in self.exploit_attempts if a.get("success"))
            lines.append(f"Exploit attempts: {len(self.exploit_attempts)} ({successes} successful)")
            lines.append(f"Access level: {self.access_level}")
        if self.attack_chains:
            lines.append(f"Attack chains: {len(self.attack_chains)}")
        if self.recon.technologies or self.recon.server_info:
            lines.append(f"Recon: {self.recon.summary()}")
        if self.scratchpad:
            lines.append(f"Notes: {self.scratchpad[-1]}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "scope": self.scope,
            "depth": self.depth,
            "phase": self.phase.value,
            "recon": self.recon.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "actions_taken": self.actions_taken,
            "finding_counts": self.finding_counts(),
            "exploit_attempts": self.exploit_attempts,
            "attack_chains": self.attack_chains,
            "access_level": self.access_level,
            "start_time": self.start_time,
            "end_time": self.end_time,
        }

    def save(self, output_dir: str):
        path = Path(output_dir)
        path.mkdir(parents=True, exist_ok=True)
        with open(path / "session.json", "w") as f:
            json.dump(self.to_dict(), f, indent=2)
