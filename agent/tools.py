"""
Tool registry — exposes each scanner as a callable tool for the agent.

Each tool has a name, description, parameter schema, and a run() function.
The agent picks tools based on session state; the registry validates
arguments and captures results back into the session.
"""
from __future__ import annotations

import json
import sys
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

# Ensure scanners are importable
_regen_root = str(Path(__file__).resolve().parent.parent)
if _regen_root not in sys.path:
    sys.path.insert(0, _regen_root)


@dataclass
class ToolDef:
    name: str
    description: str
    parameters: dict  # JSON Schema
    fn: Callable  # (session, **kwargs) -> list[dict]
    phase: str = "testing"  # which phase this tool belongs to


class ToolRegistry:
    def __init__(self):
        self._tools: dict[str, ToolDef] = {}

    def register(self, tool: ToolDef):
        self._tools[tool.name] = tool

    def get(self, name: str) -> ToolDef | None:
        return self._tools.get(name)

    def list_tools(self) -> list[dict]:
        """Return tool definitions in Claude tool_use format."""
        return [
            {
                "name": t.name,
                "description": t.description,
                "input_schema": t.parameters,
            }
            for t in self._tools.values()
        ]

    def tool_names(self) -> list[str]:
        return list(self._tools.keys())

    def run_tool(self, name: str, session, **kwargs) -> dict:
        tool = self._tools.get(name)
        if not tool:
            return {"error": f"Unknown tool: {name}"}
        try:
            result = tool.fn(session, **kwargs)
            return {"success": True, "result": result}
        except Exception as e:
            return {"error": str(e), "traceback": traceback.format_exc()}


def build_registry() -> ToolRegistry:
    """Create the registry with all scanner tools."""
    registry = ToolRegistry()

    # --- Recon ---
    def run_recon(session, **kwargs):
        from scanners.recon import scan_headers
        findings = scan_headers(session.target)
        for f in findings:
            if f.get("scanner") == "header-check":
                if "Server" in f.get("title", ""):
                    session.recon.server_info = f.get("evidence", "")
        session.add_findings(findings)
        return findings

    registry.register(ToolDef(
        name="recon",
        description="Reconnaissance: scan security headers, fingerprint technologies, check exposed paths. Run this first to map the attack surface.",
        parameters={
            "type": "object",
            "properties": {
                "depth": {
                    "type": "string",
                    "enum": ["quick", "standard", "full"],
                    "description": "Scan depth. Quick checks headers only; standard adds tech fingerprinting; full adds subdomain enumeration.",
                }
            },
        },
        fn=run_recon,
        phase="recon",
    ))

    # --- TLS ---
    def run_tls(session, **kwargs):
        from scanners.tls import run_tls_tests
        depth = kwargs.get("depth", session.depth)
        findings = run_tls_tests(session.target, depth)
        session.add_findings(findings)
        for f in findings:
            if f.get("scanner") == "tls":
                session.recon.tls_info[f["title"]] = f.get("evidence", "")
        return findings

    registry.register(ToolDef(
        name="tls_scan",
        description="TLS/SSL analysis: check certificate validity, cipher suites, protocol versions, and HSTS configuration.",
        parameters={
            "type": "object",
            "properties": {
                "depth": {
                    "type": "string",
                    "enum": ["quick", "standard", "full"],
                    "description": "Quick checks cert only; standard adds ciphers; full probes deprecated protocols.",
                }
            },
        },
        fn=run_tls,
        phase="recon",
    ))

    # --- Auth ---
    def run_auth(session, **kwargs):
        from scanners.auth import run_auth_tests
        depth = kwargs.get("depth", session.depth)
        findings = run_auth_tests(session.target, depth)
        session.add_findings(findings)
        session.recon.has_auth = any(
            f.get("severity") != "info" for f in findings
        )
        return findings

    registry.register(ToolDef(
        name="auth_scan",
        description="Authentication testing: check cookie security, session management, rate limiting, login error messages, and session fixation.",
        parameters={
            "type": "object",
            "properties": {
                "depth": {
                    "type": "string",
                    "enum": ["quick", "standard", "full"],
                }
            },
        },
        fn=run_auth,
        phase="testing",
    ))

    # --- Injection ---
    def run_injection(session, **kwargs):
        from scanners.injection import run_injection_tests
        depth = kwargs.get("depth", session.depth)
        findings = run_injection_tests(session.target, depth)
        session.add_findings(findings)
        return findings

    registry.register(ToolDef(
        name="injection_scan",
        description="Injection testing: XSS, SQL injection (error and timing-based), SSTI, CRLF header injection, open redirect, and command injection. Payload count scales with depth.",
        parameters={
            "type": "object",
            "properties": {
                "depth": {
                    "type": "string",
                    "enum": ["quick", "standard", "full"],
                }
            },
        },
        fn=run_injection,
        phase="testing",
    ))

    # --- SSRF ---
    def run_ssrf(session, **kwargs):
        from scanners.ssrf import run_ssrf_tests
        depth = kwargs.get("depth", session.depth)
        findings = run_ssrf_tests(session.target, depth)
        session.add_findings(findings)
        return findings

    registry.register(ToolDef(
        name="ssrf_scan",
        description="Server-Side Request Forgery testing: probe URL parameters and POST bodies for SSRF to internal services and cloud metadata endpoints (AWS, GCP, Azure).",
        parameters={
            "type": "object",
            "properties": {
                "depth": {
                    "type": "string",
                    "enum": ["quick", "standard", "full"],
                }
            },
        },
        fn=run_ssrf,
        phase="testing",
    ))

    # --- NoSQL ---
    def run_nosql(session, **kwargs):
        from scanners.nosql import run_nosql_tests
        depth = kwargs.get("depth", session.depth)
        findings = run_nosql_tests(session.target, depth)
        session.add_findings(findings)
        return findings

    registry.register(ToolDef(
        name="nosql_scan",
        description="NoSQL injection testing: MongoDB operator injection, JavaScript string injection, and authentication bypass via NoSQL operators.",
        parameters={
            "type": "object",
            "properties": {
                "depth": {
                    "type": "string",
                    "enum": ["quick", "standard", "full"],
                }
            },
        },
        fn=run_nosql,
        phase="testing",
    ))

    # --- GraphQL ---
    def run_graphql(session, **kwargs):
        from scanners.graphql import run_graphql_tests
        depth = kwargs.get("depth", session.depth)
        findings = run_graphql_tests(session.target, depth)
        session.add_findings(findings)
        # Update recon
        for f in findings:
            if "endpoint found" not in f.get("title", "").lower():
                session.recon.has_graphql = True
                break
        return findings

    registry.register(ToolDef(
        name="graphql_scan",
        description="GraphQL testing: check for exposed introspection, field suggestion leaks, query depth limits, batch query abuse, and sensitive mutations.",
        parameters={
            "type": "object",
            "properties": {
                "depth": {
                    "type": "string",
                    "enum": ["quick", "standard", "full"],
                }
            },
        },
        fn=run_graphql,
        phase="testing",
    ))

    # --- API Fuzzer ---
    def run_api(session, **kwargs):
        from scanners.api_fuzzer import run_api_tests
        depth = kwargs.get("depth", session.depth)
        findings = run_api_tests(session.target, depth)
        session.add_findings(findings)
        session.recon.has_api = any(
            f.get("severity") != "info" for f in findings
        )
        return findings

    registry.register(ToolDef(
        name="api_scan",
        description="API surface testing: method enumeration, mass assignment probes, IDOR patterns, excessive data exposure, and content-type confusion.",
        parameters={
            "type": "object",
            "properties": {
                "depth": {
                    "type": "string",
                    "enum": ["quick", "standard", "full"],
                }
            },
        },
        fn=run_api,
        phase="testing",
    ))

    # --- Exploit ---
    def run_exploit(session, **kwargs):
        from scanners.exploit import run_exploits
        findings = run_exploits(session.target)
        session.add_findings(findings)
        return findings

    registry.register(ToolDef(
        name="exploit_scan",
        description="Active exploit testing: CORS bypass, CSRF, clickjacking, CSP bypass, origin header manipulation, and cache poisoning. Non-destructive probes that test whether defenses hold.",
        parameters={
            "type": "object",
            "properties": {},
        },
        fn=run_exploit,
        phase="verification",
    ))

    # --- Dependency audit ---
    def run_deps(session, **kwargs):
        from scanners.dependency import scan_dependencies
        import tempfile
        project_dir = kwargs.get("project_dir", session.project_dir)
        if not project_dir:
            return [{"title": "No project directory", "severity": "info",
                      "description": "Dependency audit requires a local project directory (-d).",
                      "location": session.target, "scanner": "dependency"}]
        with tempfile.TemporaryDirectory() as tmp:
            findings = scan_dependencies(project_dir, tmp)
        session.add_findings(findings)
        return findings

    registry.register(ToolDef(
        name="dependency_scan",
        description="Dependency vulnerability audit: scan npm, pip, and OSV databases for known vulnerabilities in project dependencies. Requires a local project directory.",
        parameters={
            "type": "object",
            "properties": {
                "project_dir": {
                    "type": "string",
                    "description": "Path to the local project directory containing package.json, requirements.txt, etc.",
                }
            },
        },
        fn=run_deps,
        phase="testing",
    ))

    # --- Session tools (for the agent's own use) ---
    def note_to_self(session, **kwargs):
        note = kwargs.get("note", "")
        if note:
            session.scratchpad.append(note)
        return [{"note": "saved"}]

    registry.register(ToolDef(
        name="note",
        description="Save a reasoning note to the session scratchpad. Use this to record observations, hypotheses, or next-step plans between scanner runs.",
        parameters={
            "type": "object",
            "properties": {
                "note": {"type": "string", "description": "Your observation or plan."}
            },
            "required": ["note"],
        },
        fn=note_to_self,
        phase="analysis",
    ))

    def set_phase(session, **kwargs):
        phase = kwargs.get("phase", "")
        try:
            from agent.session import Phase
            session.phase = Phase(phase)
        except ValueError:
            return [{"error": f"Unknown phase: {phase}"}]
        return [{"phase": phase}]

    registry.register(ToolDef(
        name="set_phase",
        description="Transition the scan to a new phase: recon, analysis, testing, verification, remediation, or reporting.",
        parameters={
            "type": "object",
            "properties": {
                "phase": {
                    "type": "string",
                    "enum": ["recon", "analysis", "testing", "verification", "remediation", "reporting"],
                }
            },
            "required": ["phase"],
        },
        fn=set_phase,
        phase="analysis",
    ))

    def mark_false_positive(session, **kwargs):
        idx = kwargs.get("finding_index")
        reason = kwargs.get("reason", "")
        if idx is not None and 0 <= idx < len(session.findings):
            session.findings[idx].false_positive = True
            session.scratchpad.append(f"Marked finding #{idx} as false positive: {reason}")
            return [{"marked": idx, "reason": reason}]
        return [{"error": f"Invalid finding index: {idx}"}]

    registry.register(ToolDef(
        name="mark_false_positive",
        description="Mark a finding as a false positive with a reason. The finding stays in the session but is excluded from severity counts and the final report.",
        parameters={
            "type": "object",
            "properties": {
                "finding_index": {"type": "integer", "description": "Index of the finding in session.findings"},
                "reason": {"type": "string", "description": "Why this is a false positive"},
            },
            "required": ["finding_index", "reason"],
        },
        fn=mark_false_positive,
        phase="analysis",
    ))

    # --- Remediation ---
    def run_remediate(session, **kwargs):
        from agent.remediate import generate_remediation
        idx = kwargs.get("finding_index")
        if idx is None or idx < 0 or idx >= len(session.findings):
            return [{"error": f"Invalid finding index: {idx}"}]
        finding = session.findings[idx]
        remediation = generate_remediation(
            finding.to_dict(),
            technologies=session.recon.technologies,
            server=session.recon.server_info,
        )
        finding.remediation = remediation
        finding.fix_generated = True
        return [{"finding": finding.title, "remediation": remediation}]

    registry.register(ToolDef(
        name="remediate",
        description="Generate AI-powered remediation guidance for a specific finding. Produces risk explanation, concrete fix steps, and verification instructions tailored to the target's technology stack.",
        parameters={
            "type": "object",
            "properties": {
                "finding_index": {
                    "type": "integer",
                    "description": "Index of the finding in the session to generate remediation for.",
                },
            },
            "required": ["finding_index"],
        },
        fn=run_remediate,
        phase="remediation",
    ))

    # =======================================================================
    # Exploitation tools — the pentester's toolkit
    # =======================================================================

    def exploit_finding_fn(session, **kwargs):
        """Attempt to exploit a specific finding."""
        # Import all exploit modules to register them
        from agent.exploits import engine
        from agent.exploits import xss, sqli, auth, ssrf, traversal, injection, web  # noqa: F401

        idx = kwargs.get("finding_index")
        if idx is None or idx < 0 or idx >= len(session.findings):
            return [{"error": f"Invalid finding index: {idx}"}]

        finding = session.findings[idx]
        finding_dict = finding.to_dict()

        state = {
            "target": session.target,
            "recon": session.recon.to_dict(),
            "technologies": session.recon.technologies,
            "access_level": session.access_level,
        }

        attempt = engine.run_exploit(finding_dict, idx, state)
        result = attempt.to_dict()
        session.add_exploit_attempt(result)

        return [result]

    registry.register(ToolDef(
        name="exploit_finding",
        description=(
            "Attempt to exploit a specific vulnerability finding. Takes a finding "
            "by index and tries to weaponize it: escalate XSS to cookie theft, "
            "SQLi to data extraction, SSTI to RCE, auth bypass to admin access, etc. "
            "Returns proof of what an attacker can actually do."
        ),
        parameters={
            "type": "object",
            "properties": {
                "finding_index": {
                    "type": "integer",
                    "description": "Index of the finding in session.findings to exploit.",
                },
            },
            "required": ["finding_index"],
        },
        fn=exploit_finding_fn,
        phase="exploitation",
    ))

    def escalate_fn(session, **kwargs):
        """From a successful exploit, try to reach deeper access."""
        from agent.exploits import engine, http
        from agent.exploits import auth as auth_exploit  # noqa: F811

        target = session.target.rstrip("/")
        proof_parts = []
        access = session.access_level

        # Try admin paths
        from agent.exploits.engine import SENSITIVE_PATHS
        accessible = []
        for path in SENSITIVE_PATHS:
            url = target + path
            status, hdrs, body, final_url = http.get(url, timeout=5)
            if status in (200, 201, 202) and len(body) > 100:
                accessible.append((path, status, len(body)))

        if accessible:
            for path, status, size in accessible[:10]:
                proof_parts.append(f"ACCESSIBLE: {path} ({status}, {size} bytes)")
            if any("/admin" in p for p, _, _ in accessible):
                access = "admin"
            elif any("/api" in p for p, _, _ in accessible):
                if engine.access_rank(access) < 1:
                    access = "read"

        # Try to read sensitive files via known traversal
        from agent.exploits.engine import SENSITIVE_FILES
        for trav_path in SENSITIVE_FILES[:5]:
            url = f"{target}/{trav_path}"
            status, _, body, _ = http.get(url, timeout=5)
            if status == 200 and ("root:" in body or "HOME=" in body):
                proof_parts.append(f"FILE READ: {trav_path} returned server data")
                access = "read"

        result = {
            "accessible_paths": [(p, s, sz) for p, s, sz in accessible],
            "access_level": access,
            "proof": "\n".join(proof_parts) if proof_parts else "No escalation achieved.",
        }
        session.access_level = access
        session.add_exploit_attempt({
            "finding_index": -1,
            "technique": "escalation_scan",
            "target_url": target,
            "payload": "sensitive path and file probing",
            "response_summary": result["proof"],
            "success": access != "none",
            "impact": f"Access level: {access}",
            "proof": result["proof"],
            "access_gained": access,
        })
        return [result]

    registry.register(ToolDef(
        name="escalate",
        description=(
            "After a successful exploit, try to escalate access further. "
            "Probes admin paths, sensitive files, internal endpoints, and "
            "tries to reach higher privilege levels from the current position."
        ),
        parameters={
            "type": "object",
            "properties": {},
        },
        fn=escalate_fn,
        phase="exploitation",
    ))

    def map_surface_fn(session, **kwargs):
        """Map what's reachable after exploitation."""
        from agent.exploits import http
        target = session.target.rstrip("/")

        discovered = {"endpoints": [], "technologies": [], "data_exposed": []}

        # Probe common API patterns
        api_paths = [
            "/api", "/api/", "/api/v1", "/api/v2", "/api/v1/",
            "/graphql", "/api/graphql",
            "/swagger.json", "/openapi.json", "/api-docs",
            "/api/v1/users", "/api/v1/admin", "/api/v1/config",
            "/api/health", "/api/status", "/api/version",
            "/.well-known/openid-configuration",
            "/actuator", "/actuator/env", "/actuator/beans",
            "/debug/vars", "/debug/pprof",
            "/_cat/indices", "/_cluster/health",
        ]

        for path in api_paths:
            url = target + path
            status, hdrs, body, _ = http.get(url, timeout=5)
            if status in (200, 201) and len(body) > 20:
                content_type = hdrs.get("Content-Type", "")
                discovered["endpoints"].append({
                    "path": path,
                    "status": status,
                    "size": len(body),
                    "type": content_type[:50],
                    "sample": body[:200],
                })

                # Check for data exposure
                if any(x in body.lower() for x in ["email", "password", "secret",
                                                     "token", "api_key", "credit"]):
                    discovered["data_exposed"].append(path)

        # Check for technology-specific endpoints
        status, _, body, _ = http.get(target + "/")
        if "wp-content" in body:
            discovered["technologies"].append("WordPress")
        if "next/static" in body or "__next" in body:
            discovered["technologies"].append("Next.js")
        if "/_nuxt/" in body:
            discovered["technologies"].append("Nuxt.js")

        return [discovered]

    registry.register(ToolDef(
        name="map_attack_surface",
        description=(
            "After exploitation, map what else is reachable: API endpoints, "
            "debug interfaces, data exposure, internal services. Discovers "
            "new attack vectors from the current access level."
        ),
        parameters={
            "type": "object",
            "properties": {},
        },
        fn=map_surface_fn,
        phase="exploitation",
    ))

    def build_chain_fn(session, **kwargs):
        """Build an attack chain narrative from connected exploits."""
        name = kwargs.get("name", "Attack Chain")
        step_indices = kwargs.get("exploit_indices", [])
        summary = kwargs.get("impact_summary", "")

        steps = []
        for idx in step_indices:
            if 0 <= idx < len(session.exploit_attempts):
                steps.append(session.exploit_attempts[idx])

        chain = {
            "name": name,
            "steps": steps,
            "initial_finding": steps[0]["finding_index"] if steps else -1,
            "final_access": steps[-1]["access_gained"] if steps else "none",
            "impact_summary": summary,
            "proof_of_concept": "\n---\n".join(
                f"Step {i+1} ({s['technique']}): {s['proof'][:300]}"
                for i, s in enumerate(steps) if s.get("success")
            ),
        }
        session.add_attack_chain(chain)
        return [chain]

    registry.register(ToolDef(
        name="build_chain",
        description=(
            "Build an attack chain from connected exploit attempts. Links "
            "exploit steps into a narrative showing how an attacker chains "
            "vulnerabilities to achieve maximum impact."
        ),
        parameters={
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Name for this attack chain, e.g. 'XSS → Session Hijack → Admin'",
                },
                "exploit_indices": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "Indices into session.exploit_attempts to include in this chain.",
                },
                "impact_summary": {
                    "type": "string",
                    "description": "Business impact summary of this attack chain.",
                },
            },
            "required": ["name", "exploit_indices", "impact_summary"],
        },
        fn=build_chain_fn,
        phase="exploitation",
    ))

    def finish_scan(session, **kwargs):
        from datetime import datetime, timezone
        from agent.session import Phase
        session.end_time = datetime.now(timezone.utc).isoformat()
        session.phase = Phase.REPORTING
        summary = kwargs.get("summary", "")
        if summary:
            session.scratchpad.append(f"Final summary: {summary}")

        exploit_summary = {}
        if session.exploit_attempts:
            successes = [a for a in session.exploit_attempts if a.get("success")]
            exploit_summary = {
                "total_attempts": len(session.exploit_attempts),
                "successful": len(successes),
                "access_level": session.access_level,
                "chains": len(session.attack_chains),
            }

        return [{
            "status": "complete",
            "findings": session.finding_counts(),
            "exploitation": exploit_summary,
            "summary": summary,
        }]

    registry.register(ToolDef(
        name="finish",
        description="End the scan and produce the final report. Call this when all relevant scanners have run and findings have been analyzed.",
        parameters={
            "type": "object",
            "properties": {
                "summary": {"type": "string", "description": "Executive summary of the scan results."}
            },
            "required": ["summary"],
        },
        fn=finish_scan,
        phase="reporting",
    ))

    return registry
