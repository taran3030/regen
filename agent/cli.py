#!/usr/bin/env python3
"""
Regen CLI — agentic security scanner.

Usage:
  regen agent -t <url> [-p standard] [-d <dir>] [-o <dir>] [--model <model>] [--max-turns <n>]
  regen scan  -t <url> [-p standard] [-d <dir>] [-o <dir>]   (legacy pipeline)

The agent mode uses Claude to reason about what to scan and in what order.
The legacy mode runs the fixed pipeline from regen.sh.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# Ensure the regen root is on the path
_regen_root = str(Path(__file__).resolve().parent.parent)
if _regen_root not in sys.path:
    sys.path.insert(0, _regen_root)


def cmd_agent(args):
    """Run an agentic scan with Claude-driven reasoning."""
    from agent.session import Session
    from agent.loop import run_agent

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print(
            "[regen] ANTHROPIC_API_KEY not set.\n"
            "        export ANTHROPIC_API_KEY=sk-ant-...",
            file=sys.stderr,
        )
        sys.exit(1)

    session = Session(
        target=args.target,
        scope=args.scope.split(",") if args.scope else [],
        depth=args.profile,
        project_dir=args.project_dir,
    )

    result = run_agent(
        session,
        max_turns=args.max_turns,
        model=args.model,
        verbose=not args.quiet,
        output_dir=args.output,
    )

    # Print summary
    counts = result.finding_counts()
    total = sum(counts.values())
    print(f"\n{'=' * 50}")
    print(f"Regen Agent Scan Complete: {result.target}")
    print(f"{'=' * 50}")
    print(f"Findings: {total}")
    for sev in ("critical", "high", "medium", "low", "info"):
        if sev in counts:
            print(f"  {sev}: {counts[sev]}")
    print(f"Actions taken: {len(result.actions_taken)}")
    print(f"Output: {args.output}/")
    print(f"SARIF: {args.output}/regen-results.sarif.json")

    if result.has_critical_or_high():
        sys.exit(1)


def cmd_scan(args):
    """Legacy pipeline scan — calls regen.sh."""
    import subprocess
    regen_sh = Path(__file__).resolve().parent.parent / "regen.sh"
    cmd = [str(regen_sh), "scan", "-t", args.target, "-p", args.profile]
    if args.scope:
        cmd.extend(["-s", args.scope])
    if args.project_dir:
        cmd.extend(["-d", args.project_dir])
    if args.output:
        cmd.extend(["-o", args.output])
    if args.no_oast:
        cmd.append("--no-oast")
    if args.web_only:
        cmd.append("--web-only")
    subprocess.run(cmd)


def cmd_pentest(args):
    """Run a full penetration test: scan everything, then exploit everything."""
    import json
    from agent.session import Session, Phase
    from agent.tools import build_registry

    session = Session(
        target=args.target,
        scope=args.scope.split(",") if args.scope else [],
        depth=args.profile,
        project_dir=args.project_dir,
    )

    registry = build_registry()
    output_dir = args.output

    # Phase 1: Scan
    scanners = [
        "recon", "tls_scan", "auth_scan", "injection_scan",
        "ssrf_scan", "nosql_scan", "graphql_scan", "api_scan", "exploit_scan",
    ]
    print(f"\n{'='*60}", file=sys.stderr)
    print(f" REGEN PENTEST: {session.target}", file=sys.stderr)
    print(f"{'='*60}", file=sys.stderr)

    print(f"\n[1/3] SCANNING", file=sys.stderr)
    for name in scanners:
        print(f"  [{name}]", end=" ", file=sys.stderr, flush=True)
        result = registry.run_tool(name, session)
        findings = result.get("result", [])
        count = len(findings) if isinstance(findings, list) else 0
        non_info = sum(1 for f in (findings if isinstance(findings, list) else [])
                       if f.get("severity", "info") != "info")
        marker = f"({non_info} actionable)" if non_info else "(clean)"
        print(marker, file=sys.stderr)

    counts = session.finding_counts()
    total = sum(counts.values())
    print(f"\n  Scan complete: {total} findings", file=sys.stderr)
    for sev in ("critical", "high", "medium", "low"):
        if sev in counts:
            print(f"    {sev}: {counts[sev]}", file=sys.stderr)

    # Phase 2: Exploit
    session.phase = Phase.EXPLOITATION
    exploitable = [
        (i, f) for i, f in enumerate(session.findings)
        if f.severity in ("critical", "high", "medium", "low") and not f.false_positive
    ]

    print(f"\n[2/3] EXPLOITING ({len(exploitable)} targets)", file=sys.stderr)
    for idx, finding in exploitable:
        print(f"  [{idx}] {finding.title}", end=" ", file=sys.stderr, flush=True)
        result = registry.run_tool("exploit_finding", session, finding_index=idx)
        attempt = result.get("result", [{}])[0] if result.get("result") else {}
        if attempt.get("success"):
            access = attempt.get("access_gained", "none")
            print(f"=> EXPLOITED (access: {access})", file=sys.stderr)
        else:
            print(f"=> defended", file=sys.stderr)

    # Also run escalation and surface mapping
    print(f"\n  Escalating...", end=" ", file=sys.stderr, flush=True)
    registry.run_tool("escalate", session)
    print(f"access: {session.access_level}", file=sys.stderr)

    print(f"  Mapping attack surface...", end=" ", file=sys.stderr, flush=True)
    surface = registry.run_tool("map_attack_surface", session)
    endpoints = surface.get("result", [{}])[0].get("endpoints", []) if surface.get("result") else []
    print(f"{len(endpoints)} endpoints discovered", file=sys.stderr)

    # Phase 3: Report
    session.phase = Phase.REPORTING
    print(f"\n[3/3] REPORT", file=sys.stderr)
    print(f"{'='*60}", file=sys.stderr)

    # Summary
    exploit_successes = [a for a in session.exploit_attempts if a.get("success")]
    print(f"  Target: {session.target}", file=sys.stderr)
    print(f"  Findings: {total}", file=sys.stderr)
    print(f"  Exploit attempts: {len(session.exploit_attempts)}", file=sys.stderr)
    print(f"  Successful exploits: {len(exploit_successes)}", file=sys.stderr)
    print(f"  Highest access: {session.access_level}", file=sys.stderr)

    if exploit_successes:
        print(f"\n  Proven exploits:", file=sys.stderr)
        for a in exploit_successes:
            print(f"    [{a['technique']}] {a['impact'][:80]}", file=sys.stderr)

    # Save
    session.end_time = __import__("datetime").datetime.now(
        __import__("datetime").timezone.utc
    ).isoformat()
    session.save(output_dir)
    print(f"\n  Results: {output_dir}/session.json", file=sys.stderr)

    if session.has_critical_or_high() or session.access_level != "none":
        print(f"\n  EXIT CODE 1: exploitable vulnerabilities found.", file=sys.stderr)
        sys.exit(1)
    else:
        print(f"\n  EXIT CODE 0: no exploitable vulnerabilities.", file=sys.stderr)


def cmd_deep(args):
    """Run the deep manual pentest (10-phase red team beyond automated scanners)."""
    scripts_dir = Path(__file__).resolve().parent.parent / "scripts"
    sys.path.insert(0, str(scripts_dir))
    from deep_pentest import run_deep_pentest
    run_deep_pentest(args.target, output_dir=args.output)


def cmd_azure(args):
    """Run the zero-knowledge Azure infrastructure breach attempt."""
    scripts_dir = Path(__file__).resolve().parent.parent / "scripts"
    sys.path.insert(0, str(scripts_dir))
    from azure_breach import run_azure_breach
    run_azure_breach(args.target, output_dir=args.output)


def cmd_full(args):
    """Run all three test modes: pentest + deep + azure. The CI/CD pipeline command."""
    import json
    from datetime import datetime, timezone

    output_base = args.output
    target = args.target
    start = datetime.now(timezone.utc)

    print(f"\n{'='*60}", file=sys.stderr)
    print(f" REGEN FULL ASSESSMENT: {target}", file=sys.stderr)
    print(f" Started: {start.isoformat()}", file=sys.stderr)
    print(f"{'='*60}", file=sys.stderr)

    results = {"target": target, "start": start.isoformat(), "modes": {}}
    exit_code = 0

    # Mode 1: Automated pentest (scan + exploit)
    print(f"\n--- MODE 1/3: AUTOMATED PENTEST ---", file=sys.stderr)
    try:
        args.output = f"{output_base}/pentest"
        cmd_pentest(args)
    except SystemExit as e:
        if e.code:
            exit_code = 1
        results["modes"]["pentest"] = {"exit_code": e.code or 0}
    else:
        results["modes"]["pentest"] = {"exit_code": 0}

    # Mode 2: Deep manual pentest
    print(f"\n--- MODE 2/3: DEEP PENTEST ---", file=sys.stderr)
    scripts_dir = Path(__file__).resolve().parent.parent / "scripts"
    sys.path.insert(0, str(scripts_dir))
    from deep_pentest import run_deep_pentest
    deep_rpt = run_deep_pentest(target, output_dir=f"{output_base}/deep")
    if deep_rpt.findings:
        exit_code = 1
    results["modes"]["deep"] = {
        "attempts": len(deep_rpt.attempts),
        "breaches": len(deep_rpt.findings),
    }

    # Mode 3: Azure infrastructure (only for Azure-hosted sites)
    from azure_breach import run_azure_breach
    print(f"\n--- MODE 3/3: AZURE BREACH ---", file=sys.stderr)
    az_rpt = run_azure_breach(target, output_dir=f"{output_base}/azure")
    if az_rpt.findings:
        exit_code = 1
    results["modes"]["azure"] = {
        "attempts": len(az_rpt.attempts),
        "breaches": len(az_rpt.findings),
    }

    # Summary
    end = datetime.now(timezone.utc)
    results["end"] = end.isoformat()
    results["duration_seconds"] = (end - start).total_seconds()
    results["exit_code"] = exit_code

    summary_path = f"{output_base}/full-assessment.json"
    Path(summary_path).parent.mkdir(parents=True, exist_ok=True)
    with open(summary_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n{'='*60}", file=sys.stderr)
    print(f" FULL ASSESSMENT COMPLETE", file=sys.stderr)
    print(f" Duration: {results['duration_seconds']:.0f}s", file=sys.stderr)
    print(f" Results: {summary_path}", file=sys.stderr)
    print(f"{'='*60}", file=sys.stderr)

    if exit_code:
        sys.exit(1)


def cmd_tools(args):
    """List available scanner tools."""
    from agent.tools import build_registry
    registry = build_registry()
    for t in registry.list_tools():
        print(f"  {t['name']:20s} {t['description'][:70]}")


def main():
    parser = argparse.ArgumentParser(
        prog="regen",
        description="Regen — LLM-native defensive security scanner by Axolotl Labs",
    )
    sub = parser.add_subparsers(dest="command")

    # --- agent ---
    p_agent = sub.add_parser("agent", help="Run an agentic scan (Claude-driven)")
    p_agent.add_argument("-t", "--target", required=True, help="Target URL")
    p_agent.add_argument("-s", "--scope", default="", help="Comma-separated allowed domains")
    p_agent.add_argument("-p", "--profile", default="standard", choices=["quick", "standard", "full"])
    p_agent.add_argument("-d", "--project-dir", default=None, help="Local project dir for dep audit")
    p_agent.add_argument("-o", "--output", default="./regen-results", help="Output directory")
    p_agent.add_argument("--model", default="claude-sonnet-4-20250514", help="Claude model to use")
    p_agent.add_argument("--max-turns", type=int, default=25, help="Max agent turns")
    p_agent.add_argument("-q", "--quiet", action="store_true", help="Suppress verbose output")
    p_agent.set_defaults(func=cmd_agent)

    # --- scan (legacy) ---
    p_scan = sub.add_parser("scan", help="Run a pipeline scan (legacy)")
    p_scan.add_argument("-t", "--target", required=True)
    p_scan.add_argument("-s", "--scope", default="")
    p_scan.add_argument("-p", "--profile", default="standard", choices=["quick", "standard", "full"])
    p_scan.add_argument("-d", "--project-dir", default=None)
    p_scan.add_argument("-o", "--output", default="./regen-results")
    p_scan.add_argument("--no-oast", action="store_true")
    p_scan.add_argument("--web-only", action="store_true")
    p_scan.set_defaults(func=cmd_scan)

    # --- pentest ---
    p_pentest = sub.add_parser("pentest", help="Full penetration test: scan + exploit + report")
    p_pentest.add_argument("-t", "--target", required=True, help="Target URL")
    p_pentest.add_argument("-s", "--scope", default="", help="Comma-separated allowed domains")
    p_pentest.add_argument("-p", "--profile", default="standard", choices=["quick", "standard", "full"])
    p_pentest.add_argument("-d", "--project-dir", default=None, help="Local project dir for dep audit")
    p_pentest.add_argument("-o", "--output", default="./regen-pentest", help="Output directory")
    p_pentest.set_defaults(func=cmd_pentest)

    # --- deep (manual red team) ---
    p_deep = sub.add_parser("deep", help="Deep manual pentest (10-phase red team)")
    p_deep.add_argument("-t", "--target", required=True, help="Target URL")
    p_deep.add_argument("-o", "--output", default="./deep-pentest", help="Output directory")
    p_deep.set_defaults(func=cmd_deep)

    # --- azure (infrastructure breach) ---
    p_azure = sub.add_parser("azure", help="Zero-knowledge Azure infrastructure breach attempt")
    p_azure.add_argument("-t", "--target", required=True, help="Target URL")
    p_azure.add_argument("-o", "--output", default="./azure-breach", help="Output directory")
    p_azure.set_defaults(func=cmd_azure)

    # --- full (all three modes) ---
    p_full = sub.add_parser("full", help="Full assessment: pentest + deep + azure (CI/CD pipeline)")
    p_full.add_argument("-t", "--target", required=True, help="Target URL")
    p_full.add_argument("-s", "--scope", default="", help="Comma-separated allowed domains")
    p_full.add_argument("-p", "--profile", default="standard", choices=["quick", "standard", "full"])
    p_full.add_argument("-d", "--project-dir", default=None, help="Local project dir for dep audit")
    p_full.add_argument("-o", "--output", default="./regen-full", help="Output directory")
    p_full.set_defaults(func=cmd_full)

    # --- tools ---
    p_tools = sub.add_parser("tools", help="List available scanner tools")
    p_tools.set_defaults(func=cmd_tools)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
