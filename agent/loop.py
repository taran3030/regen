"""
Agent loop — the LLM-native reasoning core of Regen.

Sends the session state and tool definitions to Claude, lets it pick
which scanner to run next based on what it's learned, executes the tool,
feeds results back, and repeats until the agent calls finish().

The loop is the brain. The scanners are the hands.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Optional

from .session import Session, Phase
from .tools import ToolRegistry, build_registry

VERSION = (Path(__file__).resolve().parent.parent / "VERSION").read_text().strip()

SYSTEM_PROMPT = f"""\
You are Regen v{VERSION}, an autonomous penetration testing agent built by Axolotl Labs.
You think like an attacker to defend like an engineer.

Your job: find vulnerabilities, PROVE they're exploitable, chain them together,
and show the owner exactly how an attacker would break in. A finding without
proof is just noise. A proven exploit chain is a wake-up call.

## Your workflow

1. RECON — map the attack surface. Headers, tech stack, exposed paths, API endpoints.
   What you learn here decides everything else.

2. SCAN — run targeted scanners based on what recon found.
   A static SPA gets different tests than a server-rendered app with auth.
   Don't waste time on NoSQL tests against a Cloudflare Pages site.

3. EXPLOIT — this is where you earn your keep. For every finding above info:
   - Call exploit_finding() to try weaponizing it.
   - XSS? Prove you can steal cookies or forge requests.
   - SQLi? Extract actual data — table names, row counts, credentials.
   - SSTI? Escalate from 7*7=49 to reading /etc/passwd or running commands.
   - Auth issues? Try to reach /admin without credentials.
   - SSRF? Pivot to cloud metadata and steal IAM tokens.

4. ESCALATE — when an exploit succeeds, go deeper.
   - Call escalate() to probe for admin access, sensitive files, internal services.
   - Call map_attack_surface() to discover new endpoints from your current position.
   - Think: "I got read access — can I get write? Can I get admin? Can I get RCE?"

5. CHAIN — connect your exploits into attack narratives.
   - Call build_chain() to link steps: "XSS → cookie theft → session hijack → admin panel"
   - Each chain tells a story an executive can understand.
   - The chain's access level is the worst-case impact.

6. VERIFY — mark false positives with evidence. A finding is false positive only
   when you can prove the detection was wrong (e.g., "49" appears in a hex color,
   not from template evaluation). Don't dismiss something just because exploitation
   failed — it might need a different approach.

7. FINISH — produce the pentest report:
   - Executive summary with highest access achieved
   - Attack chains with proof-of-concept for each
   - Individual findings with severity and remediation
   - What defenses actually worked (credit the good stuff)

## Principles

- PROVE IT. "Might be vulnerable" is scanner output. "I extracted the user table" is a pentest.
- CHAIN EVERYTHING. One medium finding is a footnote. Three mediums chained together is a critical.
- THINK LIKE AN ATTACKER. After every finding, ask: what can I do with this?
  What does it unlock? What's the next step?
- CREDIT THE DEFENSE. When an exploit fails because of a good defense (HttpOnly cookies,
  CSP, rate limiting), say so. The owner needs to know what's working.
- STAY IN SCOPE. Only test the authorized target. Be non-destructive — prove access,
  don't use it. Read data to prove the point, don't modify it.
- BE RELENTLESS. Try multiple approaches before giving up. Filter bypasses, encoding
  tricks, alternate parameters, different HTTP methods.

You are authorized to test this target. The owner wants to know how an attacker
would break in before the attacker does.\
"""


def _get_client():
    """Get an Anthropic client. Supports ANTHROPIC_API_KEY env var."""
    try:
        import anthropic
        return anthropic.Anthropic()
    except ImportError:
        print(
            "[regen] Error: anthropic package not installed.\n"
            "        pip install anthropic",
            file=sys.stderr,
        )
        sys.exit(1)
    except Exception as e:
        print(f"[regen] Error creating Anthropic client: {e}", file=sys.stderr)
        sys.exit(1)


def _build_user_message(session: Session, tool_result: Optional[dict] = None) -> str:
    """Build the user message with current session state."""
    parts = [
        "Current scan state:",
        session.state_summary(),
    ]

    if tool_result:
        parts.append(f"\nLast tool result:\n{json.dumps(tool_result, indent=2, default=str)[:4000]}")

    parts.append(
        "\nDecide what to do next. Call a tool, or call finish() if the scan is complete."
    )
    return "\n".join(parts)


def run_agent(
    session: Session,
    max_turns: int = 25,
    model: str = "claude-sonnet-4-20250514",
    verbose: bool = True,
    output_dir: Optional[str] = None,
) -> Session:
    """
    Run the agentic scan loop.

    The agent gets the session state, picks a tool, we execute it,
    feed the result back, and repeat until it calls finish() or
    hits the turn limit.
    """
    client = _get_client()
    registry = build_registry()
    tools = registry.list_tools()

    messages = []
    output_dir = output_dir or "./regen-results"

    if verbose:
        print(f"[regen] Agent scan: {session.target}", file=sys.stderr)
        print(f"[regen] Depth: {session.depth}, Model: {model}", file=sys.stderr)
        print(f"[regen] Tools: {', '.join(registry.tool_names())}", file=sys.stderr)

    # Initial message
    messages.append({
        "role": "user",
        "content": _build_user_message(session),
    })

    for turn in range(max_turns):
        if verbose:
            print(f"\n[regen] === Turn {turn + 1}/{max_turns} ===", file=sys.stderr)

        response = client.messages.create(
            model=model,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            tools=tools,
            messages=messages,
        )

        # Process the response
        assistant_content = response.content
        messages.append({"role": "assistant", "content": assistant_content})

        # Check for text blocks (agent reasoning)
        for block in assistant_content:
            if block.type == "text" and verbose:
                print(f"[regen] Agent: {block.text[:200]}", file=sys.stderr)

        # Check for tool use
        tool_uses = [b for b in assistant_content if b.type == "tool_use"]

        if not tool_uses:
            if verbose:
                print("[regen] Agent finished (no tool calls).", file=sys.stderr)
            break

        # Execute each tool call
        tool_results = []
        for tool_use in tool_uses:
            tool_name = tool_use.name
            tool_input = tool_use.input

            if verbose:
                print(f"[regen] Running: {tool_name}({json.dumps(tool_input, default=str)[:100]})", file=sys.stderr)

            result = registry.run_tool(tool_name, session, **tool_input)
            session.log_action(tool_name, tool_input, str(result)[:500])

            if verbose:
                if result.get("error"):
                    print(f"[regen] Error: {result['error'][:200]}", file=sys.stderr)
                else:
                    r = result.get("result", [])
                    count = len(r) if isinstance(r, list) else 1
                    print(f"[regen] Result: {count} items", file=sys.stderr)

            tool_results.append({
                "type": "tool_result",
                "tool_use_id": tool_use.id,
                "content": json.dumps(result, default=str)[:8000],
            })

            # Check if the agent called finish
            if tool_name == "finish":
                if verbose:
                    print("[regen] Scan complete.", file=sys.stderr)
                session.save(output_dir)
                _write_sarif(session, output_dir)
                return session

        messages.append({"role": "user", "content": tool_results})

    # Hit turn limit
    if verbose:
        print(f"[regen] Turn limit ({max_turns}) reached.", file=sys.stderr)
    session.end_time = __import__("datetime").datetime.now(
        __import__("datetime").timezone.utc
    ).isoformat()
    session.save(output_dir)
    _write_sarif(session, output_dir)
    return session


def _write_sarif(session: Session, output_dir: str):
    """Write SARIF output from session findings."""
    from engine.sarif_gen import VERSION as SARIF_VERSION

    findings_sarif = []
    for f in session.findings:
        if f.false_positive:
            continue
        sev = f.severity.lower()
        level = "error" if sev in ("critical", "high") else "warning" if sev == "medium" else "note"
        result = {
            "ruleId": f"regen/{f.scanner}/{f.title.lower().replace(' ', '-')[:60]}",
            "level": level,
            "message": {"text": f.description},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.location}
                }
            }],
            "properties": {
                "severity": sev,
                "scanner": f.scanner,
                "evidence": f.evidence,
                "remediation": f.remediation,
            },
        }
        if f.cwe:
            result["taxa"] = [{"toolComponent": {"name": "cwe"}, "id": f.cwe}]
        findings_sarif.append(result)

    sarif = {
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
            "results": findings_sarif,
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": session.start_time,
                "endTimeUtc": session.end_time or "",
                "properties": {
                    "target": session.target,
                    "scope": session.scope,
                    "depth": session.depth,
                    "mode": "agent",
                },
            }]
        }]
    }

    path = Path(output_dir)
    path.mkdir(parents=True, exist_ok=True)
    sarif_path = path / "regen-results.sarif.json"
    with open(sarif_path, "w") as fp:
        json.dump(sarif, fp, indent=2)
    print(f"[regen] SARIF: {sarif_path} ({len(findings_sarif)} findings)", file=sys.stderr)
