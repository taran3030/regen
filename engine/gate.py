#!/usr/bin/env python3
"""Exit 1 when a SARIF file has a finding at least as severe as the threshold.

Usage: python3 gate.py <regen-results.sarif.json> <critical|high|medium|low|none>
"""
import json
import sys

ORDER = ["info", "low", "medium", "high", "critical"]


def main() -> int:
    path, threshold = sys.argv[1], sys.argv[2].lower()
    if threshold == "none":
        return 0
    if threshold not in ORDER:
        print(f"[regen] Unknown severity '{threshold}'. Use one of: critical, high, medium, low, none.")
        return 2
    with open(path) as f:
        sarif = json.load(f)
    results = [r for run in sarif.get("runs", []) for r in run.get("results", [])]
    floor = ORDER.index(threshold)
    def severity(r):
        sev = str((r.get("properties") or {}).get("severity", "info")).lower()
        sev = {"moderate": "medium"}.get(sev, sev)  # npm audit says moderate
        return sev if sev in ORDER else "info"

    blocking = [r for r in results if ORDER.index(severity(r)) >= floor]
    for r in blocking:
        print(f"[regen] {severity(r).upper()}: {r.get('message', {}).get('text', '')}")
    if blocking:
        print(f"[regen] {len(blocking)} finding(s) at {threshold} or above.")
        return 1
    print(f"[regen] Nothing at {threshold} or above ({len(results)} finding(s) in total).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
