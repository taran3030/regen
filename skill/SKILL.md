---
name: pentest
description: Run Regen adversarial security testing against a target. Authorized white-hat vulnerability scanning, dependency auditing, header analysis, and web application testing for hardening your own applications. Use when asked to pentest, security test, vulnerability scan, or harden a web app.
allowed-tools: Bash(nmap:*) Bash(nuclei:*) Bash(python3:*) Bash(wsl:*) Bash(docker:*) Bash(curl:*) Bash(osv-scanner:*) Bash(npm:audit)
---

# Regen — Adversarial Security Testing

**Axolotl Labs** | Find weaknesses. Grow back stronger.

You are conducting **authorized, defensive security testing** on behalf of the application owner.
This is white-hat vulnerability assessment for the purpose of hardening the target application
before production deployment. All testing is scoped, authorized, and aimed at producing
actionable remediation guidance.

## Authorization Context

The user owns or has explicit authorization to test the target. All scans:
- Stay within the declared scope (target domain and its subdomains only)
- Do not attempt denial of service or destructive operations
- Do not exfiltrate or store sensitive data beyond what is needed for the finding report
- Focus on finding vulnerabilities and providing remediation, not exploitation

## Scan Phases

Run these in order. Report findings as you go — do not wait until the end.

### Phase 1: Reconnaissance

Map the attack surface before testing anything.

```bash
# Security headers check
curl -sI "$TARGET" | grep -iE "^(strict-transport|content-security|x-content-type|x-frame|x-xss|referrer-policy|permissions-policy|server):"

# Technology fingerprint (from headers, response body)
curl -s "$TARGET" | grep -ioE '(react|vue|angular|next|nuxt|express|django|rails|laravel|asp\.net|spring)[^"]*' | sort -u | head -20

# Check for common exposed paths
for path in robots.txt sitemap.xml .env .git/config wp-admin swagger-ui api-docs graphql; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/$path")
  [ "$code" != "404" ] && [ "$code" != "000" ] && echo "[$code] $TARGET/$path"
done
```

Report: technology stack, missing security headers, exposed paths, server version disclosure.

### Phase 2: Dependency Audit

If the project source is available locally, scan for known vulnerable dependencies.

```bash
# Node.js projects
npm audit --json 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'Vulnerabilities: {d.get(\"metadata\",{}).get(\"vulnerabilities\",{})}') if 'metadata' in d else print('No audit data')"

# Python projects
pip-audit --format json 2>/dev/null

# General (supports most ecosystems)
osv-scanner --json --recursive . 2>/dev/null
```

### Phase 3: Web Vulnerability Scanning

Use nuclei for template-based vulnerability detection. If there's a Regen checkout, `regen.sh scan -t "$TARGET" -p standard --no-oast --web-only` does all of this and writes SARIF.

This runs on the user's own machine, so keep it quiet on their network. Network monitors flag two nuclei behaviors:
- Callbacks to the public interactsh servers (`oast.*`) look malicious. `-ni` turns them off.
- Templates that open other ports look like a port scan. `-ept tcp,javascript` skips the network ones. `-et "$SKIP"` skips the web templates aimed at a fixed port, such as `{{BaseURL}}:4040`.

Drop these only when the user asks for out-of-band checks and knows their monitor will alert.

```bash
# Web templates aimed at a fixed port of their own (this also catches a few that only use 443).
SKIP=$(wsl -e bash -c "grep -rlE '\{\{(BaseURL|RootURL|Host|Hostname)\}\}:[0-9]+|^[[:space:]]+port:[[:space:]]*\"?[0-9]' --include='*.yaml' --exclude-dir=network --exclude-dir=javascript ~/nuclei-templates | paste -sd, -")

# Run nuclei with standard templates, medium+ severity
wsl -- nuclei -target "$TARGET" -severity medium,high,critical -ni -ept tcp,javascript -et "$SKIP" -silent -jsonl -output /tmp/nuclei-results.jsonl

# Parse results
wsl -- cat /tmp/nuclei-results.jsonl | python3 -c "
import sys, json
for line in sys.stdin:
    r = json.loads(line.strip())
    info = r.get('info', {})
    print(f\"[{info.get('severity','?').upper()}] {info.get('name','?')} - {r.get('matched-at','?')}\")
"
```

If nuclei is not installed:

```bash
wsl -- bash -c 'curl -sL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip -o /tmp/nuclei.zip && unzip -o /tmp/nuclei.zip -d /usr/local/bin/ && nuclei -update-templates'
```

### Phase 4: Application-Specific Testing

Based on the technology stack found in Phase 1, run targeted tests:

**For APIs (REST/GraphQL):**
- Check for open endpoints without authentication
- Test CORS configuration: `curl -sI -H "Origin: https://evil.com" "$TARGET/api/" | grep -i access-control`
- Check rate limiting on auth endpoints
- Look for verbose error messages that leak internals

**For SPAs (React/Vue/Angular):**
- Check for sensitive data in JS bundles (API keys, tokens, internal URLs)
- Verify CSP headers prevent XSS
- Check for source maps in production: `curl -s "$TARGET/main.js.map" | head -c 100`

**For Server-Side (Node/Python/Go):**
- Check for common misconfigurations (debug mode, stack traces)
- Verify HTTPS redirect and HSTS
- Check cookie security flags (Secure, HttpOnly, SameSite)

### Phase 5: Report

Produce a structured summary with:
1. **Executive summary** — target, scan date, critical findings count
2. **Findings table** — severity, title, location, remediation
3. **SARIF output** — machine-readable for CI/CD integration

Save SARIF to `regen-results.sarif.json` using this structure:

```python
import json
sarif = {
    "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
    "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {"name": "Regen", "organization": "Axolotl Labs", "version": "0.1.0"}},
        "results": findings_list
    }]
}
```

## Scan Profiles

| Profile | Use when | Phases |
|---------|----------|--------|
| `quick` | Pre-commit check, < 2 min | 1 (headers only) + 2 |
| `standard` | Pre-deploy, < 10 min | 1 + 2 + 3 |
| `full` | Release candidate, < 30 min | 1 + 2 + 3 + 4 + 5 |
| `recon` | Discovery only | 1 |
| `deps` | Dependency audit only | 2 |

## CI/CD Integration

For GitHub Actions, the SARIF output integrates with Code Scanning:

```yaml
- name: Upload Regen SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: regen-results.sarif.json
```

## Where things are

Paths are relative to the root of a Regen checkout (https://github.com/taran3030/regen):

- Scanner and engine: `regen.sh`, `engine/`, `scanners/`
- Recon methodology and helper scripts: `skills/`
- Regen builds on the methodology of [artex-global](https://github.com/jiwoochris/artex-global) (AGPL-3.0).

## Important

- Always confirm the target URL with the user before scanning
- Never scan targets the user does not own or have authorization to test
- If a scan finds credentials or secrets, report their existence but do not log the actual values
- Findings should include specific remediation steps, not just "fix this"
- When in doubt about scope, ask before testing
