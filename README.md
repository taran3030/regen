<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo/logo-animated.svg">
    <img src="assets/logo/logo-animated-light.svg" alt="regen." width="360">
  </picture>
</p>

<p align="center"><b>Find weaknesses. Grow back stronger.</b><br>LLM-native defensive security scanner, from Axolotl Labs.</p>

---

Regen is an agentic security scanner for web applications. It uses Claude to reason about your attack surface, decide which scanners to run, interpret findings, and generate remediation — not just a checklist, but an AI security engineer that adapts to what it finds.

It also runs as a traditional pipeline scanner for CI/CD, with SARIF output that lands findings in GitHub's Security tab.

It's named for the axolotl, which regrows what it loses. It's open source so the checks keep growing too.

> **Only scan what you own or have permission to test.** Regen is for hardening your own sites.

## Agent mode

The agent uses Claude to drive the scan. It starts with reconnaissance, reasons about what it found, picks the right scanners, verifies findings, and generates remediation.

```bash
pip install anthropic
export ANTHROPIC_API_KEY=sk-ant-...

python3 -m agent.cli agent -t https://your-site.example -p standard
```

What the agent does:
1. **Recon** — maps headers, technologies, exposed paths
2. **Reason** — decides which scanners matter for this target (skips NoSQL for a static SPA, adds GraphQL probes when it finds an endpoint)
3. **Test** — runs scanners with depth-appropriate payloads
4. **Verify** — marks false positives, confirms real findings
5. **Remediate** — generates fix guidance tailored to the target's stack
6. **Report** — writes SARIF and a structured summary

```bash
# Full scan with dependency audit
python3 -m agent.cli agent -t https://your-site.example -d ./my-project -p full

# List available tools
python3 -m agent.cli tools
```

### Agent tools

The agent has 15 tools it can invoke:

| Tool | What it does |
|---|---|
| `recon` | Security headers, tech fingerprinting, exposed paths |
| `tls_scan` | Certificate, cipher suites, protocol analysis |
| `auth_scan` | Cookie security, session management, rate limiting |
| `injection_scan` | XSS, SQLi, SSTI, CRLF, command injection, open redirect |
| `ssrf_scan` | Internal service probes, cloud metadata, IP bypasses |
| `nosql_scan` | MongoDB operator injection, auth bypass |
| `graphql_scan` | Introspection, complexity abuse, batch queries |
| `api_scan` | Method enumeration, IDOR, mass assignment |
| `exploit_scan` | CORS, CSRF, clickjacking, CSP bypass |
| `dependency_scan` | npm, pip, OSV vulnerability databases |
| `remediate` | AI-generated fix guidance for a finding |
| `note` | Agent scratchpad for reasoning between steps |
| `set_phase` | Transition between scan phases |
| `mark_false_positive` | Flag a finding as not a real vulnerability |
| `finish` | End the scan and produce the report |

## Pipeline mode

The traditional scanner pipeline, for CI/CD and scripted use:

```bash
./regen.sh install                                  # nuclei and osv-scanner
./regen.sh scan -t https://your-site.example -p quick         # headers, exposed paths
./regen.sh scan -t https://your-site.example -d . -p standard # plus dependencies and nuclei
```

| Command | Checks |
|---|---|
| `scan -p quick` | Security headers, exposed paths, TLS certificate, dependency audit (with `-d`) |
| `scan -p standard` | `quick` plus auth testing, injection probes, API fuzzing, nuclei templates |
| `scan -p full` | `standard` plus active exploit testing, command injection timing, deprecated TLS probes |
| `exploit -t <url>` | Active exploit testing only (origin bypass, CSRF, CORS, CSP, clickjacking, etc.) |
| `recon -t <url>` | Headers and exposed paths only |
| `deps -d <dir>` | Dependency audit only |

Each scanner has its own depth level that tracks the profile:

| Scanner | Quick | Standard | Full |
|---|---|---|---|
| **Recon** (headers, paths) | Yes | Yes | Yes |
| **TLS** (cert, cipher, protocols) | Cert only | + cipher, issuer | + deprecated protocol probes |
| **Dependencies** (npm, pip, osv) | Yes | Yes | Yes |
| **Auth** (cookies, rate limits, sessions) | Cookies, logout | + rate limits, fixation, error messages | + concurrent sessions |
| **Injection** (XSS, SQLi, SSTI, CRLF) | 3 XSS probes | + DB-specific SQLi, SSTI, CRLF, open redirect | + timing-based SQLi/cmdi, filter bypasses |
| **SSRF** (internal/cloud/bypass) | URL param probes | + cloud metadata, POST body | + IP encoding bypasses |
| **NoSQL** (MongoDB, operator injection) | Operator injection | + string injection, auth bypass | + string injection, auth bypass |
| **GraphQL** (introspection, complexity) | Introspection | + field suggestions, complexity, mutations | + batch query abuse |
| **API** (methods, IDOR, mass assignment) | Methods, versioning | + mass assignment, IDOR, data exposure | + content-type, large payload |
| **Nuclei** (template scanning) | — | Yes | Yes |
| **Exploit** (active defense testing) | — | — | Yes |

Results go to the output folder (`-o`, default `./regen-results`): one text file per check, plus `regen-results.sarif.json`.

### Scanning from your own network

Two nuclei behaviors look like an attack to a home or office network monitor. Turn them off when you scan from your own machine:

- `--no-oast` skips nuclei's out-of-band checks. Those plant a link to ProjectDiscovery's public interactsh servers (`oast.pro`, `oast.live` and others) and wait for a callback, and monitors flag those servers as malicious.
- `--web-only` skips nuclei templates that connect to ports other than the site's own: the network templates (SSH, databases and so on) and the few web templates aimed at a fixed port, like Spark's UI on 4040. Monitors read those as a port scan, and behind a CDN they only reach the CDN anyway.

```bash
./regen.sh scan -t https://your-site.example -p standard --no-oast --web-only
```

## In GitHub Actions

```yaml
- uses: taran3030/regen@v2
  id: regen
  with:
    target: https://your-site.example
    profile: standard        # or quick
    fail-on: high            # fail the job on high or critical findings
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: ${{ steps.regen.outputs.sarif }}
```

Run it after your deploy step, against the URL you just deployed.

## In Claude Code

Copy the skill in once, then ask for a scan:

```bash
cp -r skill/ ~/.claude/skills/pentest/
```

```
/pentest scan https://your-site.example
```

## How it stays current

- **nuclei's templates** download fresh on every run, so new detections arrive without a Regen release.
- **A weekly job** opens a pull request when nuclei itself ships a release.
- **Everyone else.** Each header and path check is a line in [`checks/`](checks/). Add one, and CI runs it against test servers before it merges. See [CONTRIBUTING.md](CONTRIBUTING.md).

## What's in here

```
agent/
  cli.py        the agentic CLI entry point
  loop.py       Claude-driven reasoning loop
  session.py    scan session state management
  tools.py      tool registry (scanners as agent tools)
  remediate.py  AI-powered fix generation
regen.sh        the pipeline CLI
checks/         header and path checks, one per line
engine/         SARIF output and the severity gate
scanners/
  payloads.py   curated payload collections (from PayloadsAllTheThings)
  recon.py      header checks and tech fingerprinting
  web.py        nuclei template scanning
  dependency.py npm/pip/osv dependency audit
  tls.py        TLS/SSL certificate and protocol analysis
  auth.py       authentication flow and session testing
  injection.py  XSS, SQLi, SSTI, CRLF, command injection
  ssrf.py       server-side request forgery testing
  nosql.py      NoSQL/MongoDB injection testing
  graphql.py    GraphQL introspection and complexity abuse
  api_fuzzer.py API method enumeration, IDOR, mass assignment
  exploit.py    active adversarial exploit testing
skills/         recon methodology and helper scripts
skill/          the Claude Code skill
action.yml      the GitHub Action
tests/          test servers and the check suite
assets/logo/    the logo, and the script that builds it
```

## License

[AGPL-3.0](LICENSE). Regen builds on the methodology of [artex-global](https://github.com/jiwoochris/artex-global), which is AGPL-3.0 too.

Made by [Axolotl Labs](https://www.axolotllabs.io).
