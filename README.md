<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo/logo-animated.svg">
    <img src="assets/logo/logo-animated-light.svg" alt="regen." width="360">
  </picture>
</p>

<p align="center"><b>Find weaknesses. Grow back stronger.</b><br>Security checks for every deploy, from Axolotl Labs.</p>

---

Regen scans a live site and its code for the problems that are easy to ship and easy to miss: missing security headers, files that shouldn't be public, known vulnerabilities, and dependencies with published advisories. It runs from the command line, in GitHub Actions, or from Claude Code, and writes SARIF so findings land in GitHub's Security tab.

It's named for the axolotl, which regrows what it loses. It's open source so the checks keep growing too: every check is one line in a file, and anyone can add one.

> **Only scan what you own or have permission to test.** Regen is for hardening your own sites.

## Run it

```bash
git clone https://github.com/taran3030/regen && cd regen
./regen.sh install                                  # nuclei and osv-scanner (needs sudo for some tools)
./regen.sh scan -t https://your-site.example -p quick         # headers, exposed paths
./regen.sh scan -t https://your-site.example -d . -p standard # plus dependencies and nuclei
```

| Command | Checks |
|---|---|
| `scan -p quick` | Security headers, exposed paths, dependency audit (with `-d`) |
| `scan -p standard` | `quick` plus nuclei's vulnerability templates at medium and above |
| `recon -t <url>` | Headers and exposed paths only |
| `deps -d <dir>` | Dependency audit only |

Results go to the output folder (`-o`, default `./regen-results`): one text file per check, plus `regen-results.sarif.json`.

### Scanning from your own network

Two nuclei behaviors look like an attack to a home or office network monitor. Turn them off when you scan from your own machine:

- `--no-oast` skips nuclei's out-of-band checks. Those plant a link to ProjectDiscovery's public interactsh servers (`oast.pro`, `oast.live` and others) and wait for a callback, and monitors flag those servers as malicious.
- `--web-only` skips nuclei templates that connect to ports other than the site's own: the network templates (SSH, databases and so on) and the few web templates aimed at a fixed port, like Spark's UI on 4040. Monitors read those as a port scan, and behind a CDN they only reach the CDN anyway.

```bash
./regen.sh scan -t https://your-site.example -p standard --no-oast --web-only
```

The GitHub Action doesn't use these flags, so it runs every template: a CI runner has no monitor to alarm. If nuclei keeps its templates somewhere other than `~/nuclei-templates`, set `NUCLEI_TEMPLATES_DIR` so `--web-only` can find the ones to skip.

## In GitHub Actions

```yaml
- uses: taran3030/regen@v1
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
regen.sh        the CLI
checks/         header and path checks, one per line
engine/         SARIF output and the severity gate
scanners/       scanner wrappers (recon, web, dependencies)
skills/         recon methodology and helper scripts
skill/          the Claude Code skill
action.yml      the GitHub Action
tests/          test servers and the check suite
assets/logo/    the logo, and the script that builds it
```

## License

[AGPL-3.0](LICENSE). Regen builds on the methodology of [artex-global](https://github.com/jiwoochris/artex-global), which is AGPL-3.0 too.

Made by [Axolotl Labs](https://www.axolotllabs.io).
