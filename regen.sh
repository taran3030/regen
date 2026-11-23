#!/usr/bin/env bash
# Regen — Adversarial Security Testing
# Axolotl Labs | Find weaknesses. Grow back stronger.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VERSION="$(tr -d '[:space:]' < "$SCRIPT_DIR/VERSION")"  # one version for the script, SARIF and tags

usage() {
    cat <<EOF
Regen v${VERSION} — Adversarial Security Testing by Axolotl Labs
Find weaknesses. Grow back stronger.

Usage: regen <command> [options]

Commands:
  scan       Run a security scan against a target
  recon      Reconnaissance only (headers, tech stack, exposed paths)
  deps       Dependency vulnerability audit (local project)
  exploit    Active exploit testing against a target (non-destructive)
  deep       Deep manual pentest (10-phase red team)
  azure      Zero-knowledge Azure infrastructure breach attempt
  pentest    Full scan + exploit + report pipeline (Python CLI)
  full       Full assessment: pentest + deep + azure (CI/CD pipeline)
  report     Generate report from previous scan results
  install    Install scanner dependencies (nuclei, nmap, osv-scanner)

Scan options:
  -t, --target URL     Target URL to scan (required for scan/recon)
  -s, --scope DOMAINS  Comma-separated allowed domains
  -p, --profile NAME   Scan profile: quick|standard|full (default: standard)
  -o, --output DIR     Output directory (default: ./regen-results)
  -d, --project DIR    Local project directory (for deps scan)
  --no-oast            Skip nuclei's out-of-band checks, which call ProjectDiscovery's
                       public interactsh servers (oast.*). Network monitors flag those.
  --web-only           Skip nuclei templates that connect to ports other than the site's
                       own: network and javascript templates, and web templates aimed at
                       a fixed port such as 4040. Monitors read those as a port scan.

Examples:
  regen scan -t https://myapp.azurewebsites.net -p full
  regen deps -d ./my-project
  regen recon -t https://staging.example.com
  regen exploit -t https://myapp.azurewebsites.net
EOF
}

check_tools() {
    local missing=()
    for tool in curl python3; do
        command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
    done
    if [ ${#missing[@]} -gt 0 ]; then
        echo "[regen] Missing tools: ${missing[*]}"
        echo "[regen] Run 'regen install' to set up dependencies"
        return 1
    fi
}

install_deps() {
    echo "[regen] Installing scanner dependencies..."

    # nuclei
    if ! command -v nuclei >/dev/null 2>&1; then
        echo "[regen] Installing nuclei..."
        curl -sL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip -o /tmp/nuclei.zip
        sudo unzip -o /tmp/nuclei.zip -d /usr/local/bin/
        rm /tmp/nuclei.zip
        nuclei -update-templates 2>/dev/null || true
    else
        echo "[regen] nuclei already installed"
    fi

    # osv-scanner
    if ! command -v osv-scanner >/dev/null 2>&1; then
        echo "[regen] Installing osv-scanner..."
        pip3 install --user osv-scanner 2>/dev/null || {
            echo "[regen] Trying Go install..."
            go install github.com/google/osv-scanner/cmd/osv-scanner@latest 2>/dev/null || echo "[regen] Could not install osv-scanner automatically"
        }
    else
        echo "[regen] osv-scanner already installed"
    fi

    echo "[regen] Dependencies ready"
}

scan_headers() {
    local target="$1"
    echo "[regen] Phase 1: Security headers for $target"
    echo "---"

    local headers
    headers=$(curl -sI --max-time 10 "$target" 2>/dev/null) || {
        echo "[CRITICAL] Target unreachable: $target"
        return 1
    }

    # One check per line in checks/headers.tsv: header, severity when missing, why.
    local h sev why
    while IFS=$'\t' read -r h sev why; do
        [[ -z "$h" || "$h" == \#* ]] && continue
        if echo "$headers" | grep -qi "^${h}:"; then
            echo "[OK] $h present"
        else
            echo "[$(printf %s "$sev" | tr "[:lower:]" "[:upper:]")] Missing: $h"
        fi
    done < "${SCRIPT_DIR}/checks/headers.tsv"

    local server
    server=$(echo "$headers" | grep -i "^server:" | head -1 || true)
    if echo "$server" | grep -qiE '(apache|nginx|iis)/[0-9]'; then
        echo "[LOW] Server version disclosed: $server"
    fi
    echo "---"
}

scan_exposed_paths() {
    local target="$1"
    echo "[regen] Phase 1b: Checking exposed paths..."

    # A single-page app answers every unknown path with its home page (200). Fetch a path that can't exist
    # first; any path that answers with that same body is the fallback, not an exposed file.
    local fallback
    fallback=$(curl -s --max-time 5 "${target%/}/regen-no-such-path-$RANDOM$RANDOM" 2>/dev/null | sha256sum | cut -d' ' -f1 || true)

    # One check per line in checks/paths.tsv: path, severity when exposed, why.
    local path sev why code body_hash
    while IFS=$'\t' read -r path sev why; do
        [[ -z "$path" || "$path" == \#* ]] && continue
        code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "${target%/}/$path" 2>/dev/null) || continue
        if [ "$code" = "200" ]; then
            body_hash=$(curl -s --max-time 5 "${target%/}/$path" 2>/dev/null | sha256sum | cut -d' ' -f1 || true)
            [ -n "$fallback" ] && [ "$body_hash" = "$fallback" ] && continue
        fi
        if [ "$code" != "404" ] && [ "$code" != "000" ] && [ "$code" != "403" ] && [ "$code" != "401" ]; then
            echo "[$(printf %s "$sev" | tr "[:lower:]" "[:upper:]")] [$code] ${target%/}/$path"
        fi
    done < "${SCRIPT_DIR}/checks/paths.tsv"
}

scan_deps() {
    local project_dir="$1"
    local output_dir="$2"
    echo "[regen] Phase 2: Dependency audit for $project_dir"
    echo "---"

    # npm audit
    if [ -f "$project_dir/package.json" ]; then
        echo "[regen] Running npm audit..."
        (cd "$project_dir" && npm audit --json 2>/dev/null > "$output_dir/npm-audit.json") || true
        python3 -c "
import json, sys
try:
    with open('$output_dir/npm-audit.json') as f:
        d = json.load(f)
    vulns = d.get('metadata', {}).get('vulnerabilities', {})
    for sev, count in vulns.items():
        if count > 0:
            print(f'[{sev.upper()}] npm: {count} {sev} vulnerabilities')
except: pass
" 2>/dev/null || true
    fi

    # pip-audit
    if [ -f "$project_dir/requirements.txt" ] || [ -f "$project_dir/pyproject.toml" ]; then
        echo "[regen] Running pip-audit..."
        (cd "$project_dir" && pip-audit --format json > "$output_dir/pip-audit.json" 2>/dev/null) || true
    fi

    # osv-scanner (universal)
    if command -v osv-scanner >/dev/null 2>&1; then
        echo "[regen] Running osv-scanner..."
        osv-scanner --json --recursive "$project_dir" > "$output_dir/osv-results.json" 2>/dev/null || true
    fi
    echo "---"
}

# Web templates that send requests to a fixed port of their own, like {{BaseURL}}:4040 for Spark's UI,
# open that port on the target even when network templates are off. List the ones that name any port
# besides 80 and 443 from nuclei's template folder, comma-separated, for -et. The network and javascript
# folders are left out: -ept covers those.
off_port_templates() {
    local dir="${NUCLEI_TEMPLATES_DIR:-$HOME/nuclei-templates}"
    local fixed='\}\}:[0-9]+|^[[:space:]]+port:[[:space:]]*"?[0-9]+'
    [ -d "$dir" ] || return 0
    grep -rlE '\{\{(BaseURL|RootURL|Host|Hostname)\}\}:[0-9]+|^[[:space:]]+port:[[:space:]]*"?[0-9]' \
        --include='*.yaml' --exclude-dir=network --exclude-dir=javascript "$dir" 2>/dev/null | sort |
    while read -r f; do
        grep -oE "$fixed" "$f" | grep -oE '[0-9]+$' | grep -qvxE '80|443' && echo "$f"
    done | paste -sd, - || true
}

scan_nuclei() {
    local target="$1"
    local output_dir="$2"
    local no_oast="${3:-}"
    local web_only="${4:-}"
    echo "[regen] Phase 3: Vulnerability scanning with nuclei..."
    echo "---"

    if ! command -v nuclei >/dev/null 2>&1; then
        echo "[WARN] nuclei not installed. Run 'regen install' first."
        return 0
    fi

    local opts=(-severity medium,high,critical -silent -jsonl -timeout 10)
    if [ -n "$no_oast" ]; then opts+=(-ni); fi
    if [ -n "$web_only" ]; then opts+=(-ept tcp,javascript); fi
    echo "[regen] nuclei options: ${opts[*]}"
    if [ -n "$web_only" ]; then
        # The list comes from the downloaded templates, so get them first if this is the first run.
        [ -d "${NUCLEI_TEMPLATES_DIR:-$HOME/nuclei-templates}" ] || nuclei -update-templates -silent >/dev/null 2>&1 || true
        local skip
        skip=$(off_port_templates)
        if [ -n "$skip" ]; then
            opts+=(-et "$skip")
            echo "[regen] --web-only: also skipping $(tr ',' '\n' <<< "$skip" | wc -l | tr -d ' ') web templates that use another port"
        elif [ ! -d "${NUCLEI_TEMPLATES_DIR:-$HOME/nuclei-templates}" ]; then
            echo "[WARN] --web-only couldn't find nuclei's templates in ${NUCLEI_TEMPLATES_DIR:-$HOME/nuclei-templates}, so web templates aimed at other ports will still run. Set NUCLEI_TEMPLATES_DIR to the folder nuclei uses."
        fi
    fi

    nuclei -target "$target" "${opts[@]}" \
        -output "$output_dir/nuclei-results.jsonl" \
        2>/dev/null || true

    if [ -f "$output_dir/nuclei-results.jsonl" ]; then
        python3 -c "
import json, sys
with open('$output_dir/nuclei-results.jsonl') as f:
    for line in f:
        if not line.strip(): continue
        r = json.loads(line.strip())
        info = r.get('info', {})
        sev = info.get('severity', '?').upper()
        name = info.get('name', '?')
        loc = r.get('matched-at', '?')
        print(f'[{sev}] {name} - {loc}')
" 2>/dev/null || true
    fi
    echo "---"
}

scan_auth() {
    local target="$1"
    local output_dir="$2"
    local depth="${3:-standard}"
    echo "[regen] Phase: Authentication testing (depth: $depth)"
    echo "---"
    python3 -c "
import sys; sys.path.insert(0, '${SCRIPT_DIR}')
from scanners.auth import run_auth_tests
for f in run_auth_tests('$target', '$depth'):
    sev = f['severity'].upper()
    print(f'[{sev}] {f[\"title\"]}')
    if sev != 'INFO': print(f'  {f[\"description\"][:120]}')
" 2>&1 | tee "$output_dir/auth-results.txt"
    echo "---"
}

scan_injection() {
    local target="$1"
    local output_dir="$2"
    local depth="${3:-standard}"
    echo "[regen] Phase: Injection testing (depth: $depth)"
    echo "---"
    python3 -c "
import sys; sys.path.insert(0, '${SCRIPT_DIR}')
from scanners.injection import run_injection_tests
for f in run_injection_tests('$target', '$depth'):
    sev = f['severity'].upper()
    print(f'[{sev}] {f[\"title\"]}')
    if sev != 'INFO': print(f'  {f[\"description\"][:120]}')
" 2>&1 | tee "$output_dir/injection-results.txt"
    echo "---"
}

scan_tls() {
    local target="$1"
    local output_dir="$2"
    local depth="${3:-standard}"
    echo "[regen] Phase: TLS analysis (depth: $depth)"
    echo "---"
    python3 -c "
import sys; sys.path.insert(0, '${SCRIPT_DIR}')
from scanners.tls import run_tls_tests
for f in run_tls_tests('$target', '$depth'):
    sev = f['severity'].upper()
    print(f'[{sev}] {f[\"title\"]}')
    if sev != 'INFO': print(f'  {f[\"description\"][:120]}')
" 2>&1 | tee "$output_dir/tls-results.txt"
    echo "---"
}

scan_api() {
    local target="$1"
    local output_dir="$2"
    local depth="${3:-standard}"
    echo "[regen] Phase: API surface testing (depth: $depth)"
    echo "---"
    python3 -c "
import sys; sys.path.insert(0, '${SCRIPT_DIR}')
from scanners.api_fuzzer import run_api_tests
for f in run_api_tests('$target', '$depth'):
    sev = f['severity'].upper()
    print(f'[{sev}] {f[\"title\"]}')
    if sev != 'INFO': print(f'  {f[\"description\"][:120]}')
" 2>&1 | tee "$output_dir/api-results.txt"
    echo "---"
}

scan_ssrf() {
    local target="$1"
    local output_dir="$2"
    local depth="${3:-standard}"
    echo "[regen] Phase: SSRF testing (depth: $depth)"
    echo "---"
    python3 -c "
import sys; sys.path.insert(0, '${SCRIPT_DIR}')
from scanners.ssrf import run_ssrf_tests
for f in run_ssrf_tests('$target', '$depth'):
    sev = f['severity'].upper()
    print(f'[{sev}] {f[\"title\"]}')
    if sev != 'INFO': print(f'  {f[\"description\"][:120]}')
" 2>&1 | tee "$output_dir/ssrf-results.txt"
    echo "---"
}

scan_nosql() {
    local target="$1"
    local output_dir="$2"
    local depth="${3:-standard}"
    echo "[regen] Phase: NoSQL injection testing (depth: $depth)"
    echo "---"
    python3 -c "
import sys; sys.path.insert(0, '${SCRIPT_DIR}')
from scanners.nosql import run_nosql_tests
for f in run_nosql_tests('$target', '$depth'):
    sev = f['severity'].upper()
    print(f'[{sev}] {f[\"title\"]}')
    if sev != 'INFO': print(f'  {f[\"description\"][:120]}')
" 2>&1 | tee "$output_dir/nosql-results.txt"
    echo "---"
}

scan_graphql() {
    local target="$1"
    local output_dir="$2"
    local depth="${3:-standard}"
    echo "[regen] Phase: GraphQL testing (depth: $depth)"
    echo "---"
    python3 -c "
import sys; sys.path.insert(0, '${SCRIPT_DIR}')
from scanners.graphql import run_graphql_tests
for f in run_graphql_tests('$target', '$depth'):
    sev = f['severity'].upper()
    print(f'[{sev}] {f[\"title\"]}')
    if sev != 'INFO': print(f'  {f[\"description\"][:120]}')
" 2>&1 | tee "$output_dir/graphql-results.txt"
    echo "---"
}

scan_exploits() {
    local target="$1"
    local output_dir="$2"
    echo "[regen] Phase: Active exploit testing"
    echo "---"

    python3 "${SCRIPT_DIR}/scanners/exploit.py" "$target" 2>&1 | tee "$output_dir/exploit-results.txt"

    echo "---"
}

generate_sarif() {
    local output_dir="$1"
    local target="$2"
    echo "[regen] Generating SARIF report..."

    python3 "${SCRIPT_DIR}/engine/sarif_gen.py" "$output_dir" "$target" 2>/dev/null || {
        echo "[regen] SARIF generation requires engine/sarif_gen.py"
    }
}

cmd_scan() {
    local target="" scope="" profile="standard" output_dir="./regen-results" project_dir="" no_oast="" web_only=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t|--target) target="$2"; shift 2 ;;
            -s|--scope) scope="$2"; shift 2 ;;
            -p|--profile) profile="$2"; shift 2 ;;
            -o|--output) output_dir="$2"; shift 2 ;;
            -d|--project) project_dir="$2"; shift 2 ;;
            --no-oast) no_oast=1; shift ;;
            --web-only) web_only=1; shift ;;
            *) echo "Unknown option: $1"; usage; exit 1 ;;
        esac
    done

    if [ -z "$target" ]; then
        echo "[regen] Error: --target is required"
        usage
        exit 1
    fi

    mkdir -p "$output_dir"
    echo "============================================"
    echo "  Regen v${VERSION} — Axolotl Labs"
    echo "  Target: $target"
    echo "  Profile: $profile"
    echo "  Output: $output_dir"
    echo "  Started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "============================================"
    echo ""

    # Phase 1: Recon (all profiles)
    scan_headers "$target" | tee "$output_dir/headers.txt"
    scan_exposed_paths "$target" | tee "$output_dir/exposed-paths.txt"

    if [ "$profile" = "quick" ]; then
        # Quick: recon + TLS + deps
        scan_tls "$target" "$output_dir" "quick"
        [ -n "$project_dir" ] && scan_deps "$project_dir" "$output_dir"
        generate_sarif "$output_dir" "$target"
        echo "[regen] Quick scan complete."
        return
    fi

    # Phase 2: TLS (standard+)
    scan_tls "$target" "$output_dir" "$profile"

    # Phase 3: Deps (if project dir provided)
    [ -n "$project_dir" ] && scan_deps "$project_dir" "$output_dir"

    # Phase 4: Auth testing (standard+)
    scan_auth "$target" "$output_dir" "$profile"

    # Phase 5: Injection testing (standard+)
    scan_injection "$target" "$output_dir" "$profile"

    # Phase 6: SSRF testing (standard+)
    scan_ssrf "$target" "$output_dir" "$profile"

    # Phase 7: NoSQL injection (standard+)
    scan_nosql "$target" "$output_dir" "$profile"

    # Phase 8: GraphQL testing (standard+)
    scan_graphql "$target" "$output_dir" "$profile"

    # Phase 9: API surface testing (standard+)
    scan_api "$target" "$output_dir" "$profile"

    # Phase 10: Nuclei (standard+)
    scan_nuclei "$target" "$output_dir" "$no_oast" "$web_only"

    # Phase 11: Active exploit testing (full only)
    if [ "$profile" = "full" ]; then
        scan_exploits "$target" "$output_dir"
    fi

    generate_sarif "$output_dir" "$target"

    echo ""
    echo "[regen] Scan complete. Results in $output_dir/"
    echo "[regen] $(date -u +%Y-%m-%dT%H:%M:%SZ)"
}

cmd_recon() {
    local target=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t|--target) target="$2"; shift 2 ;;
            *) echo "Unknown option: $1"; exit 1 ;;
        esac
    done
    [ -z "$target" ] && { echo "[regen] --target required"; exit 1; }
    scan_headers "$target"
    scan_exposed_paths "$target"
}

cmd_deps() {
    local project_dir="" output_dir="./regen-results"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--project) project_dir="$2"; shift 2 ;;
            -o|--output) output_dir="$2"; shift 2 ;;
            *) echo "Unknown option: $1"; exit 1 ;;
        esac
    done
    [ -z "$project_dir" ] && { echo "[regen] --project required"; exit 1; }
    mkdir -p "$output_dir"
    scan_deps "$project_dir" "$output_dir"
}

cmd_exploit() {
    local target="" output_dir="./regen-results"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t|--target) target="$2"; shift 2 ;;
            -o|--output) output_dir="$2"; shift 2 ;;
            *) echo "Unknown option: $1"; exit 1 ;;
        esac
    done
    [ -z "$target" ] && { echo "[regen] --target required"; exit 1; }
    mkdir -p "$output_dir"
    echo "============================================"
    echo "  Regen v${VERSION} — Exploit Testing"
    echo "  Target: $target"
    echo "  Output: $output_dir"
    echo "  Started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "============================================"
    echo ""
    scan_exploits "$target" "$output_dir"
    echo ""
    echo "[regen] Exploit testing complete. Results in $output_dir/"
}

# Main dispatcher
case "${1:-}" in
    scan)    shift; check_tools && cmd_scan "$@" ;;
    recon)   shift; cmd_recon "$@" ;;
    deps)    shift; cmd_deps "$@" ;;
    exploit) shift; check_tools && cmd_exploit "$@" ;;
    deep)    shift; cd "$SCRIPT_DIR" && python3 -m agent.cli deep "$@" ;;
    azure)   shift; cd "$SCRIPT_DIR" && python3 -m agent.cli azure "$@" ;;
    pentest) shift; cd "$SCRIPT_DIR" && python3 -m agent.cli pentest "$@" ;;
    full)    shift; cd "$SCRIPT_DIR" && python3 -m agent.cli full "$@" ;;
    agent)   shift; cd "$SCRIPT_DIR" && python3 -m agent.cli agent "$@" ;;
    install) install_deps ;;
    help|-h|--help) usage ;;
    "") usage ;;
    *) echo "Unknown command: $1"; usage; exit 1 ;;
esac
