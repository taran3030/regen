#!/usr/bin/env bash
# Runs Regen's header and path checks against local test servers and checks what it reports.
# Every line in checks/*.tsv is exercised: a hardened server must pass every header check, a bare server
# must fail every one, an exposed .env must be caught, and a single-page app's fallback page must not be.
#
#   bash tests/run.sh
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)
OUT=$(mktemp -d)
PIDS=()
cleanup() { kill "${PIDS[@]}" 2>/dev/null || true; rm -rf "$OUT"; }
trap cleanup EXIT

fails=0
check() { # name, condition
    if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; fails=$((fails + 1)); fi
}

start() { # mode port
    python3 tests/fixture_server.py "$1" "$2" &
    PIDS+=($!)
    for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$2/" && return 0; sleep 0.1; done
    echo "server $1 didn't start"; exit 1
}

start hardened 18731
start bare 18732
start spa 18733

headers=$(grep -v '^#' checks/headers.tsv | grep -c .)

bash regen.sh scan -t http://127.0.0.1:18731 -p quick -o "$OUT/hardened" > "$OUT/hardened.log" 2>&1
check "regen scan exits cleanly" "[ -f '$OUT/hardened/headers.txt' ]"
check "a hardened site passes all $headers header checks" "[ \$(grep -c '^\[OK\]' '$OUT/hardened/headers.txt') -eq $headers ]"
check "a hardened site shows no exposed paths" "! grep -qE '^\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]' '$OUT/hardened/exposed-paths.txt'"
check "every scan writes SARIF" "python3 -c 'import json,sys; json.load(open(sys.argv[1]))' '$OUT/hardened/regen-results.sarif.json'"

bash regen.sh scan -t http://127.0.0.1:18732 -p quick -o "$OUT/bare" > "$OUT/bare.log" 2>&1
check "a bare site fails all $headers header checks" "[ \$(grep -c 'Missing:' '$OUT/bare/headers.txt') -eq $headers ]"
check "an exposed .env is critical" "grep -q '^\[CRITICAL\] \[200\] .*/\.env$' '$OUT/bare/exposed-paths.txt'"
check "SARIF carries the exposed .env" "grep -q 'regen/paths/exposed-.env' '$OUT/bare/regen-results.sarif.json'"
check "SARIF carries the missing CSP" "grep -q 'regen/headers/missing-content-security-policy' '$OUT/bare/regen-results.sarif.json'"

bash regen.sh scan -t http://127.0.0.1:18733 -p quick -o "$OUT/spa" > "$OUT/spa.log" 2>&1
check "a single-page app's fallback page isn't reported as exposed files" "! grep -qE '^\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]' '$OUT/spa/exposed-paths.txt'"

# nuclei's options: a stand-in nuclei records the arguments each scan passes it.
mkdir -p "$OUT/bin"
printf '#!/usr/bin/env bash\necho "$*" >> "$NUCLEI_ARGS"\n' > "$OUT/bin/nuclei"
chmod +x "$OUT/bin/nuclei"
# A small template folder: web templates aimed at a fixed other port, in each style nuclei's use, and one that isn't.
T="$OUT/templates/http"
mkdir -p "$T"
printf 'id: a\nhttp:\n  - path:\n      - "{{BaseURL}}:4040/jobs/"\n' > "$T/off-port-baseurl.yaml"
printf 'id: b\nhttp:\n  - raw:\n      - |\n        @Host: {{Host}}:9780\n        GET / HTTP/1.1\n' > "$T/off-port-raw.yaml"
printf 'id: c\nhttp:\n  - method: GET\n    port: 8443\n    path:\n      - "{{BaseURL}}/"\n' > "$T/off-port-key.yaml"
printf 'id: d\nhttp:\n  - raw:\n      - |\n        GET /.git/config HTTP/1.1\n        Host: {{Hostname}}\n' > "$T/same-port.yaml"
printf 'id: e\nssl:\n  - address: "{{Host}}:443"\n' > "$T/web-port-443.yaml"
export NUCLEI_TEMPLATES_DIR="$OUT/templates"
PATH="$OUT/bin:$PATH" NUCLEI_ARGS="$OUT/plain.args" bash regen.sh scan -t http://127.0.0.1:18731 -p standard -o "$OUT/plain" > "$OUT/plain.log" 2>&1
PATH="$OUT/bin:$PATH" NUCLEI_ARGS="$OUT/quiet.args" bash regen.sh scan -t http://127.0.0.1:18731 -p standard --no-oast --web-only -o "$OUT/quiet" > "$OUT/quiet.log" 2>&1
check "a standard scan runs nuclei with its usual options" "[ -s '$OUT/plain.args' ] && ! grep -qE -- '(^| )-(ni|ept|et)( |\$)' '$OUT/plain.args'"
check "--no-oast turns off nuclei's out-of-band checks" "grep -qE -- '(^| )-ni( |\$)' '$OUT/quiet.args'"
check "--web-only skips network and javascript templates" "grep -qF -- '-ept tcp,javascript' '$OUT/quiet.args'"
check "--web-only skips web templates aimed at another port" "grep -qE -- '-et [^ ]*off-port-baseurl' '$OUT/quiet.args' && grep -qF off-port-raw '$OUT/quiet.args' && grep -qF off-port-key '$OUT/quiet.args'"
check "--web-only keeps web templates that use the site's own port" "! grep -qF same-port '$OUT/quiet.args'"
check "--web-only keeps templates that only name ports 80 and 443" "! grep -qF web-port-443 '$OUT/quiet.args'"
NUCLEI_TEMPLATES_DIR="$OUT/no-templates-here" PATH="$OUT/bin:$PATH" NUCLEI_ARGS="$OUT/blind.args" bash regen.sh scan -t http://127.0.0.1:18731 -p standard --web-only -o "$OUT/blind" > "$OUT/blind.log" 2>&1
check "--web-only warns when it can't find nuclei's templates to filter" "grep -q '^\[WARN\] --web-only' '$OUT/blind.log'"

check "the logo files are what assets/logo/build.py makes" "python3 assets/logo/build.py --check > '$OUT/logo.log' 2>&1"

check "every check file line has three tab-separated fields" "! grep -hv '^#' checks/*.tsv | grep . | awk -F'\t' 'NF != 3' | grep -q ."
check "every severity is one Regen knows" "! grep -hv '^#' checks/*.tsv | grep . | cut -f2 | grep -vxE 'critical|high|medium|low|info' | grep -q ."

echo
if [ "$fails" -gt 0 ]; then echo "$fails failed"; cat "$OUT"/*.log | tail -20; exit 1; fi
echo "all passed"
