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
PATH="$OUT/bin:$PATH" NUCLEI_ARGS="$OUT/plain.args" bash regen.sh scan -t http://127.0.0.1:18731 -p standard -o "$OUT/plain" > "$OUT/plain.log" 2>&1
PATH="$OUT/bin:$PATH" NUCLEI_ARGS="$OUT/quiet.args" bash regen.sh scan -t http://127.0.0.1:18731 -p standard --no-oast --web-only -o "$OUT/quiet" > "$OUT/quiet.log" 2>&1
check "a standard scan runs nuclei with its usual options" "[ -s '$OUT/plain.args' ] && ! grep -qE -- '(^| )-(ni|ept)( |\$)' '$OUT/plain.args'"
check "--no-oast turns off nuclei's out-of-band checks" "grep -qE -- '(^| )-ni( |\$)' '$OUT/quiet.args'"
check "--web-only skips templates that open other ports" "grep -qF -- '-ept tcp,javascript' '$OUT/quiet.args'"

check "the logo files are what assets/logo/build.py makes" "python3 assets/logo/build.py --check > '$OUT/logo.log' 2>&1"

check "every check file line has three tab-separated fields" "! grep -hv '^#' checks/*.tsv | grep . | awk -F'\t' 'NF != 3' | grep -q ."
check "every severity is one Regen knows" "! grep -hv '^#' checks/*.tsv | grep . | cut -f2 | grep -vxE 'critical|high|medium|low|info' | grep -q ."

echo
if [ "$fails" -gt 0 ]; then echo "$fails failed"; cat "$OUT"/*.log | tail -20; exit 1; fi
echo "all passed"
