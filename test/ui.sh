#!/usr/bin/env bash
# The browser tests, a few at a time: each one starts a fixture server and a browser, and more than a few at once
# starve the machine. Usage: bash test/ui.sh [name ...]   (names as in test/<name>_ui_test.py; all by default)
# UI_JOBS: how many run at once (2). UI_OUT: where logs and screenshots go (a temporary directory).
cd "$(dirname "$0")/.." || exit 1
jobs=${UI_JOBS:-2}; out=${UI_OUT:-$(mktemp -d)}; mkdir -p "$out"
names=("$@"); [ ${#names[@]} -gt 0 ] || names=($(ls test/*_ui_test.py | sed 's|test/||; s|_ui_test.py||'))
one() {
  local t=$1 port=$2 env base server
  case $t in apps|cloudflare|reference) env=FOUNDATION_TEST_CLOUDFLARE;; slack) env=FOUNDATION_TEST_SLACK;; services) env=FOUNDATION_TEST_SERVICES;;
    aws) env=FOUNDATION_TEST_AWS;; ebay) env=FOUNDATION_TEST_EBAY;; openrouter) env=FOUNDATION_TEST_OPENROUTER;; payment) env=FOUNDATION_TEST_PAYMENT;; *) env=FOUNDATION_TEST_NONE;; esac
  env $env=1 FOUNDATION_TEST_PORT=$port node test/fixture-server.mjs > /dev/null 2>&1 &
  server=$!
  for _ in $(seq 50); do curl -s -o /dev/null http://127.0.0.1:$port/health && break; sleep 0.2; done
  # Passkeys need a hostname.
  case $t in merge|transfer|principals|reference|webauthn|key) base=http://localhost:$port;; *) base=http://127.0.0.1:$port;; esac
  mkdir -p "$out/$t"
  if timeout 240 python3 test/${t}_ui_test.py --base $base --screenshots "$out/$t" > "$out/$t.log" 2>&1; then echo "PASS $t"
  else echo "FAIL $t  ($out/$t.log)"; echo "$t" >> "$out/failed"; fi
  kill $server 2>/dev/null; wait $server 2>/dev/null
}
port=3620; running=0
for t in "${names[@]}"; do
  port=$((port+1)); one "$t" $port & running=$((running+1))
  if [ $running -ge $jobs ]; then wait -n; running=$((running-1)); fi
done
wait
[ ! -e "$out/failed" ]
