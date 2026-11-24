#!/bin/sh
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
tmpdir="/tmp/ap-audit-process-$$"
mkdir -p "$tmpdir"
trap 'rm -rf "$tmpdir"' EXIT INT TERM

wait_active() {
  wait_out=$1
  wait_pid=$2
  wait_index=0
  while [ "$wait_index" -lt 250 ]; do
    if grep -q '"state": "active"' "$wait_out" 2>/dev/null; then
      return 0
    fi
    kill -0 "$wait_pid" 2>/dev/null || return 1
    sleep 0.02
    wait_index=$((wait_index + 1))
  done
  return 1
}

sock="$tmpdir/a.sock"
store="$tmpdir/a.jsonl"
key="$tmpdir/shared.key"
out="$tmpdir/a.out"
"$root/out/ap" --json --verbose --duration 900 --no-proc-scan --socket "$sock" \
  --store "$store" --audit-process --audit-key "$key" > "$out" 2>&1 &
engine=$!
wait_active "$out" "$engine"
"$root/build/inject" "$sock" wx 1
wait "$engine"

grep -q '"backend": "process"' "$out"
grep -q '"process": true' "$out"
grep -q '"audit_writer_status": "complete"' "$out"
grep -q '"audit_writer_queued": [1-9]' "$out"
grep -q '"audit_writer_dropped": 0' "$out"
[ -f "$key" ]
[ "$(stat -c %a "$key")" = "600" ]
[ ! -e "$key.key" ]
"$root/out/ap" --verify-store "$store" --audit-key "$key" | grep -q '"state": "ok"'
grep -q '"v":"hmac"' "$store"

cp "$store" "$store.tamper"
sed -i 's/"mprotect"/"changed"/' "$store.tamper"
if "$root/out/ap" --verify-store "$store.tamper" --audit-key "$key" > /dev/null 2>&1; then
  echo "audit test fail: tampered store verified" >&2
  exit 1
fi

badkey="$tmpdir/bad.key"
mkdir "$badkey"
sock2="$tmpdir/b.sock"
store2="$tmpdir/b.jsonl"
out2="$tmpdir/b.out"
"$root/out/ap" --json --duration 600 --no-proc-scan --socket "$sock2" \
  --store "$store2" --audit-process --audit-key "$badkey" > "$out2" 2>&1 &
engine2=$!
wait_active "$out2" "$engine2"
wait "$engine2"

grep -q '"backend": "local"' "$out2"
grep -q '"process": true' "$out2"
grep -q '"audit_writer": "unavailable"' "$out2"
grep -q '"audit_writer_status": "failed"' "$out2"
grep -q '"integrity": "fnv1a"' "$out2"

echo "audit process tests: ok"
