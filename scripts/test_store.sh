#!/bin/sh
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
tmpdir="/tmp/ap-store-$$"
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
out="$tmpdir/a.out"
"$root/out/ap" --json --verbose --duration 1200 --socket "$sock" --store "$store" > "$out" 2>&1 &
engine=$!
wait_active "$out" "$engine"
"$root/build/inject" "$sock" clean 5
wait "$engine"

"$root/out/ap" --verify-store "$store" | grep -q '"state": "ok"'
grep -q '"integrity": "hmac_sha256"' "$out"
grep -q '"v":"hmac"' "$store"
[ -f "$store.key" ]
[ "$(stat -c %a "$store.key")" = "600" ]
records=$(grep -o '"recorded": [0-9]*' "$out" | tail -1 | awk '{print $2}')
[ "$records" -ge 5 ]

sed -i 's/"type":"process"/"type":"tampered"/' "$store"
if "$root/out/ap" --verify-store "$store" > "$tmpdir/verify.out" 2>&1; then
  echo "store verifier accepted tampered records" >&2
  exit 1
fi
grep -q 'hash mismatch' "$tmpdir/verify.out"

echo "store tests: ok"
