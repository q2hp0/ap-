#!/bin/sh
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
tmpdir="/tmp/ap-adversarial-$$"
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

sock="$tmpdir/noise.sock"
store="$tmpdir/noise.jsonl"
out="$tmpdir/noise.out"
"$root/out/ap" --json --duration 2200 --no-proc-scan --socket "$sock" --store "$store" > "$out" 2>&1 &
engine=$!
wait_active "$out" "$engine"
"$root/build/fuzz_inject" "$sock" 20000 0x5eed1234
"$root/build/fuzz_inject" "$sock" malformed
"$root/build/fuzz_inject" "$sock" tampered
"$root/build/fuzz_inject" "$sock" unsigned
wait "$engine"

if grep -F -q '"rule": "' "$out"; then
  echo "adversarial noise produced a finding" >&2
  exit 1
fi
grep -q '"findings": 0' "$out"
grep -q '"invalid": 4' "$out"
events=$(grep -o '"events": [0-9]*' "$out" | tail -1 | awk '{print $2}')
[ "$events" -ge 20000 ]

sock="$tmpdir/safe.sock"
store="$tmpdir/safe.jsonl"
out="$tmpdir/safe.out"
"$root/out/ap" --json --guard --deny wx_transition --threshold 100 \
  --max-states 2 --duration 1200 --socket "$sock" --store "$store" > "$out" 2>&1 &
engine=$!
wait_active "$out" "$engine"
"$root/build/inject" "$sock" wx 1
wait "$engine"

if grep -q '"action": "denied"' "$out"; then
  echo "guard denied below risk threshold" >&2
  exit 1
fi
grep -q '"denials": 0' "$out"

sock="$tmpdir/live.sock"
store="$tmpdir/live.jsonl"
out="$tmpdir/live.out"
"$root/out/ap" --json --guard --deny wx_transition --threshold 10 \
  --duration 1200 --socket "$sock" --store "$store" > "$out" 2>&1 &
engine=$!
wait_active "$out" "$engine"
"$root/build/inject" "$sock" wx 1
wait "$engine"

grep -q '"action": "denied"' "$out"
grep -q '"denials": 1' "$out"
echo "adversarial tests: ok"
