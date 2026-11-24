#!/bin/sh
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
tmpdir="/tmp/ap-limits-$$"
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
"$root/out/ap" --json --duration 1400 --socket "$sock" --store "$store" \
  --max-states 2 --queue-depth 8 > "$out" 2>&1 &
engine=$!
wait_active "$out" "$engine"
"$root/build/fuzz_inject" "$sock" findings 240
wait "$engine"

grep -q '"risk_states": 2' "$out"
grep -q '"queue_drops": [0-9]*' "$out"

sock="$tmpdir/b.sock"
store="$tmpdir/b.jsonl"
if "$root/out/ap" --queue-depth 0 --duration 1 --socket "$sock" --store "$store" \
    > "$tmpdir/reject.out" 2>&1; then
  echo "zero queue depth was accepted" >&2
  exit 1
fi
grep -q 'bad queue depth' "$tmpdir/reject.out"

echo "limit tests: ok"
