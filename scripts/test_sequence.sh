#!/bin/sh
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
tmpdir="/tmp/ap-sequence-$$"
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
"$root/out/ap" --json --verbose --duration 1200 --socket "$sock" --store "$store" \
  --ipc-strict-seq > "$out" 2>&1 &
engine=$!
wait_active "$out" "$engine"
"$root/build/inject" "$sock" staleseq
wait "$engine"

grep -q '"ipc_sequence_drops": 1' "$out"
grep -q '"ipc_duplicates": 0' "$out"
events=$(grep -o '"events": [0-9]*' "$out" | tail -1 | awk '{print $2}')
[ "$events" -ge 2 ]

echo "sequence tests: ok"
