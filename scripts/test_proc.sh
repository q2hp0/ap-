#!/bin/sh
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
tmpdir="/tmp/ap-proc-$$"
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

sock="$tmpdir/proc.sock"
store="$tmpdir/proc.jsonl"
out="$tmpdir/proc.out"
"$root/out/ap" --json --duration 3000 --proc-interval-ms 200 --proc-max-pids 512 \
  --proc-map-samples 16 --proc-wx-per-scan 8 \
  --socket "$sock" --store "$store" > "$out" 2>&1 &
engine=$!
wait_active "$out" "$engine"
sleep 0.6 &
workload=$!
wait "$workload"
wait "$engine"

grep -F -q '"type": "process_start"' "$out"
grep -F -q '"type": "process_exit"' "$out"
grep -F -q '"sources": ["ipc","proc"]' "$out"
grep -F -q '"wx_regions":' "$out"
grep -F -q '"proc_scans":' "$out"
grep -F -q '"map_samples": 16' "$out"
grep -F -q '"wx_per_scan": 8' "$out"

sock="$tmpdir/off.sock"
store="$tmpdir/off.jsonl"
out="$tmpdir/off.out"
"$root/out/ap" --json --duration 500 --no-proc-scan \
  --socket "$sock" --store "$store" > "$out" 2>&1
grep -F -q '"proc": "disabled"' "$out"
if grep -F -q '"wx_regions":' "$out"; then
  echo "disabled proc collector still reported counters" >&2
  exit 1
fi

if "$root/out/ap" --json --duration 100 --proc-map-samples 33 \
  --socket "$tmpdir/invalid-maps.sock" --store "$tmpdir/invalid-maps.jsonl" \
  > "$tmpdir/invalid-maps.out" 2>&1; then
  echo "invalid proc map sample count was accepted" >&2
  exit 1
fi
grep -F -q 'bad proc map sample count' "$tmpdir/invalid-maps.out"
if "$root/out/ap" --json --duration 100 --proc-wx-per-scan 17 \
  --socket "$tmpdir/invalid-wx.sock" --store "$tmpdir/invalid-wx.jsonl" \
  > "$tmpdir/invalid-wx.out" 2>&1; then
  echo "invalid proc wx limit was accepted" >&2
  exit 1
fi
grep -F -q 'bad proc wx limit' "$tmpdir/invalid-wx.out"

echo "process telemetry tests: ok"
