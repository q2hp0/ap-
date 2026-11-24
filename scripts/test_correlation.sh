#!/bin/sh
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
tmpdir="/tmp/ap-correlation-$$"
mkdir -p "$tmpdir"
trap 'rm -rf "$tmpdir"' EXIT INT TERM

fail() {
  echo "correlation tests: $*" >&2
  exit 1
}

fixture="$tmpdir/events.apk1"
sock="$tmpdir/ap.sock"
store="$tmpdir/ap.jsonl"
out="$tmpdir/out"

"$root/build/kernel_fixture" "$fixture"
timeout 20 "$root/out/ap" --json --duration 900 --no-proc-scan \
  --socket "$sock" --store "$store" --kernel-events "$fixture" > "$out" 2>&1

grep -q '"graph_added": [1-9][0-9]*' "$out" || fail 'no graph observations recorded'
grep -q '"graph_evicted": 0' "$out" || fail 'unexpected graph eviction'
grep -q '"graph_suppressed": [0-9]' "$out" || fail 'missing graph suppression counter'
grep -q '"evidence_inserted": [0-9]' "$out" || fail 'missing evidence counter'
grep -q '"evidence_duplicates": [0-9]' "$out" || fail 'missing duplicate counter'
grep -q '"beacon_findings": [0-9]' "$out" || fail 'missing beacon counter'
grep -q '"risk_findings": [0-9]' "$out" || fail 'missing risk counter'

"$root/out/ap" --verify-store "$store" > "$tmpdir/verify" 2>&1 || \
  fail 'audit store verification failed'

echo "correlation tests: ok"
