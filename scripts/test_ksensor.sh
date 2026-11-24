#!/bin/sh
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
tmpdir="/tmp/ap-ksensor-$$"
mkdir -p "$tmpdir"
trap 'rm -rf "$tmpdir"' EXIT INT TERM

fail() {
  echo "kernel sensor tests: $*" >&2
  exit 1
}

sock="$tmpdir/ap.sock"
store="$tmpdir/ap.jsonl"
out="$tmpdir/out"

timeout 20 "$root/out/ap" --json --verbose --duration 400 --no-proc-scan \
  --socket "$sock" --store "$store" --kernel-sensor > "$out" 2>&1

grep -q '"ksensor":' "$out" || fail 'missing ksensor source state'
grep -q '"lsm":' "$out" || fail 'missing lsm source state'
if grep -q '"ksensor": "disabled"' "$out"; then
  fail 'requested kernel sensor must not report disabled'
fi
if grep -q '"ksensor": "unavailable"' "$out"; then
  grep -q '"source": "ksensor"' "$out" || fail 'missing ksensor degraded line'
  grep -q '"state": "unavailable"' "$out" || fail 'missing ksensor degraded state'
fi
grep -q '"ksensor_events"' "$out" || fail 'missing ksensor event counter'
grep -q '"ksensor_invalid"' "$out" || fail 'missing ksensor invalid counter'
grep -q '"ksensor_dropped"' "$out" || fail 'missing ksensor drop counter'
grep -q '"ksensor_attached"' "$out" || fail 'missing ksensor attach counter'
grep -q '"lsm_active"' "$out" || fail 'missing lsm state counter'
grep -q '"lsm_denies"' "$out" || fail 'missing lsm deny counter'

sock2="$tmpdir/lsm.sock"
store2="$tmpdir/lsm.jsonl"
out2="$tmpdir/lsm.out"
timeout 20 "$root/out/ap" --json --duration 300 --no-proc-scan \
  --socket "$sock2" --store "$store2" --lsm-enforce --lsm-mask 0x1 > "$out2" 2>&1

grep -q '"lsm":' "$out2" || fail 'missing lsm source state in enforce run'
grep -q '"lsm_active"' "$out2" || fail 'missing lsm state in enforce summary'
grep -q '"lsm_denies"' "$out2" || fail 'missing lsm denies in enforce summary'
if grep -q '"lsm": "unavailable"' "$out2"; then
  grep -q '"source": "lsm"' "$out2" || fail 'missing lsm degraded line'
fi
"$root/out/ap" --verify-store "$store" > "$tmpdir/verify" 2>&1 || \
  fail 'audit store verification failed'

echo "kernel sensor tests: ok"
