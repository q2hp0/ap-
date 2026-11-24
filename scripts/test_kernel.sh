#!/bin/sh
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
tmpdir="/tmp/ap-kernel-$$"
mkdir -p "$tmpdir"
trap 'rm -rf "$tmpdir"' EXIT INT TERM

fixture="$tmpdir/events.apk1"
sock="$tmpdir/ap.sock"
store="$tmpdir/ap.jsonl"
out="$tmpdir/out"
"$root/build/kernel_fixture" "$fixture"

timeout 20 "$root/out/ap" --json --verbose --once --no-proc-scan \
  --socket "$sock" --store "$store" --kernel-events "$fixture" > "$out" 2>&1

grep -q '"state": "stopped"' "$out"
grep -q '"reason": "complete"' "$out"
grep -q '"kernel": "active"' "$out"
grep -q '"mode": "file"' "$out"
grep -q '"events": 6' "$out"
grep -q '"parsed": 6' "$out"
grep -q '"source": "kernel"' "$out"
grep -q '"sources":.*"kernel"' "$out"
grep -q '"kernel_events": 6' "$out"
grep -q '"kernel_parsed": 6' "$out"
grep -q '"kernel_invalid": 0' "$out"
grep -q '"kernel_errors": 0' "$out"

grep -q '"source":"kernel","type":"process"' "$store"
grep -q '"detail":"kernel_source_probe"' "$store"
grep -q '"detail":"kernel_chain:bpf+ptrace"' "$store"
grep -q '"detail":"privilege_crossing:bpf+ptrace+exec_uid_change"' "$store"
grep -q '"detail":"privilege_crossing:bpf+setid"' "$store"
if grep -q '"action": "denied"' "$out"; then
  echo "kernel replay must stay observational"
  exit 1
fi

sock2="$tmpdir/missing.sock"
store2="$tmpdir/missing.jsonl"
out2="$tmpdir/missing.out"
timeout 20 "$root/out/ap" --json --duration 250 --no-proc-scan \
  --socket "$sock2" --store "$store2" \
  --kernel-events "$tmpdir/missing.apk1" > "$out2" 2>&1

grep -q '"kernel": "unavailable"' "$out2"
grep -q '"source": "kernel",' "$out2"
grep -q '"state": "unavailable"' "$out2"
grep -q '"reason": "kernel event file open failed or invalid"' "$out2"
grep -q '"kernel_events": 0' "$out2"

echo "kernel tests: ok"
