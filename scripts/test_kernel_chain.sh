#!/bin/sh
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
tmpdir="/tmp/ap-kchain-$$"
mkdir -p "$tmpdir"
trap 'rm -rf "$tmpdir"' EXIT INT TERM

sock="$tmpdir/s.sock"
store="$tmpdir/store.jsonl"
out="$tmpdir/out"

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

status=0
timeout 20 "$root/out/ap" --json --verbose --once --no-proc-scan --socket "$sock" \
  --store "$store" --trace "$root/build/kernel_probe" > "$out" 2>&1 || status=$?

if grep -q '"ptrace": "unavailable"' "$out" || grep -q '"reason": "unsupported"' "$out"; then
  echo "kernel chain trace test: skipped (degraded)"
  exit 0
fi
[ "$status" -eq 0 ]
grep -q '"state": "stopped"' "$out"
grep -q '"rules": \["kernel_interface", "kernel_chain"\]' "$out"
grep -q '"rules":\["kernel_interface","kernel_chain"\]' "$store"

sock2="$tmpdir/g.sock"
store2="$tmpdir/guard.jsonl"
out2="$tmpdir/guard.out"
status2=0
timeout 20 "$root/out/ap" --json --guard --deny kernel_chain --threshold 10 \
  --once --no-proc-scan --socket "$sock2" --store "$store2" \
  --trace "$root/build/kernel_probe" > "$out2" 2>&1 || status2=$?

if grep -q '"ptrace": "unavailable"' "$out2" || grep -q '"reason": "unsupported"' "$out2"; then
  echo "kernel chain guard test: skipped (degraded)"
  exit 0
fi
[ "$status2" -eq 0 ]
grep -q '"action": "denied"' "$out2"
grep -q '"rules": \["kernel_interface", "kernel_chain"\]' "$out2"
grep -q '"policy": "deny:kernel_chain' "$out2"
grep -q '"audit":"denied:kernel_chain"' "$store2"
grep -q '"enforcement"' "$out2"
grep -q '"backend": "ptrace_seccomp_stop"' "$out2"
grep -q '"lsm": "unavailable"' "$out2"
grep -q '"kernel_compromise": "unprotected"' "$out2"

sock3="$tmpdir/c.sock"
store3="$tmpdir/correlation.jsonl"
out3="$tmpdir/correlation.out"
"$root/out/ap" --json --verbose --duration 1600 --no-proc-scan \
  --socket "$sock3" --store "$store3" > "$out3" 2>&1 &
engine=$!
wait_active "$out3" "$engine"
"$root/build/inject" "$sock3" setid 1
"$root/build/inject" "$sock3" bpf 1
"$root/build/inject" "$sock3" ptrace 1
wait "$engine"

grep -q '"rules": \["kernel_interface", "kernel_chain"\]' "$out3"
grep -q '"rule":"privilege_crossing"' "$store3"
grep -F -q '"detail":"kernel_chain:bpf+ptrace"' "$store3"
grep -F -q '"detail":"privilege_crossing:bpf+setid"' "$store3"

echo "kernel chain trace tests: ok"
