#!/bin/sh
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
tmpdir="/tmp/ap-detectors-$$"
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

sock="$tmpdir/disabled.sock"
store="$tmpdir/disabled.jsonl"
out="$tmpdir/disabled.out"
"$root/out/ap" --json --duration 1800 --socket "$sock" --store "$store" --disable wx_transition > "$out" 2>&1 &
engine=$!
wait_active "$out" "$engine"
"$root/build/inject" "$sock" wx 1
"$root/build/inject" "$sock" net 1
wait "$engine"

if grep -F -q '"rule": "wx_transition"' "$out"; then
  echo "disabled wx_transition still produced a finding" >&2
  exit 1
fi
grep -F -q '"rule": "tcp_flag_violation"' "$out"
grep -F -q '"enabled": 31' "$out"
grep -q '"name":"wx_transition".*"enabled":false' "$out"
grep -q '"name":"tcp_flag_violation".*"enabled":true' "$out"

sock="$tmpdir/allow.sock"
store="$tmpdir/allow.jsonl"
out="$tmpdir/allow.out"
"$root/out/ap" --json --duration 1800 --socket "$sock" --store "$store" \
  --enable wx_transition,tcp_flag_violation > "$out" 2>&1 &
engine=$!
wait_active "$out" "$engine"
"$root/build/inject" "$sock" wx 1
"$root/build/inject" "$sock" net 1
"$root/build/inject" "$sock" heap 1
wait "$engine"

grep -F -q '"rule": "wx_transition"' "$out"
grep -F -q '"rule": "tcp_flag_violation"' "$out"
if grep -F -q '"rule": "double_free"' "$out"; then
  echo "unlisted double_free detector produced a finding" >&2
  exit 1
fi
grep -F -q '"enabled": 2' "$out"
grep -q '"name":"double_free".*"enabled":false' "$out"

sock="$tmpdir/empty.sock"
store="$tmpdir/empty.jsonl"
out="$tmpdir/empty.out"
status=0
"$root/out/ap" --json --disable all --socket "$sock" --store "$store" > "$out" 2>&1 || status=$?
if [ "$status" -ne 1 ]; then
  echo "empty detector set did not fail with status 1" >&2
  exit 1
fi
grep -F -q 'no detectors enabled' "$out"

echo "detector tests: ok"
