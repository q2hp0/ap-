#!/bin/sh
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
tmpdir="/tmp/ap-entity-$$"
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

run_case() {
  case_name=$1
  fixture=$2
  sock="$tmpdir/$case_name.sock"
  store="$tmpdir/$case_name.jsonl"
  out="$tmpdir/$case_name.out"
  "$root/out/ap" --json --verbose --duration 1500 --no-proc-scan \
    --correlate-window-ms 1000 --socket "$sock" --store "$store" > "$out" 2>&1 &
  engine=$!
  wait_active "$out" "$engine"
  "$root/build/inject" "$sock" "$fixture" 1
  wait "$engine"
}

run_case positive entitychain
grep -q '"policy": "[^"]*correlate:1000ms' "$tmpdir/positive.out"
grep -q '"rule":"correlated_exploit_indicators"' "$tmpdir/positive.jsonl"
grep -F -q '"detail":"entity_chain:wx+exec+priv+net:pid+binary+peer+priv:10.9.8.7:4444"' \
  "$tmpdir/positive.jsonl"

run_case jit jitstream
grep -q '"rule":"wx_region"' "$tmpdir/jit.jsonl"
grep -q '"rule":"exec_after_wx"' "$tmpdir/jit.jsonl"
if grep -q '"rule":"correlated_exploit_indicators"' "$tmpdir/jit.jsonl"; then
  echo "benign jit stream produced an entity chain" >&2
  exit 1
fi

run_case container containerstream
if grep -q '"rule":"correlated_exploit_indicators"' "$tmpdir/container.jsonl"; then
  echo "benign container stream produced an entity chain" >&2
  exit 1
fi

echo "entity chain tests: ok"
