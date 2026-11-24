#!/bin/sh
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
tmpdir=$(mktemp -d)
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
  # the engine exits immediately with --once unless a tracer is active, so the
  # duration keeps the ipc socket alive while the fixture is injected.
  "$root/out/ap" --json --verbose --duration 1500 --no-proc-scan \
    --socket "$sock" --store "$store" > "$out" 2>&1 &
  engine=$!
  wait_active "$out" "$engine"
  "$root/build/inject" "$sock" "$fixture" 1
  wait "$engine"
  [ -s "$store" ]
  grep -q '"state": "stopped"' "$out"
}

run_case injection injectionchain
grep -q '"rule":"process_injection"' "$tmpdir/injection.jsonl"

run_case exploit exploitchain
grep -q '"rule":"exploit_chain"' "$tmpdir/exploit.jsonl"

run_case credential credchain
grep -q '"rule":"credential_dump"' "$tmpdir/credential.jsonl"

run_case benign ptrace
if grep -q '"rule":"process_injection"' "$tmpdir/benign.jsonl" ||
   grep -q '"rule":"exploit_chain"' "$tmpdir/benign.jsonl" ||
   grep -q '"rule":"credential_dump"' "$tmpdir/benign.jsonl"; then
  echo "benign single signal produced an intrusion finding" >&2
  exit 1
fi

echo "intrusion tests: ok"
