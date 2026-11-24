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
  expected=$3
  sock="$tmpdir/$case_name.sock"
  store="$tmpdir/$case_name.jsonl"
  out="$tmpdir/$case_name.out"
  # the engine exits on its duration, so the socket stays alive while the
  # fixture is injected through the authenticated ipc path.
  "$root/out/ap" --json --verbose --duration 1500 --no-proc-scan \
    --socket "$sock" --store "$store" > "$out" 2>&1 &
  engine=$!
  wait_active "$out" "$engine"
  "$root/build/inject" "$sock" "$fixture" 1
  wait "$engine"
  [ -s "$store" ]
  grep -q '"state": "stopped"' "$out"
  if [ "$expected" = none ]; then
    if grep -q '"rule":"file_write_burst"' "$store"; then
      echo "unexpected write burst for $case_name" >&2
      return 1
    fi
    if grep -q '"rule":"destructive_chain"' "$store"; then
      echo "unexpected destructive chain for $case_name" >&2
      return 1
    fi
    if grep -q '"rule":"data_exfiltration"' "$store"; then
      echo "unexpected exfiltration for $case_name" >&2
      return 1
    fi
  else
    grep -q "\"rule\":\"$expected\"" "$store"
  fi
}

run_case fileburst fileburst file_write_burst
run_case destructive destructive destructive_chain
run_case exfil exfil data_exfiltration
run_case filebenign filebenign none
echo "destructive chain tests: ok"
