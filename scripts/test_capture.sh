#!/bin/sh
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
tmpdir="/tmp/ap-capture-$$"
mkdir -p "$tmpdir"
trap 'rm -rf "$tmpdir"' EXIT INT TERM

frames="$tmpdir/frames.bin"
sock="$tmpdir/s.sock"
store="$tmpdir/store.jsonl"
out="$tmpdir/out"

"$root/build/capture_fixture" "$frames" 4

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

"$root/out/ap" --json --verbose --duration 1500 --no-proc-scan \
  --capture --capture-file "$frames" --socket "$sock" --store "$store" \
  > "$out" 2>&1 &
engine=$!
wait_active "$out" "$engine"
wait "$engine"

grep -q '"capture": "active"' "$out"
grep -q '"source":"capture"' "$store"
grep -q '"rule":"tcp_flag_violation"' "$store"
grep -q '"capture_frames": *4' "$out"
grep -q '"capture_parsed": *4' "$out"
grep -q '"capture_truncated": *0' "$out"
grep -q '"packet_capture": "unavailable"' "$out"

echo "capture tests: ok"
