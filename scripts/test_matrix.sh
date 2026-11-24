#!/bin/sh
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
tmpdir="/tmp/ap-matrix-$$"
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

sock="$tmpdir/negative.sock"
store="$tmpdir/negative.jsonl"
out="$tmpdir/negative.out"
"$root/out/ap" --json --verbose --duration 1600 --no-proc-scan --socket "$sock" --store "$store" > "$out" 2>&1 &
engine=$!
wait_active "$out" "$engine"
"$root/build/inject" "$sock" clean 40
"$root/build/inject" "$sock" weak 1
"$root/build/inject" "$sock" exec 1
"$root/build/inject" "$sock" badabi 1
wait "$engine"

if grep -F -q '"rule": "' "$out"; then
  echo "false positive: clean and weak events produced a finding" >&2
  exit 1
fi
grep -q '"findings": 0' "$out"
grep -q '"invalid": 1' "$out"

sock="$tmpdir/positive.sock"
store="$tmpdir/positive.jsonl"
out="$tmpdir/positive.out"
"$root/out/ap" --json --verbose --duration 1600 --no-proc-scan --socket "$sock" --store "$store" > "$out" 2>&1 &
engine=$!
wait_active "$out" "$engine"
"$root/build/inject" "$sock" wx 1
"$root/build/inject" "$sock" exec 1
for name in shadowcall shadowret raw wxregion flowstrong net net6 heap; do
  "$root/build/inject" "$sock" "$name" 1
done
"$root/build/inject" "$sock" kernelchain 1
wait "$engine"

for rule in shadow_mismatch raw_socket wx_region exec_after_wx return_outside_exec tcp_flag_violation double_free; do
  grep -q "\"rule\": \"$rule\"" "$out"
done
grep -q 'kernel_chain' "$out"
grep -q '"rules": \["kernel_interface", "kernel_chain"\]' "$out"
findings=$(grep -o '"findings": [0-9]*' "$out" | tail -1 | awk '{print $2}')
[ "$findings" -ge 10 ]
echo "detection matrix tests: ok"
