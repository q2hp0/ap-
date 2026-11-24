#!/bin/sh
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
sock="/tmp/ap-int-$$.sock"
store="/tmp/ap-int-$$.jsonl"
out="/tmp/ap-int-$$.out"

"$root/out/ap" --json --duration 2500 --socket "$sock" --store "$store" > "$out" 2>&1 &
engine=$!
sleep 0.4
for name in wx net heap module badabi; do
  "$root/build/inject" "$sock" "$name" 1
done
wait "$engine"

grep -q '"rule": "wx_transition"' "$out"
grep -q '"rule": "tcp_flag_violation"' "$out"
grep -q '"rule": "double_free"' "$out"
grep -q '"rule": "module_load"' "$out"
grep -q '"state": "stopped"' "$out"
grep -q '"invalid": 1' "$out"
grep -q '"action": "investigating"' "$out"
echo "integration tests: ok"
rm -f "$out" "$sock" "$store"
