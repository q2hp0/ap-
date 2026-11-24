#!/bin/sh
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
sock="/tmp/ap-guard-$$.sock"
store="/tmp/ap-guard-$$.jsonl"
out="/tmp/ap-guard-$$.out"
engine=0

cleanup() {
  if [ "$engine" -ne 0 ]; then
    kill "$engine" 2>/dev/null || true
    wait "$engine" 2>/dev/null || true
  fi
  rm -f "$out" "$sock" "$store"
}
trap cleanup EXIT INT TERM

"$root/out/ap" --json --guard --deny wx_transition --threshold 10 \
  --duration 2500 --socket "$sock" --store "$store" \
  --trace "$root/build/rwx_probe" > "$out" 2>&1 &
engine=$!

ready=0
index=0
while [ "$index" -lt 250 ]; do
  if grep -q '"state": "active"' "$out" 2>/dev/null; then
    ready=1
    break
  fi
  kill -0 "$engine" 2>/dev/null || break
  sleep 0.02
  index=$((index + 1))
done
[ "$ready" -eq 1 ]

"$root/build/inject" "$sock" wx 1
wait "$engine"
engine=0

denials=$(grep -o '"denials": [0-9]*' "$out" | tail -1 | awk '{print $2}')
[ "$denials" -ge 2 ]
grep -q '"action": "denied"' "$out"
grep -q '"rule": "wx_transition"' "$out"
grep -q 'mprotect=-1 errno=1' "$out"
grep -q '"audit":"denied:wx_transition"' "$store"
echo "guard tests: ok"
