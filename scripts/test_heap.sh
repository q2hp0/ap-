#!/bin/sh
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
sock="/tmp/ap-heap-$$.sock"
out="/tmp/ap-heap-$$.out"
link="/tmp/ap-heap-$$.so"
ln -sf "$root/build/libapheap.so" "$link"

"$root/build/heap_recv" "$sock" 3 > "$out" &
receiver=$!
sleep 0.2
AP_SOCKET="$sock" LD_PRELOAD="$link" "$root/build/heap_probe" >/dev/null
wait "$receiver"

grep -q '^1 trailing_canary$' "$out"
grep -q '^2 double_free$' "$out"
grep -q '^3 invalid_free_header$' "$out"
echo "heap guard tests: ok"
rm -f "$out" "$sock" "$link"
