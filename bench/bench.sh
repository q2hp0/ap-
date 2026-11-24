#!/bin/sh
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

tmpdir="/tmp/ap-bench-$$"
mkdir -p "$tmpdir"
engine=0
sampler=0
trap 'if [ "$engine" -ne 0 ]; then kill "$engine" 2>/dev/null || true; fi; if [ "$sampler" -ne 0 ]; then kill "$sampler" 2>/dev/null || true; fi; rm -rf "$tmpdir"' EXIT INT TERM

injected=${AP_BENCH_EVENTS:-20000}
duration=${AP_BENCH_DURATION_MS:-3000}
lat_duration=${AP_BENCH_LATENCY_MS:-2500}
ticks_per_second=$(getconf CLK_TCK)
host=$(uname -srm)
cpus=$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc)

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

sample_usage() {
  sample_pid=$1
  sample_out=$2
  : > "$sample_out"
  while kill -0 "$sample_pid" 2>/dev/null; do
    if [ -r "/proc/$sample_pid/stat" ]; then
      sample_ticks=$(awk '{print $14 + $15}' "/proc/$sample_pid/stat" 2>/dev/null || echo 0)
      sample_rss=$(awk '/VmHWM:/ {print $2}' "/proc/$sample_pid/status" 2>/dev/null || echo 0)
      printf '%s %s\n' "${sample_ticks:-0}" "${sample_rss:-0}" >> "$sample_out"
    fi
    sleep 0.05
  done
}

sock="$tmpdir/throughput.sock"
store="$tmpdir/throughput.jsonl"
out="$tmpdir/throughput.out"
usage="$tmpdir/throughput.usage"

"$root/out/ap" --json --duration "$duration" --no-proc-scan --socket "$sock" --store "$store" > "$out" 2>&1 &
engine=$!
sample_usage "$engine" "$usage" &
sampler=$!
wait_active "$out" "$engine"
start_ns=$(date +%s%N)
"$root/build/inject" "$sock" clean "$injected"
wait "$engine"
engine=0
wait "$sampler"
sampler=0
end_ns=$(date +%s%N)

accepted=$(grep -o '"events": [0-9]*' "$out" | tail -1 | awk '{print $2}')
uptime_ms=$(grep -o '"uptime_ms": [0-9]*' "$out" | tail -1 | awk '{print $2}')
abi=$(grep -o '"abi": [0-9]*' "$out" | head -1 | awk '{print $2}')
wall_ms=$(((end_ns - start_ns) / 1000000))
ticks=$(awk 'BEGIN { m = 0 } { if ($1 > m) m = $1 } END { print m + 0 }' "$usage")
rss_kb=$(awk 'BEGIN { m = 0 } { if ($2 > m) m = $2 } END { print m + 0 }' "$usage")
cpu_seconds=$(awk -v t="$ticks" -v h="$ticks_per_second" 'BEGIN { printf "%.3f", t / h }')
events_per_second=$(awk -v e="$accepted" -v u="$uptime_ms" 'BEGIN { if (u > 0) printf "%.1f", e * 1000 / u; else printf "0.0" }')

sock="$tmpdir/latency.sock"
store="$tmpdir/latency.jsonl"
out="$tmpdir/latency.out"
"$root/out/ap" --json --verbose --duration "$lat_duration" --no-proc-scan --socket "$sock" --store "$store" > "$out" 2>&1 &
engine=$!
wait_active "$out" "$engine"
start_ns=$(date +%s%N)
"$root/build/inject" "$sock" wx 1
latency_ms="unavailable"
index=0
while [ "$index" -lt 500 ]; do
  if grep -q '"rule": "wx_transition"' "$out" 2>/dev/null; then
    end_ns=$(date +%s%N)
    latency_ms=$(((end_ns - start_ns) / 1000000))
    break
  fi
  sleep 0.01
  index=$((index + 1))
done
kill "$engine" 2>/dev/null || true
wait "$engine" 2>/dev/null || true
engine=0
if [ "$latency_ms" = "unavailable" ]; then
  echo "bench: detection latency sample timed out" >&2
  exit 1
fi

sock="$tmpdir/trace.sock"
store="$tmpdir/trace.jsonl"
out="$tmpdir/trace.out"
usage="$tmpdir/trace.usage"
start_ns=$(date +%s%N)
"$root/out/ap" --json --once --duration 10000 --no-proc-scan --socket "$sock" --store "$store" \
  --trace /bin/sleep 0.2 > "$out" 2>&1 &
engine=$!
sample_usage "$engine" "$usage" &
sampler=$!
wait "$engine"
engine=0
wait "$sampler"
sampler=0
end_ns=$(date +%s%N)

trace_events=$(grep -o '"events": [0-9]*' "$out" | tail -1 | awk '{print $2}')
trace_uptime_ms=$(grep -o '"uptime_ms": [0-9]*' "$out" | tail -1 | awk '{print $2}')
trace_wall_ms=$(((end_ns - start_ns) / 1000000))
trace_ticks=$(awk 'BEGIN { m = 0 } { if ($1 > m) m = $1 } END { print m + 0 }' "$usage")
trace_rss_kb=$(awk 'BEGIN { m = 0 } { if ($2 > m) m = $2 } END { print m + 0 }' "$usage")
trace_cpu_seconds=$(awk -v t="$trace_ticks" -v h="$ticks_per_second" 'BEGIN { printf "%.3f", t / h }')

sock="$tmpdir/proc.sock"
store="$tmpdir/proc.jsonl"
out="$tmpdir/proc.out"
usage="$tmpdir/proc.usage"
"$root/out/ap" --json --duration 1200 --proc-interval-ms 200 --proc-max-pids 512 \
  --socket "$sock" --store "$store" > "$out" 2>&1 &
engine=$!
sample_usage "$engine" "$usage" &
sampler=$!
wait_active "$out" "$engine"
wait "$engine"
engine=0
wait "$sampler"
sampler=0

proc_events=$(grep -o '"events": [0-9]*' "$out" | tail -1 | awk '{print $2}')
proc_scans=$(grep -o '"scans": [0-9]*' "$out" | tail -1 | awk '{print $2}')
proc_uptime_ms=$(grep -o '"uptime_ms": [0-9]*' "$out" | tail -1 | awk '{print $2}')
proc_ticks=$(awk 'BEGIN { m = 0 } { if ($1 > m) m = $1 } END { print m + 0 }' "$usage")
proc_rss_kb=$(awk 'BEGIN { m = 0 } { if ($2 > m) m = $2 } END { print m + 0 }' "$usage")
proc_cpu_seconds=$(awk -v t="$proc_ticks" -v h="$ticks_per_second" 'BEGIN { printf "%.3f", t / h }')

printf '{\n'
printf '  "bench": {\n'
printf '    "host": "%s",\n' "$host"
printf '    "cpus": %s,\n' "$cpus"
printf '    "abi": %s,\n' "$abi"
printf '    "injected": %s,\n' "$injected"
printf '    "accepted": %s,\n' "$accepted"
printf '    "uptime_ms": %s,\n' "$uptime_ms"
printf '    "wall_ms": %s,\n' "$wall_ms"
printf '    "events_per_second": %s,\n' "$events_per_second"
printf '    "cpu_seconds": %s,\n' "$cpu_seconds"
printf '    "max_rss_kb": %s,\n' "$rss_kb"
printf '    "trace_events": %s,\n' "$trace_events"
printf '    "trace_uptime_ms": %s,\n' "$trace_uptime_ms"
printf '    "trace_wall_ms": %s,\n' "$trace_wall_ms"
printf '    "trace_cpu_seconds": %s,\n' "$trace_cpu_seconds"
printf '    "trace_max_rss_kb": %s,\n' "$trace_rss_kb"
printf '    "proc_events": %s,\n' "$proc_events"
printf '    "proc_scans": %s,\n' "$proc_scans"
printf '    "proc_uptime_ms": %s,\n' "$proc_uptime_ms"
printf '    "proc_cpu_seconds": %s,\n' "$proc_cpu_seconds"
printf '    "proc_max_rss_kb": %s,\n' "$proc_rss_kb"
printf '    "detection_latency_ms": %s\n' "$latency_ms"
printf '  }\n'
printf '}\n'
