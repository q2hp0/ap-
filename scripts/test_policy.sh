#!/bin/sh
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
tmpdir="/tmp/ap-policy-$$"
mkdir -p "$tmpdir"
engine=0

cleanup() {
  if [ "$engine" -ne 0 ]; then
    kill "$engine" 2>/dev/null || true
    wait "$engine" 2>/dev/null || true
  fi
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM

wait_active() {
  out=$1
  pid=$2
  index=0
  while [ "$index" -lt 250 ]; do
    if grep -q '"state": "active"' "$out" 2>/dev/null; then
      return 0
    fi
    kill -0 "$pid" 2>/dev/null || return 1
    sleep 0.02
    index=$((index + 1))
  done
  return 1
}

policy="$tmpdir/ap.policy"
sealed="$tmpdir/sealed.policy"
sock="$tmpdir/ap.sock"
store="$tmpdir/ap.jsonl"
sealout="$tmpdir/seal.out"
verifyout="$tmpdir/verify.out"
runout="$tmpdir/run.out"
overrideout="$tmpdir/override.out"
failout="$tmpdir/fail.out"

cat > "$policy" <<EOF
ap_policy_v1
guard=true
deny=wx_transition
threshold=10
no-proc-scan=true
socket=$sock
store=$store
EOF
chmod 600 "$policy"

"$root/out/ap" --seal-policy "$policy" > "$sealout" 2>&1
grep -q '"state": "sealed"' "$sealout"
grep -q '"entries": 6' "$sealout"
[ -f "$policy.key" ]
[ "$(stat -c %a "$policy.key")" = "600" ]

"$root/out/ap" --verify-policy "$policy" > "$verifyout" 2>&1
grep -q '"state": "ok"' "$verifyout"
grep -q '"entries": 6' "$verifyout"

cp "$policy" "$sealed"
sed -i 's/threshold=10/threshold=90/' "$policy"
if "$root/out/ap" --verify-policy "$policy" > "$failout" 2>&1; then
  echo "tampered policy verified"
  exit 1
fi
grep -q 'policy mac mismatch' "$failout"
if "$root/out/ap" --policy "$policy" --duration 100 >> "$failout" 2>&1; then
  echo "tampered policy loaded"
  exit 1
fi
grep -q 'policy load failed: policy mac mismatch' "$failout"
cp "$sealed" "$policy"

"$root/out/ap" --json --policy "$policy" --duration 1200 > "$runout" 2>&1 &
engine=$!
wait_active "$runout" "$engine"
grep -q '"mode": "guard"' "$runout"
grep -q '"source": "proc", "state": "disabled"' "$runout" || true
"$root/build/inject" "$sock" wx 1
wait "$engine"
engine=0

denials=$(grep -o '"denials": [0-9]*' "$runout" | tail -1 | awk '{print $2}')
[ "$denials" -ge 1 ]
grep -q '"action": "denied"' "$runout"
grep -q '"audit":"denied:wx_transition"' "$store"
grep -q '"integrity": "hmac_sha256"' "$runout"

rm -f "$store"
"$root/out/ap" --json --policy "$policy" --threshold 100 --deny double_free \
  --duration 1200 > "$overrideout" 2>&1 &
engine=$!
wait_active "$overrideout" "$engine"
"$root/build/inject" "$sock" wx 1
wait "$engine"
engine=0

overrides=$(grep -o '"denials": [0-9]*' "$overrideout" | tail -1 | awk '{print $2}')
[ "$overrides" -eq 0 ]
if grep -q '"action": "denied"' "$overrideout"; then
  echo "cli override did not replace policy"
  exit 1
fi

echo "policy tests: ok"
