#!/bin/sh
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
bin="$root/out/ap"
tmpdir="/tmp/ap-update-$$"
mkdir -p "$tmpdir"
trap 'rm -rf "$tmpdir"' EXIT INT TERM

fail() {
  echo "update tests: $*" >&2
  exit 1
}

check_line() {
  grep -q "$1" "$2" || fail "missing $1 in $2"
}

expect_fail() {
  expected=$1
  shift
  if "$@" >"$tmpdir/out" 2>"$tmpdir/err"; then
    fail "expected failure: $expected"
  fi
  grep -q "$expected" "$tmpdir/err" || fail "expected $expected, got $(cat "$tmpdir/err")"
}

bundle="$tmpdir/bundle"
mkdir -p "$bundle/bin" "$bundle/etc"
printf 'tool bytes' > "$bundle/bin/tool"
printf 'note' > "$bundle/etc/note"
chmod 600 "$bundle/bin/tool" "$bundle/etc/note"
tool_hash=$(sha256sum "$bundle/bin/tool" | awk '{print $1}')
note_hash=$(sha256sum "$bundle/etc/note" | awk '{print $1}')
manifest="$bundle/bundle.manifest"
printf 'ap_update_v1\nfile=bin/tool 10 %s\nfile=etc/note 4 %s\n' \
  "$tool_hash" "$note_hash" > "$manifest"
chmod 600 "$manifest"

"$bin" --seal-update "$manifest" > "$tmpdir/out"
check_line '"state": "sealed"' "$tmpdir/out"
check_line '"entries": 2' "$tmpdir/out"
[ -f "$manifest.key" ] || fail "missing update key"
[ "$(stat -c %a "$manifest.key")" = 600 ] || fail "update key mode is not 0600"

"$bin" --verify-update "$manifest" > "$tmpdir/out"
check_line '"state": "ok"' "$tmpdir/out"
check_line '"entries": 2' "$tmpdir/out"
check_line '"bytes": 14' "$tmpdir/out"

staged="$tmpdir/staged"
"$bin" --stage-update "$manifest" "$staged" > "$tmpdir/out"
check_line '"state": "staged"' "$tmpdir/out"
check_line '"entries": 2' "$tmpdir/out"
check_line '"bytes": 14' "$tmpdir/out"
cmp -s "$bundle/bin/tool" "$staged/bin/tool" || fail "staged tool differs"
cmp -s "$bundle/etc/note" "$staged/etc/note" || fail "staged note differs"
[ "$(stat -c %a "$staged")" = 700 ] || fail "staging directory mode is not 0700"
[ "$(stat -c %a "$staged/bin/tool")" = 600 ] || fail "staged file mode is not 0600"
expect_fail 'update destination already exists' "$bin" --stage-update "$manifest" "$staged"

install_root="$tmpdir/install"
mkdir -p "$install_root"
chmod 700 "$install_root"
"$bin" --install-update "$manifest" "$install_root" > "$tmpdir/out"
check_line '"state": "installed"' "$tmpdir/out"
check_line '"entries": 2' "$tmpdir/out"
check_line '"bytes": 14' "$tmpdir/out"
grep -q '"release": "[0-9a-f]\{32\}"' "$tmpdir/out" || fail "missing release id"
check_line 'active=' "$install_root/state"
check_line 'previous=none' "$install_root/state"
active=$(sed -n 's/^active=//p' "$install_root/state")
cmp -s "$bundle/bin/tool" "$install_root/releases/$active/bin/tool" || fail "installed tool differs"
cmp -s "$bundle/etc/note" "$install_root/releases/$active/etc/note" || fail "installed note differs"
[ -f "$install_root/releases/$active/manifest" ] || fail "missing release manifest"
[ -f "$install_root/releases/$active/manifest.key" ] || fail "missing release key"
[ "$(stat -c %a "$install_root/releases/$active/manifest")" = 600 ] || fail "release manifest mode is not 0600"
[ "$(stat -c %a "$install_root/releases/$active/manifest.key")" = 600 ] || fail "release key mode is not 0600"
expect_fail 'update has no previous release' "$bin" --rollback-update "$install_root"

bundle2="$tmpdir/bundle2"
mkdir -p "$bundle2/bin"
printf 'tool two' > "$bundle2/bin/tool"
chmod 600 "$bundle2/bin/tool"
tool2_hash=$(sha256sum "$bundle2/bin/tool" | awk '{print $1}')
manifest2="$bundle2/bundle.manifest"
printf 'ap_update_v1\nfile=bin/tool 8 %s\n' "$tool2_hash" > "$manifest2"
chmod 600 "$manifest2"
"$bin" --seal-update "$manifest2" > "$tmpdir/out"
"$bin" --install-update "$manifest2" "$install_root" > "$tmpdir/out"
check_line '"state": "installed"' "$tmpdir/out"
check_line '"entries": 1' "$tmpdir/out"
check_line '"bytes": 8' "$tmpdir/out"
active2=$(sed -n 's/^active=//p' "$install_root/state")
[ "$active2" != "$active" ] || fail "active release did not change"
grep -q "^previous=$active$" "$install_root/state" || fail "previous release not recorded"
cmp -s "$bundle2/bin/tool" "$install_root/releases/$active2/bin/tool" || fail "second tool differs"

printf 'tool byteZ' > "$install_root/releases/$active/bin/tool"
chmod 600 "$install_root/releases/$active/bin/tool"
expect_fail 'update payload hash mismatch' "$bin" --rollback-update "$install_root"
printf 'tool bytes' > "$install_root/releases/$active/bin/tool"
chmod 600 "$install_root/releases/$active/bin/tool"

"$bin" --rollback-update "$install_root" > "$tmpdir/out"
check_line '"state": "rolled_back"' "$tmpdir/out"
grep -q "\"release\": \"$active\"" "$tmpdir/out" || fail "wrong rollback release"
rolled=$(sed -n 's/^active=//p' "$install_root/state")
[ "$rolled" = "$active" ] || fail "active release did not roll back"
grep -q "^previous=$active2$" "$install_root/state" || fail "rollback state did not swap"
cmp -s "$bundle/bin/tool" "$install_root/releases/$rolled/bin/tool" || fail "rolled back tool differs"
[ "$(find "$install_root/releases" -mindepth 1 -maxdepth 1 -type d | wc -l)" = 2 ] || fail "release count is unbounded"

badroot="$tmpdir/badroot"
mkdir -p "$badroot"
chmod 775 "$badroot"
expect_fail 'update root must not be group or other writable' "$bin" --install-update "$manifest" "$badroot"

printf 'tool byteX' > "$bundle/bin/tool"
chmod 600 "$bundle/bin/tool"
expect_fail 'update payload hash mismatch' "$bin" --verify-update "$manifest"
printf 'tool bytes' > "$bundle/bin/tool"
chmod 600 "$bundle/bin/tool"
"$bin" --verify-update "$manifest" > "$tmpdir/out"
check_line '"state": "ok"' "$tmpdir/out"

sed -i 's/file=bin\/tool /file=bin\/toolx /' "$manifest"
chmod 600 "$manifest"
expect_fail 'update mac mismatch' "$bin" --verify-update "$manifest"
sed -i 's/file=bin\/toolx /file=bin\/tool /' "$manifest"
chmod 600 "$manifest"
"$bin" --verify-update "$manifest" > "$tmpdir/out"
check_line '"state": "ok"' "$tmpdir/out"

xhash=$(printf 'x' | sha256sum | awk '{print $1}')
bad="$tmpdir/bad.manifest"
for relative in '../escape' '/tmp/escape' 'bin/../escape' 'bin//tool' 'bin/tool/'; do
  printf 'ap_update_v1\nfile=%s 1 %s\n' "$relative" "$xhash" > "$bad"
  chmod 600 "$bad"
  expect_fail 'unsafe update path' "$bin" --seal-update "$bad"
done
for relative in 'manifest' 'manifest.key' 'manifest.approval.key'; do
  printf 'ap_update_v1\nfile=%s 1 %s\n' "$relative" "$xhash" > "$bad"
  chmod 600 "$bad"
  expect_fail 'reserved update path' "$bin" --seal-update "$bad"
done

rm "$bundle/bin/tool"
ln -s "$bundle/etc/note" "$bundle/bin/tool"
expect_fail 'update payload must be a regular file' "$bin" --verify-update "$manifest"
rm "$bundle/bin/tool"
expect_fail 'update payload unreadable' "$bin" --verify-update "$manifest"

bundle3="$tmpdir/bundle3"
mkdir -p "$bundle3/bin"
printf 'approved' > "$bundle3/bin/tool"
chmod 600 "$bundle3/bin/tool"
approved_hash=$(sha256sum "$bundle3/bin/tool" | awk '{print $1}')
manifest3="$bundle3/bundle.manifest"
printf 'ap_update_v1\nfile=bin/tool 8 %s\n' "$approved_hash" > "$manifest3"
chmod 600 "$manifest3"
"$bin" --seal-update "$manifest3" --require-approval > "$tmpdir/out"
check_line '"state": "sealed"' "$tmpdir/out"
[ -f "$manifest3.approval.key" ] || fail "missing approval key"
[ "$(stat -c %a "$manifest3.approval.key")" = 600 ] || fail "approval key mode is not 0600"
"$bin" --verify-update "$manifest3" --require-approval > "$tmpdir/out"
check_line '"state": "ok"' "$tmpdir/out"
check_line '"bytes": 8' "$tmpdir/out"
expect_fail 'update approval missing' "$bin" --verify-update "$manifest" --require-approval

approval_root="$tmpdir/approval-install"
mkdir -p "$approval_root"
chmod 700 "$approval_root"
"$bin" --install-update "$manifest3" "$approval_root" --require-approval > "$tmpdir/out"
active3=$(sed -n 's/^active=//p' "$approval_root/state")
[ -f "$approval_root/releases/$active3/manifest.approval.key" ] || fail "missing stored approval key"
[ "$(stat -c %a "$approval_root/releases/$active3/manifest.approval.key")" = 600 ] || fail "stored approval key mode is not 0600"
"$bin" --activation-plan "$approval_root" --require-approval > "$tmpdir/out"
check_line '"state": "plan"' "$tmpdir/out"
check_line "\"active\": \"$active3\"" "$tmpdir/out"
check_line '"executed": false' "$tmpdir/out"

bundle4="$tmpdir/bundle4"
mkdir -p "$bundle4/bin"
printf 'second' > "$bundle4/bin/tool"
chmod 600 "$bundle4/bin/tool"
approved2_hash=$(sha256sum "$bundle4/bin/tool" | awk '{print $1}')
manifest4="$bundle4/bundle.manifest"
printf 'ap_update_v1\nfile=bin/tool 6 %s\n' "$approved2_hash" > "$manifest4"
chmod 600 "$manifest4"
"$bin" --seal-update "$manifest4" --require-approval > "$tmpdir/out"
"$bin" --install-update "$manifest4" "$approval_root" --require-approval > "$tmpdir/out"

stored_approval="$approval_root/releases/$active3/manifest.approval.key"
dd if=/dev/zero of="$stored_approval" bs=32 count=1 2>/dev/null
chmod 600 "$stored_approval"
expect_fail 'update approval mac mismatch' "$bin" --rollback-update "$approval_root" --require-approval
cp "$manifest3.approval.key" "$stored_approval"
chmod 600 "$stored_approval"
"$bin" --rollback-update "$approval_root" --require-approval > "$tmpdir/out"
check_line '"state": "rolled_back"' "$tmpdir/out"
check_line "\"release\": \"$active3\"" "$tmpdir/out"

echo "update tests: ok"
