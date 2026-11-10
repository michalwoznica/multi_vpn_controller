#!/usr/bin/env bash
# C24A Stage 3 — v2.4.1 deterministic release + fake-root install/update/remove.
set -euo pipefail
umask 077
export LC_ALL=C

HERE=$(cd -- "${BASH_SOURCE[0]%/*}" && pwd -P)
ROOT=$(cd -- "$HERE/../.." && pwd -P)
BUILDER=$ROOT/source/build/build-mvc-monolith.sh
INSTALLER=$ROOT/source/tools/install-mvc.sh
DIST=$ROOT/dist/mvc
EMERGENCY=$ROOT/source/tools/recover-mvc-host-guard-local.sh
DUAL=$ROOT/source/tools/recover-mvc-dual-local.sh
PASS=0
FAIL=0
ok(){ printf 'PASS: %s\n' "$1"; PASS=$((PASS+1)); }
bad(){ printf 'FAIL: %s\n' "$1" >&2; FAIL=$((FAIL+1)); }

TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT
mkdir -p "$TMP/a" "$TMP/b"
"$BUILDER" "$TMP/a/mvc" >/dev/null
"$BUILDER" "$TMP/b/mvc" >/dev/null
A=$TMP/a/mvc
B=$TMP/b/mvc

cmp -s -- "$A" "$B" && ok 'v2.4.1 independent builds are byte-identical' || bad 'v2.4.1 independent builds are byte-identical'
cmp -s -- "$A" "$DIST" && ok 'checked-in v2.4.1 artifact equals fresh deterministic build' || bad 'checked-in v2.4.1 artifact equals fresh deterministic build'
info=$($A --monolith-build-info)
if grep -Fxq 'checkpoint=MVC_R6C_RUNTIME_MODULE_FILENAMES' <<<"$info" &&
   grep -Fxq 'authority=audited-dispatch-mvc-v241-candidate-physical-pending' <<<"$info"; then
    ok 'v2.4.1 provenance records candidate with physical proof pending'
else
    bad 'v2.4.1 provenance records candidate with physical proof pending'
fi

if grep -Fq 'preflight|list|status|connect|disconnect)' "$A" &&
   grep -Fq 'mvc24e_dispatch "$@"' "$A" &&
   ! grep -Fq 'mvc24mon_stage3b_refuse_lifecycle' "$A" &&
   ! grep -Fq 'return 78' < <(awk '/^mvc24mon_stage5_main\(\)/,/^}/' "$A"); then
    ok 'generated outer wrapper contains no Stage-3B lifecycle refusal and delegates to dispatcher'
else
    bad 'generated outer wrapper contains no Stage-3B lifecycle refusal and delegates to dispatcher'
fi

# Load the exact generated artifact without its final main call, replace only the
# already-proven internal dispatcher with a spy, and prove the outer wrapper
# preserves command/argument frames. No lifecycle function can run in this test.
sed '$d' "$A" > "$TMP/without-main"
run_spy() {
    local out
    out=$(BODY="$TMP/without-main" bash -s -- "$@" <<'SPY'
set -euo pipefail
body=$BODY
# shellcheck disable=SC1090
source "$body"
mvc24e_dispatch() {
    printf 'DISPATCH'
    printf '|%s' "$@"
    printf '\n'
}
mvc24mon_stage5_main "$@"
SPY
)
    printf '%s\n' "$out"
}
[[ $(run_spy preflight wg --split ovpn) == 'DISPATCH|preflight|wg|--split|ovpn' ]] && ok 'preflight wrapper preserves exact dispatcher frame' || bad 'preflight wrapper preserves exact dispatcher frame'
[[ $(run_spy connect wg --split ovpn) == 'DISPATCH|connect|wg|--split|ovpn' ]] && ok 'connect wrapper preserves exact dispatcher frame' || bad 'connect wrapper preserves exact dispatcher frame'
[[ $(run_spy list) == 'DISPATCH|list' && $(run_spy status) == 'DISPATCH|status' && $(run_spy disconnect) == 'DISPATCH|disconnect' ]] && ok 'list/status/disconnect wrappers preserve exact dispatcher frames' || bad 'list/status/disconnect wrappers preserve exact dispatcher frames'

# Installer fake root. Stubs deliberately fail if the fake-root code ever tries
# to inspect the real host network.
FAKE=$TMP/fakeroot
mkdir -p "$FAKE/usr/local/sbin" "$FAKE/root" "$FAKE/run" "$TMP/stubbin"
chmod 755 "$FAKE" "$FAKE/usr" "$FAKE/usr/local" "$FAKE/usr/local/sbin" "$FAKE/root" "$FAKE/run"
cat > "$TMP/stubbin/nmcli" <<EOF_STUB
#!/usr/bin/env bash
touch '$TMP/network-command-called'
exit 99
EOF_STUB
cat > "$TMP/stubbin/ip" <<EOF_STUB
#!/usr/bin/env bash
touch '$TMP/network-command-called'
exit 99
EOF_STUB
chmod 755 "$TMP/stubbin/nmcli" "$TMP/stubbin/ip"

PATH="$TMP/stubbin:$PATH" "$INSTALLER" install --root "$FAKE" > "$TMP/install.out"
if grep -Fq 'INSTALLED AND VERIFIED IN FAKE ROOT' "$TMP/install.out" && [[ ! -e $TMP/network-command-called ]]; then
    ok 'fake-root install succeeds without querying real network commands'
else
    bad 'fake-root install succeeds without querying real network commands'
fi

C_DST=$FAKE/usr/local/sbin/mvc
E_DST=$FAKE/root/mvc-emergency-rollback
D_DST=$FAKE/root/mvc-dual-recovery
if [[ $(stat -c %u:%g:%a:%h -- "$C_DST") == 0:0:755:1 &&
      $(stat -c %u:%g:%a:%h -- "$E_DST") == 0:0:700:1 &&
      $(stat -c %u:%g:%a:%h -- "$D_DST") == 0:0:700:1 ]]; then
    ok 'installed controller/recovery ownership and modes are exact'
else
    bad 'installed controller/recovery ownership and modes are exact'
fi
if cmp -s -- "$C_DST" "$DIST" && cmp -s -- "$E_DST" "$EMERGENCY" && cmp -s -- "$D_DST" "$DUAL"; then
    ok 'installed file identities exactly match release sources'
else
    bad 'installed file identities exactly match release sources'
fi
PATH="$TMP/stubbin:$PATH" "$INSTALLER" verify --root "$FAKE" > "$TMP/verify.out" && grep -Fq 'INSTALLED MULTI VPN CONTROLLER 2.4.1 FILE SET VERIFIED' "$TMP/verify.out" && ok 'installer verify rechecks installed identity/provenance' || bad 'installer verify rechecks installed identity/provenance'

old_inode=$(stat -c %i -- "$C_DST")
PATH="$TMP/stubbin:$PATH" "$INSTALLER" update --root "$FAKE" > "$TMP/update.out"
new_inode=$(stat -c %i -- "$C_DST")
if [[ $new_inode != "$old_inode" ]] && cmp -s -- "$C_DST" "$DIST" && ! find "$FAKE/usr/local/sbin" "$FAKE/root" -maxdepth 1 -name '.*.new.*' -print -quit | grep -q .; then
    ok 'update atomically replaces exact managed candidate and leaves no staging residue'
else
    bad 'update atomically replaces exact managed candidate and leaves no staging residue'
fi

# A same-name/version impostor is not accepted: replacement is hash-bound to
# either this package candidate or the exact physically proven v2.4.0 predecessor.
cp "$C_DST" "$TMP/good-controller"
cat > "$C_DST" <<'UNKNOWN_CONTROLLER'
#!/usr/bin/env bash
[[ ${1:-} == version ]] && { echo 'Multi VPN Controller 2.4.1'; exit 0; }
exit 99
UNKNOWN_CONTROLLER
chmod 755 "$C_DST"
set +e
PATH="$TMP/stubbin:$PATH" "$INSTALLER" update --root "$FAKE" > "$TMP/unrecognized.out" 2>&1
unknown_rc=$?
set -e
if (( unknown_rc != 0 )) && grep -Fq 'refusing to replace unrecognized existing MVC controller' "$TMP/unrecognized.out"; then
    ok 'installer rejects same-version controller with unrecognized hash'
else
    bad 'installer rejects same-version controller with unrecognized hash'
fi
cp "$TMP/good-controller" "$C_DST"; chmod 755 "$C_DST"

# Upgrade contract explicitly recognizes only the exact physically proven 2.4.0 predecessor hash.
grep -Fq 'a035bcdfca9eab009d9f7ad1455f519516109f95c0ecf4345db2633506f8a0ef' "$INSTALLER" &&
  ok 'installer pins exact physically proven v2.4.0 predecessor identity' ||
  bad 'installer pins exact physically proven v2.4.0 predecessor identity'

# Exercise the legacy-name migration path in a fake root. The dummy legacy files
# are identity-mapped by a test-only sha256sum shim; all current MVC/package
# hashes are delegated to the real sha256sum implementation.
FAKE3=$TMP/fakeroot-legacy-migration
mkdir -p "$FAKE3/usr/local/sbin" "$FAKE3/root" "$FAKE3/run" "$TMP/migratebin"
chmod 755 "$FAKE3" "$FAKE3/usr" "$FAKE3/usr/local" "$FAKE3/usr/local/sbin" "$FAKE3/root" "$FAKE3/run"
printf '%s\n' legacy-controller > "$FAKE3/usr/local/sbin/ubs-vpn"
printf '%s\n' legacy-emergency > "$FAKE3/root/ubs-v240-emergency-rollback"
printf '%s\n' legacy-dual > "$FAKE3/root/ubs-v240-dual-recovery"
chmod 755 "$FAKE3/usr/local/sbin/ubs-vpn"
chmod 700 "$FAKE3/root/ubs-v240-emergency-rollback" "$FAKE3/root/ubs-v240-dual-recovery"
cp "$TMP/stubbin/nmcli" "$TMP/migratebin/nmcli"
cp "$TMP/stubbin/ip" "$TMP/migratebin/ip"
real_sha=$(command -v sha256sum)
cat > "$TMP/migratebin/sha256sum" <<EOF_SHA
#!/usr/bin/env bash
path=\${!#}
case "\$path" in
  '$FAKE3/usr/local/sbin/ubs-vpn') printf '%s  %s\n' a035bcdfca9eab009d9f7ad1455f519516109f95c0ecf4345db2633506f8a0ef "\$path" ;;
  '$FAKE3/root/ubs-v240-emergency-rollback') printf '%s  %s\n' e2de136ccdc43f70aebb83778c5ff09ee706e870d6ad4a7d0770aabcec3af8f9 "\$path" ;;
  '$FAKE3/root/ubs-v240-dual-recovery') printf '%s  %s\n' a6222f917c8b4ecd8284887ec1a0895774c877ca985ebb575608f73ecce8a15a "\$path" ;;
  *) exec '$real_sha' "\$@" ;;
esac
EOF_SHA
chmod 755 "$TMP/migratebin/sha256sum" "$TMP/migratebin/nmcli" "$TMP/migratebin/ip"
PATH="$TMP/migratebin:$PATH" "$INSTALLER" install --root "$FAKE3" > "$TMP/migrate.out"
if [[ -f $FAKE3/usr/local/sbin/mvc && -f $FAKE3/root/mvc-emergency-rollback && -f $FAKE3/root/mvc-dual-recovery &&
      ! -e $FAKE3/usr/local/sbin/ubs-vpn && ! -L $FAKE3/usr/local/sbin/ubs-vpn &&
      ! -e $FAKE3/root/ubs-v240-emergency-rollback && ! -L $FAKE3/root/ubs-v240-emergency-rollback &&
      ! -e $FAKE3/root/ubs-v240-dual-recovery && ! -L $FAKE3/root/ubs-v240-dual-recovery ]] &&
   grep -Fq 'MULTI VPN CONTROLLER 2.4.1 FILE SET INSTALLED AND VERIFIED IN FAKE ROOT' "$TMP/migrate.out"; then
    ok 'recognized pre-MVC 2.4.0 file set migrates to MVC names and retires legacy files'
else
    bad 'recognized pre-MVC 2.4.0 file set migrates to MVC names and retires legacy files'
fi

# A managed runtime root must block both update/removal and leave installed
# identities untouched.
mkdir "$FAKE/run/mvc-controller"
before=$(sha256sum -- "$C_DST" "$E_DST" "$D_DST")
set +e
PATH="$TMP/stubbin:$PATH" "$INSTALLER" update --root "$FAKE" > "$TMP/active-update.out" 2>&1
update_rc=$?
PATH="$TMP/stubbin:$PATH" "$INSTALLER" uninstall --root "$FAKE" > "$TMP/active-uninstall.out" 2>&1
uninstall_rc=$?
set -e
after=$(sha256sum -- "$C_DST" "$E_DST" "$D_DST")
if (( update_rc != 0 && uninstall_rc != 0 )) && [[ $before == "$after" ]] && grep -Fq 'managed runtime state is present' "$TMP/active-update.out"; then
    ok 'package maintenance refuses managed live state without changing installed files'
else
    bad 'package maintenance refuses managed live state without changing installed files'
fi
rmdir "$FAKE/run/mvc-controller"

# Unsafe pre-existing symlink target must never be followed/replaced.
FAKE2=$TMP/fakeroot-symlink
mkdir -p "$FAKE2/usr/local/sbin" "$FAKE2/root" "$FAKE2/run"
chmod 755 "$FAKE2" "$FAKE2/usr" "$FAKE2/usr/local" "$FAKE2/usr/local/sbin" "$FAKE2/root" "$FAKE2/run"
printf '%s\n' sentinel > "$TMP/sentinel-target"
ln -s "$TMP/sentinel-target" "$FAKE2/usr/local/sbin/mvc"
set +e
PATH="$TMP/stubbin:$PATH" "$INSTALLER" install --root "$FAKE2" > "$TMP/symlink.out" 2>&1
symlink_rc=$?
set -e
if (( symlink_rc != 0 )) && [[ $(cat "$TMP/sentinel-target") == sentinel ]] && [[ -L $FAKE2/usr/local/sbin/mvc ]]; then
    ok 'installer refuses symlink targets without following or modifying them'
else
    bad 'installer refuses symlink targets without following or modifying them'
fi

printf '%s\n' keep-me > "$FAKE/root/unrelated-sentinel"
PATH="$TMP/stubbin:$PATH" "$INSTALLER" uninstall --root "$FAKE" > "$TMP/uninstall.out"
if [[ ! -e $C_DST && ! -L $C_DST && ! -e $E_DST && ! -L $E_DST && ! -e $D_DST && ! -L $D_DST &&
      $(cat "$FAKE/root/unrelated-sentinel") == keep-me && ! -e $TMP/network-command-called ]]; then
    ok 'uninstall removes only managed files and leaves unrelated files/network untouched'
else
    bad 'uninstall removes only managed files and leaves unrelated files/network untouched'
fi

# Static defense: the installer may only observe NetworkManager/ip state. It
# must contain no obvious networking mutation verbs.
if ! grep -Eq 'nmcli[[:space:]].*(up|down|delete|modify)|ip[[:space:]].*(route|link)[[:space:]].*(add|del|set)|nft[[:space:]]' "$INSTALLER"; then
    ok 'installer contains no VPN/network mutation command surface'
else
    bad 'installer contains no VPN/network mutation command surface'
fi

printf 'RESULT: C24A Stage-3 v2.4.1 install/promotion %d/%d checks passed\n' "$PASS" "$((PASS+FAIL))"
(( FAIL == 0 ))
