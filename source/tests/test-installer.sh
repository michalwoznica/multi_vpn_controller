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
if grep -Fxq 'checkpoint=MVC_V241_RELEASE' <<<"$info" &&
   grep -Fxq 'authority=audited-dispatch-mvc-v241-release' <<<"$info"; then
    ok 'v2.4.1 provenance records stable release identity'
else
    bad 'v2.4.1 provenance records stable release identity'
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
    ok 'update atomically replaces exact managed release and leaves no staging residue'
else
    bad 'update atomically replaces exact managed release and leaves no staging residue'
fi

# Reconstruct the exact physically proven R8 controller by reversing only the
# final-release provenance wrapper changes in the current builder. This avoids
# carrying predecessor binaries in the public tree while proving that the R8
# allowlist entry is bound to the real deterministic artifact.
R8_ROOT=$TMP/r8-rebuild
mkdir -p "$R8_ROOT"
cp -a "$ROOT/source" "$R8_ROOT/source"
R8_BUILDER=$R8_ROOT/source/build/build-mvc-monolith.sh
sed -i \
    -e 's/# Public v2.4.1 release\./# Public v2.4.1 release candidate./' \
    -e 's/# Lifecycle verbs delegate to the audited dispatcher; validation evidence remains hash-specific\./# Lifecycle verbs delegate to the audited dispatcher; v2.4.1 physical proof remains pending./' \
    -e "s/MVC24_BUILD_CHECKPOINT='MVC_V241_RELEASE'/MVC24_BUILD_CHECKPOINT='MVC_R8_BOOTSTRAP_RESOURCE_PIN_REPAIR'/" \
    -e "s/mvc24_emit '# Multi VPN Controller 2.4.1 operational release\.'/mvc24_emit '# C24A Stage 3 v2.4.1 operational candidate.'/" \
    -e 's/# Multi VPN Controller v2.4.1 release wrapper — audited dispatcher/# C24A Stage-3 v2.4.1 release wrapper — audited dispatcher, physical proof pending/' \
    -e 's/Multi VPN Controller 2.4.1$/Multi VPN Controller 2.4.1 — public identity release candidate/' \
    -e 's/This is the deterministic MVC v2.4.1 release artifact\. Validation evidence is/This MVC v2.4.1 candidate has completed offline identity\/build regression; physical proof/' \
    -e 's/hash-specific; verify the exact artifact identity used for deployment\./of this exact hash remains pending controlled live-host validation./' \
    -e 's/authority=audited-dispatch-mvc-v241-release/authority=audited-dispatch-mvc-v241-candidate-physical-pending/' \
    -e 's/Multi VPN Controller v2.4.1 monolith is incomplete\./Multi VPN Controller v2.4.1 candidate monolith is incomplete./' \
    "$R8_BUILDER"
"$R8_BUILDER" "$TMP/r8-mvc" >/dev/null
R8_SHA=594b4f747db4dd6cd7d3efe86994a3027f672c30db80749ffbca0c4113ec2edd
if [[ $(sha256sum "$TMP/r8-mvc" | awk '{print $1}') == "$R8_SHA" ]]; then
    ok 'test reconstructs the exact physically proven R8 predecessor identity'
else
    bad 'test reconstructs the exact physically proven R8 predecessor identity'
fi

# `install` remains conservative: the exact R8 predecessor must use explicit
# update rather than being silently treated as a reinstall.
cp -- "$TMP/r8-mvc" "$C_DST"
chmod 755 "$C_DST"
set +e
PATH="$TMP/stubbin:$PATH" "$INSTALLER" install --root "$FAKE" > "$TMP/r8-install.out" 2>&1
r8_install_rc=$?
set -e
if (( r8_install_rc != 0 )) && grep -Fq 'approved prior identity; use update instead of install' "$TMP/r8-install.out" &&
   [[ $(sha256sum "$C_DST" | awk '{print $1}') == "$R8_SHA" ]]; then
    ok 'install refuses exact R8 predecessor and requires explicit update'
else
    bad 'install refuses exact R8 predecessor and requires explicit update'
fi

old_inode=$(stat -c %i -- "$C_DST")
PATH="$TMP/stubbin:$PATH" "$INSTALLER" update --root "$FAKE" > "$TMP/r8-update.out"
new_inode=$(stat -c %i -- "$C_DST")
if [[ $new_inode != "$old_inode" ]] && cmp -s -- "$C_DST" "$DIST" &&
   ! find "$FAKE/usr/local/sbin" "$FAKE/root" -maxdepth 1 -name '.*.new.*' -print -quit | grep -q .; then
    ok 'update accepts exact approved R8 identity and atomically promotes to final 2.4.1'
else
    bad 'update accepts exact approved R8 identity and atomically promotes to final 2.4.1'
fi

# Reconstruct the exact R7 controller from the reconstructed R8 source using the
# documented R8-only delta. This proves the older allowlist entry remains real.
R7_ROOT=$TMP/r7-rebuild
mkdir -p "$R7_ROOT"
cp -a "$R8_ROOT/source" "$R7_ROOT/source"
sed -i "s/MVC24_BUILD_CHECKPOINT='MVC_R8_BOOTSTRAP_RESOURCE_PIN_REPAIR'/MVC24_BUILD_CHECKPOINT='MVC_R7_STANDALONE_PUBLIC_IDENTITY'/" \
    "$R7_ROOT/source/build/build-mvc-monolith.sh"
sed -i 's/15a274a9127731b3bddb9bb73a9eee1b7978c31a8d0299323db3cbbd31fdbd23/b2e817bf3f22853502f547feef07923e2c4ee5449e520cef6c72189611bd7b03/g' \
    "$R7_ROOT/source/lib/combined-operational-host-guard-plan.sh" \
    "$R7_ROOT/source/lib/combined-operational-host-guard-transaction.sh"
r7_plan_sha=$(sha256sum "$R7_ROOT/source/lib/combined-operational-host-guard-plan.sh" | awk '{print $1}')
r7_transaction_sha=$(sha256sum "$R7_ROOT/source/lib/combined-operational-host-guard-transaction.sh" | awk '{print $1}')
awk -F'|' -v OFS='|' -v plan_sha="$r7_plan_sha" -v transaction_sha="$r7_transaction_sha" '
    $4 == "source/lib/combined-operational-host-guard-plan.sh" { $3 = plan_sha }
    $4 == "source/lib/combined-operational-host-guard-transaction.sh" { $3 = transaction_sha }
    { print }
' "$R7_ROOT/source/build/monolith-runtime.manifest" > "$R7_ROOT/source/build/monolith-runtime.manifest.new"
mv -- "$R7_ROOT/source/build/monolith-runtime.manifest.new" "$R7_ROOT/source/build/monolith-runtime.manifest"
"$R7_ROOT/source/build/build-mvc-monolith.sh" "$TMP/r7-mvc" >/dev/null
R7_SHA=05b12e106844af20fdce1390005ef01e638970215b3dbfa1726fbd0848837f44
if [[ $(sha256sum "$TMP/r7-mvc" | awk '{print $1}') == "$R7_SHA" ]]; then
    ok 'test reconstructs the exact deterministic R7 predecessor identity'
else
    bad 'test reconstructs the exact deterministic R7 predecessor identity'
fi

# `install` remains conservative: a recognized prior MVC controller must use
# the explicit update action rather than being silently treated as a reinstall.
cp -- "$TMP/r7-mvc" "$C_DST"
chmod 755 "$C_DST"
set +e
PATH="$TMP/stubbin:$PATH" "$INSTALLER" install --root "$FAKE" > "$TMP/prior-install.out" 2>&1
prior_install_rc=$?
set -e
if (( prior_install_rc != 0 )) && grep -Fq 'approved prior identity; use update instead of install' "$TMP/prior-install.out" &&
   [[ $(sha256sum "$C_DST" | awk '{print $1}') == "$R7_SHA" ]]; then
    ok 'install refuses an approved prior controller and requires explicit update'
else
    bad 'install refuses an approved prior controller and requires explicit update'
fi

# `update` accepts the exact allowlisted R7 content identity and atomically
# promotes it directly to the final 2.4.1 controller.
old_inode=$(stat -c %i -- "$C_DST")
PATH="$TMP/stubbin:$PATH" "$INSTALLER" update --root "$FAKE" > "$TMP/prior-update.out"
new_inode=$(stat -c %i -- "$C_DST")
if [[ $new_inode != "$old_inode" ]] && cmp -s -- "$C_DST" "$DIST" &&
   ! find "$FAKE/usr/local/sbin" "$FAKE/root" -maxdepth 1 -name '.*.new.*' -print -quit | grep -q .; then
    ok 'update accepts exact approved R7 identity and atomically promotes to final 2.4.1'
else
    bad 'update accepts exact approved R7 identity and atomically promotes to final 2.4.1'
fi

# A same-name/version impostor is not accepted: replacement is hash-bound to
# the exact MVC package release.
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

printf 'RESULT: MVC v2.4.1 authenticated install/update/remove %d/%d checks passed\n' "$PASS" "$((PASS+FAIL))"
(( FAIL == 0 ))
