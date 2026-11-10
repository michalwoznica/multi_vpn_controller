#!/usr/bin/env bash
# C23BN Stage 3A — generated monolith runtime-seam equivalence.
set -euo pipefail
umask 077
export LC_ALL=C

HERE=$(cd -- "${BASH_SOURCE[0]%/*}" && pwd -P)
ROOT=$(cd -- "$HERE/../.." && pwd -P)
BUILDER=$ROOT/source/build/build-mvc-monolith.sh
PROBE=$ROOT/source/tools/check-mvc-live-saved-ovpn-readonly.sh
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

cmp -s -- "$A" "$B" && ok 'Stage-3A independent builds are byte-identical' || bad 'Stage-3A independent builds are byte-identical'
[[ $($A version) == 'Multi VPN Controller 2.4.1' ]] && ok 'Stage-3A version identity is exact' || bad 'Stage-3A version identity is exact'
$A --help | grep -Fq 'public identity release candidate' && ok 'current help identifies v2.4.1 candidate' || bad 'current help identifies v2.4.1 candidate'
if grep -Fq 'preflight|list|status|connect|disconnect)' "$A" &&
   grep -Fq 'mvc24e_dispatch "$@"' "$A"; then
    ok 'v2.4.1 wrapper delegates lifecycle verbs to audited dispatcher'
else
    bad 'v2.4.1 wrapper delegates lifecycle verbs to audited dispatcher'
fi

# Source the generated artifact only to inspect/test its definitions. Passing
# --help prevents the wrapper from attempting any lifecycle action.
set -- --help
# shellcheck disable=SC1090
source "$A" >/dev/null

# Four path-dependent modular call sites must resolve through embedded assets.
declare -f mvc24gs_capture_settings | grep -Fq 'mvc24mon_runtime_asset_path gvariant-awk' && ok 'GetSettings decoder uses embedded AWK asset' || bad 'GetSettings decoder uses embedded AWK asset'
declare -f mvc24gb2_batch_valid | grep -Fq 'mvc24mon_runtime_asset_path b4-bootstrap-nft' && ok 'B2 batch validation uses embedded nft asset' || bad 'B2 batch validation uses embedded nft asset'
declare -f mvc24gc3_execute_once | grep -Fq 'mvc24mon_runtime_asset_path b4-bootstrap-nft' && ok 'C3 guard install uses embedded nft asset' || bad 'C3 guard install uses embedded nft asset'
declare -f mvc24gwg_policy_file | grep -Fq 'mvc24mon_runtime_asset_dir' && ok 'protected-WG policy path uses embedded nft asset' || bad 'protected-WG policy path uses embedded nft asset'

# Runtime asset materialization is exact and private.
mvc24mon_runtime_assets_prepare
awk_asset=$(mvc24mon_runtime_asset_path gvariant-awk)
nft_asset=$(mvc24mon_runtime_asset_path b4-bootstrap-nft)
if cmp -s -- "$awk_asset" "$ROOT/source/lib/combined-gvariant-settings-to-json.awk" &&
   cmp -s -- "$nft_asset" "$ROOT/source/nftables/mvc-preclone-quarantine-offline.nft"; then
    ok 'runtime embedded assets are byte-identical to audited sources'
else
    bad 'runtime embedded assets are byte-identical to audited sources'
fi
if [[ $(stat -c '%a:%h' -- "$awk_asset") == 600:1 && $(stat -c '%a:%h' -- "$nft_asset") == 600:1 ]]; then
    ok 'runtime embedded assets are private single-link files'
else
    bad 'runtime embedded assets are private single-link files'
fi
asset_dir=$MVC24_MONOLITH_ASSET_DIR
mvc24mon_runtime_assets_cleanup
[[ ! -e $asset_dir && ! -L $asset_dir ]] && ok 'runtime embedded assets clean up without residue' || bad 'runtime embedded assets clean up without residue'

# Recovery identity is now source-tree independent: strict metadata + embedded SHA.
recovery=$TMP/emergency-recovery
cp -- "$ROOT/source/tools/recover-mvc-host-guard-local.sh" "$recovery"
chmod 700 -- "$recovery"
mvc24mon_recovery_file_identity "$recovery" "$MVC24_MONOLITH_EMERGENCY_RECOVERY_SHA256" && ok 'embedded emergency recovery SHA authenticates exact file' || bad 'embedded emergency recovery SHA authenticates exact file'
printf '\n# drift\n' >> "$recovery"
if ! mvc24mon_recovery_file_identity "$recovery" "$MVC24_MONOLITH_EMERGENCY_RECOVERY_SHA256"; then ok 'recovery identity rejects content drift'; else bad 'recovery identity rejects content drift'; fi
cp -- "$ROOT/source/tools/recover-mvc-host-guard-local.sh" "$recovery"
chmod 755 -- "$recovery"
if ! mvc24mon_recovery_file_identity "$recovery" "$MVC24_MONOLITH_EMERGENCY_RECOVERY_SHA256"; then ok 'recovery identity rejects wrong mode'; else bad 'recovery identity rejects wrong mode'; fi

# Preview-shape contract must exactly match the old external --preview-derivative
# structural validator. Source the old probe for its pure validator only.
# shellcheck disable=SC1090
source "$PROBE"
uuid=a1000001-0000-4000-8000-000000000001
fixture=$TMP/source.json
cat > "$fixture" <<JSON
{"type":"a{sa{sv}}","data":[{"connection":{"id":{"type":"s","data":"source"},"uuid":{"type":"s","data":"$uuid"},"type":{"type":"s","data":"vpn"},"autoconnect":{"type":"b","data":false},"timestamp":{"type":"t","data":0}},"vpn":{"service-type":{"type":"s","data":"org.freedesktop.NetworkManager.openvpn"},"data":{"type":"a{ss}","data":{"remote":"203.0.113.11:443","proto-tcp":"yes","remote-random":"no","connection-type":"password","password-flags":"1","ca":"/etc/ssl/test-ca.pem","tls-crypt":"/etc/ssl/test-tls-crypt.key"}}},"ipv4":{"dns-priority":{"type":"i","data":100}},"ipv6":{"dns-priority":{"type":"i","data":100}}}]}
JSON
chmod 600 "$fixture"
if mvc24spf_validate "$fixture" "$uuid" --preview-derivative && mvc24mon_openvpn_source_shape_valid "$fixture" "$uuid"; then
    ok 'internal preview structural admission matches external probe on accepted shape'
else
    bad 'internal preview structural admission matches external probe on accepted shape'
fi
badshape=$TMP/bad.json
jq '.data[0].vpn["service-type"].data="org.example.not-openvpn"' "$fixture" > "$badshape"; chmod 600 "$badshape"
old=0; new=0
mvc24spf_validate "$badshape" "$uuid" --preview-derivative >/dev/null 2>&1 || old=$?
mvc24mon_openvpn_source_shape_valid "$badshape" "$uuid" >/dev/null 2>&1 || new=$?
(( old != 0 && new != 0 )) && ok 'internal preview rejects same wrong-service shape as external probe' || bad 'internal preview rejects same wrong-service shape as external probe'
old=0; new=0
wrong_uuid=11111111-1111-4111-8111-111111111111
mvc24spf_validate "$fixture" "$wrong_uuid" --preview-derivative >/dev/null 2>&1 || old=$?
mvc24mon_openvpn_source_shape_valid "$fixture" "$wrong_uuid" >/dev/null 2>&1 || new=$?
(( old != 0 && new != 0 )) && ok 'internal preview rejects same UUID mismatch as external probe' || bad 'internal preview rejects same UUID mismatch as external probe'

# Mock only D-Bus transport/capture; keep the real candidate planner and preview
# builder so the internal helper must satisfy the same derivative semantics.
preview_case() (
    set -euo pipefail
    local mode=$1 owner_call=0 counter=$TMP/preview-object-counter
    printf '0\n' > "$counter"
    gdbus() { return 0; }
    mvc24g_call_readonly() {
        local n
        n=$(<"$counter")
        n=$((n+1))
        printf '%s\n' "$n" > "$counter"
        if [[ $mode == object-drift && $n == 2 ]]; then
            printf 'o "/org/freedesktop/NetworkManager/Settings/43"\n'
        else
            printf 'o "/org/freedesktop/NetworkManager/Settings/42"\n'
        fi
    }
    mvc24g_get_property() {
        if [[ $mode == unsaved ]]; then printf 'b true\n'; else printf 'b false\n'; fi
    }
    mvc24gs_capture_settings() {
        local out=$2
        cp -- "$fixture" "$out"
        if [[ $mode == snapshot-drift && ${out##*/} == second.json ]]; then
            jq '.data[0].connection.id.data="changed"' "$fixture" > "$out.tmp"
            mv -- "$out.tmp" "$out"
            chmod 600 "$out"
        fi
    }
    mvc24op_session_nm_identity() {
        owner_call=$((owner_call+1))
        if [[ $mode == owner-drift && $owner_call -ge 3 ]]; then
            MVC24OP_SESSION_NM_IDENTITY=':1.99|999|0'
        else
            MVC24OP_SESSION_NM_IDENTITY=':1.7|1025|0'
        fi
    }
    if [[ $mode == preview-reject ]]; then
        mvc24op_preview_build() { return 1; }
    fi
    mvc24mon_openvpn_source_preview "$uuid"
)
preview_case happy && ok 'internal preview accepts stable saved OpenVPN source and real derivative projection' || bad 'internal preview accepts stable saved OpenVPN source and real derivative projection'
if ! preview_case unsaved; then ok 'internal preview rejects Unsaved=true'; else bad 'internal preview rejects Unsaved=true'; fi
if ! preview_case object-drift; then ok 'internal preview rejects object-path drift'; else bad 'internal preview rejects object-path drift'; fi
if ! preview_case snapshot-drift; then ok 'internal preview rejects GetSettings snapshot drift'; else bad 'internal preview rejects GetSettings snapshot drift'; fi
if ! preview_case owner-drift; then ok 'internal preview rejects NetworkManager owner drift'; else bad 'internal preview rejects NetworkManager owner drift'; fi
if ! preview_case preview-reject; then ok 'internal preview rejects unsupported derivative projection'; else bad 'internal preview rejects unsupported derivative projection'; fi

# C4 final definitions must be monolith-native and independent of source-root.
if ! declare -f mvc24gc4_recovery_installed | grep -Eq 'MVC24GC4_SOURCE_ROOT|cmp -s'; then ok 'C4 recovery identity has no sibling source dependency'; else bad 'C4 recovery identity has no sibling source dependency'; fi
if ! declare -f mvc24gc4_source_preview | grep -Eq 'check-v240-live-saved-ovpn-readonly|MVC24GC4_SOURCE_ROOT'; then ok 'C4 source preview has no external probe dependency'; else bad 'C4 source preview has no external probe dependency'; fi

# Fresh-process initialization should prepare only embedded runtime assets and
# leave the obsolete modular source-root binding empty.
mvc24pub_process_initialize
if [[ -z ${MVC24GC4_SOURCE_ROOT:-} && -n ${MVC24_MONOLITH_ASSET_DIR:-} && -d $MVC24_MONOLITH_ASSET_DIR ]]; then
    ok 'monolith process initialization uses embedded assets with no C4 source root'
else
    bad 'monolith process initialization uses embedded assets with no C4 source root'
fi
asset_dir=$MVC24_MONOLITH_ASSET_DIR
mvc24mon_runtime_assets_cleanup
[[ ! -e $asset_dir ]] && ok 'process-initialization asset directory is cleanly removable' || bad 'process-initialization asset directory is cleanly removable'

printf 'RESULT: C23BN Stage-3A monolith runtime seams %d/%d checks passed\n' "$PASS" "$((PASS+FAIL))"
(( FAIL == 0 ))
