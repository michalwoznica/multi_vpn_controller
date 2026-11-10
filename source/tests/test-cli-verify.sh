#!/usr/bin/env bash
# C23BN Stage 3B — generated monolith read-only verify + daily CLI contract.
set -euo pipefail
umask 077
export LC_ALL=C

HERE=$(cd -- "${BASH_SOURCE[0]%/*}" && pwd -P)
ROOT=$(cd -- "$HERE/../.." && pwd -P)
BUILDER=$ROOT/source/build/build-mvc-monolith.sh
MANIFEST=$ROOT/source/build/monolith-runtime.manifest
VERIFY_SOURCE=$ROOT/source/tools/verify-mvc-state-readonly.sh
PASS=0
FAIL=0
ok(){ printf 'PASS: %s\n' "$1"; PASS=$((PASS+1)); }
bad(){ printf 'FAIL: %s\n' "$1" >&2; FAIL=$((FAIL+1)); }

TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT
mkdir -p "$TMP/a" "$TMP/b" "$TMP/bin"
"$BUILDER" "$TMP/a/mvc" >/dev/null
"$BUILDER" "$TMP/b/mvc" >/dev/null
A=$TMP/a/mvc
B=$TMP/b/mvc

cmp -s -- "$A" "$B" && ok 'Stage-3B independent builds are byte-identical' || bad 'Stage-3B independent builds are byte-identical'
[[ $($A version) == 'Multi VPN Controller 2.4.1' ]] && ok 'plain version remains concise and exact' || bad 'plain version remains concise and exact'

verbose=$($A version --verbose)
manifest_sha=$(sha256sum -- "$MANIFEST" | awk '{print $1}')
builder_sha=$(sha256sum -- "$BUILDER" | awk '{print $1}')
verify_sha=$(sha256sum -- "$VERIFY_SOURCE" | awk '{print $1}')
if grep -Fxq 'checkpoint=MVC_R6A_DEAD_COMBINED_STATE_REMOVAL' <<<"$verbose" &&
   grep -Fxq 'authority=audited-dispatch-mvc-v241-candidate-physical-pending' <<<"$verbose" &&
   grep -Fxq "manifest_sha256=$manifest_sha" <<<"$verbose" &&
   grep -Fxq "builder_sha256=$builder_sha" <<<"$verbose" &&
   grep -Fxq "verify_source_sha256=$verify_sha" <<<"$verbose"; then
    ok 'verbose version reports deterministic current provenance'
else
    bad 'verbose version reports deterministic current provenance'
fi

help=$($A --help)
if grep -Fq 'connect OPENVPN_PROFILE' <<<"$help" &&
   grep -Fq 'connect WIREGUARD_PROFILE' <<<"$help" &&
   grep -Fq 'connect WIREGUARD_PROFILE --split' <<<"$help" &&
   grep -Fq 'connect WIREGUARD_PROFILE --split OPENVPN_PROFILE' <<<"$help"; then
    ok 'help documents all four v2.4 daily modes'
else
    bad 'help documents all four v2.4 daily modes'
fi
if grep -Fq '/root/mvc-emergency-rollback' <<<"$help" &&
   grep -Fq '/root/mvc-dual-recovery' <<<"$help"; then
    ok 'help documents both independent recovery paths'
else
    bad 'help documents both independent recovery paths'
fi
if grep -Fq 'diagnostic only' <<<"$help" && grep -Fq 'physical proof' <<<"$help"; then
    ok 'help separates diagnostic verify and states v2.4.1 physical boundary'
else
    bad 'help separates diagnostic verify and states v2.4.1 physical boundary'
fi
if $A verify --help | grep -Fq 'Usage: sudo mvc verify [--no-internet-check]'; then
    ok 'verify help uses monolith-native CLI syntax'
else
    bad 'verify help uses monolith-native CLI syntax'
fi

if grep -Fq 'preflight|list|status|connect|disconnect)' "$A" &&
   grep -Fq 'mvc24e_dispatch "$@"' "$A" &&
   ! grep -Fq 'mvc24mon_stage3b_refuse_lifecycle' "$A"; then
    ok 'lifecycle production verbs are promoted only through audited dispatcher'
else
    bad 'lifecycle production verbs are promoted only through audited dispatcher'
fi

set +e
"$A" not-a-command >"$TMP/unknown" 2>&1
unknown_rc=$?
set -e
if [[ $unknown_rc == 2 ]] && grep -Fq 'unknown command' "$TMP/unknown"; then
    ok 'unknown commands remain usage errors'
else
    bad 'unknown commands remain usage errors'
fi

# Prove the builder embeds the verifier's marked function block byte-for-byte.
awk '
    $0 == "# MVC24_MONOLITH_VERIFY_FUNCTIONS_BEGIN" {inside=1; next}
    $0 == "# MVC24_MONOLITH_VERIFY_FUNCTIONS_END" {inside=0; next}
    inside {print}
' "$VERIFY_SOURCE" > "$TMP/verify-source-functions"
awk '
    /^# >>> SOURCE SHA-256: / && seen_begin {inside=1; next}
    /^# >>> BEGIN C23BN STAGE-3B READ-ONLY VERIFIER$/ {seen_begin=1; next}
    /^# <<< END C23BN STAGE-3B READ-ONLY VERIFIER$/ {inside=0; exit}
    inside {print}
' "$A" > "$TMP/verify-generated-functions"
if cmp -s -- "$TMP/verify-source-functions" "$TMP/verify-generated-functions"; then
    ok 'embedded verifier function block is byte-identical to audited source block'
else
    bad 'embedded verifier function block is byte-identical to audited source block'
fi

final_callback=$(set -- --help; source "$A" >/dev/null; declare -f mvc24v_controller_status)
if grep -Fq 'mvc24pub_status_readonly' <<<"$final_callback" && ! grep -Fq '"$1" status' <<<"$final_callback"; then
    ok 'final verifier controller-status callback is monolith-internal'
else
    bad 'final verifier controller-status callback is monolith-internal'
fi

# Hermetic host observations for generated `verify`.
cat > "$TMP/dual" <<'EOF'
#!/usr/bin/env bash
echo 'RESULT: MOCK DUAL RECOVERY CLEAN'
EOF
cat > "$TMP/emergency" <<'EOF'
#!/usr/bin/env bash
echo 'RESULT: MOCK EMERGENCY RECOVERY CLEAN'
EOF
chmod +x "$TMP/dual" "$TMP/emergency"

cat > "$TMP/bin/nmcli" <<'EOF'
#!/usr/bin/env bash
case_name=${VERIFY_CASE:?}
if [[ " $* " == *' connection show --active '* ]]; then
    case $case_name in
        baseline)
            printf '%s\n' '802-11-wireless:wifi:TEST_WIFI_5G:wlan0' 'loopback:lo:lo:lo'
            ;;
        combined)
            printf '%s\n' 'vpn:ovpn:vpnks-ovpn:wlan0' '802-11-wireless:wifi:TEST_WIFI_5G:wlan0' 'wireguard:wg:vpnks-wg:vpnks-wg' 'tun:tun:tun-vpnks:tun-vpnks' 'loopback:lo:lo:lo'
            ;;
    esac
else
    case $case_name in
        baseline) printf '%s\n' 'source-vpn:vpn:test-openvpn' ;;
        combined) printf '%s\n' 'source-vpn:vpn:test-openvpn' 'ovpn:vpn:vpnks-ovpn' 'wg:wireguard:vpnks-wg' ;;
    esac
fi
EOF

cat > "$TMP/bin/nft" <<'EOF'
#!/usr/bin/env bash
case_name=${VERIFY_CASE:?}
if [[ ${1-} == list && ${2-} == tables ]]; then
    echo 'table inet laptop_base'
    if [[ $case_name == combined ]]; then
        echo 'table inet mvc_preclone_quarantine'
        echo 'table bridge mvc_preclone_bridge'
        echo 'table netdev mvc_preclone_underlay'
    fi
    exit 0
fi
if [[ ${1-} == list && ${2-} == table ]]; then
    [[ $case_name == combined ]] || exit 1
    case "${3-}:${4-}" in
        inet:mvc_preclone_quarantine|bridge:mvc_preclone_bridge|netdev:mvc_preclone_underlay) exit 0 ;;
        *) exit 1 ;;
    esac
fi
exit 1
EOF

cat > "$TMP/bin/ip" <<'EOF'
#!/usr/bin/env bash
case_name=${VERIFY_CASE:?}
if [[ ${1-} == -brief && ${2-} == link && ${3-} == show ]]; then
    [[ $case_name == combined ]] && printf '%s\n' 'tun-vpnks UNKNOWN' 'vpnks-wg UNKNOWN'
    exit 0
fi
if [[ ${1-} == -4 && ${2-} == route && ${3-} == get ]]; then
    destination=${4-}
    if [[ $case_name == combined ]]; then
        if [[ $destination == 1.1.1.1 ]]; then
            echo '1.1.1.1 via 10.8.0.1 dev tun-vpnks src 10.8.0.14'
        else
            echo "$destination dev vpnks-wg src 10.66.10.7"
        fi
    else
        echo "$destination via 192.168.200.1 dev wlan0 src 192.168.200.36"
    fi
    exit 0
fi
if [[ ${1-} == -4 && ${2-} == route && ${3-} == show && ${4-} == table ]]; then
    [[ $case_name == combined && ${7-} == 186 ]] && echo '203.0.113.10 via 192.168.200.1 dev wlan0 proto 186'
    exit 0
fi
if [[ ${1-} == -4 && ${2-} == route && ${3-} == show && ${4-} == default ]]; then
    echo 'default via 192.168.200.1 dev wlan0 proto dhcp src 192.168.200.36 metric 600'
    exit 0
fi
exit 0
EOF

cat > "$TMP/bin/curl" <<'EOF'
#!/usr/bin/env bash
echo 'TEST ERROR: curl should not run with --no-internet-check' >&2
exit 91
EOF
chmod +x "$TMP/bin/nmcli" "$TMP/bin/nft" "$TMP/bin/ip" "$TMP/bin/curl"

echo 'nameserver 192.168.200.1' > "$TMP/resolv"
run_verify_case() {
    local case_name=$1 output=$2
    VERIFY_CASE=$case_name \
    MVC24V_DUAL_RECOVERY="$TMP/dual" \
    MVC24V_EMERGENCY_RECOVERY="$TMP/emergency" \
    MVC24V_RESOLV_CONF="$TMP/resolv" \
    PATH="$TMP/bin:$PATH" \
        "$A" verify --no-internet-check > "$output" 2>&1
}

run_verify_case baseline "$TMP/baseline.out"
if grep -q '^observed_shape=baseline$' "$TMP/baseline.out" &&
   grep -Fq 'Managed v2.4 session: none; controller guard: OFF' "$TMP/baseline.out" &&
   grep -Fq 'MOCK DUAL RECOVERY CLEAN' "$TMP/baseline.out" &&
   grep -Fq 'MOCK EMERGENCY RECOVERY CLEAN' "$TMP/baseline.out" &&
   grep -Fq 'skipped (--no-internet-check)' "$TMP/baseline.out" &&
   grep -Fq 'RESULT: READ-ONLY STATE REPORT COMPLETE — NO LIFECYCLE AUTHORITY GRANTED' "$TMP/baseline.out"; then
    ok 'generated verify reports baseline through internal status and recovery inspectors'
else
    bad 'generated verify reports baseline through internal status and recovery inspectors'
fi

run_verify_case combined "$TMP/combined.out"
if grep -q '^observed_shape=combined-protected$' "$TMP/combined.out" &&
   grep -Fq 'Managed v2.4 state is present; status remains conservative' "$TMP/combined.out" &&
   grep -Fq 'skipped while a managed VPN/WireGuard/tun session is active' "$TMP/combined.out" &&
   ! grep -Fq 'MOCK DUAL RECOVERY CLEAN' "$TMP/combined.out"; then
    ok 'generated verify reports combined protected shape without invoking recovery inspectors'
else
    bad 'generated verify reports combined protected shape without invoking recovery inspectors'
fi

# The standalone verifier's existing no-mutation contract remains authoritative
# for the function block that was embedded above.
if "$ROOT/source/tests/test-verifier.sh" > "$TMP/standalone-verifier-regression" 2>&1 &&
   grep -Fq 'RESULT: C23BI READ-ONLY STATE VERIFIER 10/10' "$TMP/standalone-verifier-regression"; then
    ok 'standalone verifier read-only regression remains 10/10'
else
    bad 'standalone verifier read-only regression remains 10/10'
fi

printf 'RESULT: C23BN Stage-3B monolith CLI/verify %d/%d checks passed\n' "$PASS" "$((PASS+FAIL))"
(( FAIL == 0 ))
