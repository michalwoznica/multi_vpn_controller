#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
TOOL="$ROOT/tools/verify-mvc-state-readonly.sh"
TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT
mkdir -p "$TMP/bin"

cat > "$TMP/controller" <<'SH'
#!/usr/bin/env bash
echo 'Managed v2.4 diagnostic mock status'
SH
cat > "$TMP/dual" <<'SH'
#!/usr/bin/env bash
echo 'RESULT: MOCK DUAL RECOVERY CLEAN'
SH
cat > "$TMP/emergency" <<'SH'
#!/usr/bin/env bash
echo 'RESULT: MOCK EMERGENCY RECOVERY CLEAN'
SH
chmod +x "$TMP/controller" "$TMP/dual" "$TMP/emergency"

cat > "$TMP/bin/nmcli" <<'SH'
#!/usr/bin/env bash
case_name=${VERIFY_CASE:?}
if [[ $case_name == inventory-fail && " $* " == *' connection show --active '* ]]; then
    echo 'mock active inventory failure' >&2
    exit 9
fi
if [[ " $* " == *' connection show --active '* ]]; then
    case $case_name in
        baseline)
            printf '%s\n' '802-11-wireless:wifi:TEST_WIFI_5G:wlan0' 'loopback:lo:lo:lo'
            ;;
        openvpn)
            printf '%s\n' 'vpn:ovpn:vpnks-ovpn:wlan0' '802-11-wireless:wifi:TEST_WIFI_5G:wlan0' 'tun:tun:tun-vpnks:tun-vpnks' 'loopback:lo:lo:lo'
            ;;
        combined)
            printf '%s\n' 'vpn:ovpn:vpnks-ovpn:wlan0' '802-11-wireless:wifi:TEST_WIFI_5G:wlan0' 'wireguard:wg:vpnks-wg:vpnks-wg' 'tun:tun:tun-vpnks:tun-vpnks' 'loopback:lo:lo:lo'
            ;;
        wg-protected|wg-split)
            printf '%s\n' '802-11-wireless:wifi:TEST_WIFI_5G:wlan0' 'wireguard:wg:vpnks-wg:vpnks-wg' 'loopback:lo:lo:lo'
            ;;
        inventory-fail) : ;;
    esac
else
    case $case_name in
        baseline) printf '%s\n' 'source-vpn:vpn:test-openvpn' ;;
        openvpn|combined) printf '%s\n' 'source-vpn:vpn:test-openvpn' 'ovpn:vpn:vpnks-ovpn' ;;
        wg-protected|wg-split) printf '%s\n' 'source-wg:wireguard:test-wireguard' 'wg:wireguard:vpnks-wg' ;;
        inventory-fail) printf '%s\n' 'source-vpn:vpn:test-openvpn' ;;
    esac
fi
SH

cat > "$TMP/bin/nft" <<'SH'
#!/usr/bin/env bash
case_name=${VERIFY_CASE:?}
echo 'table inet laptop_base'
case $case_name in
    openvpn|combined|wg-protected)
        echo 'table inet vpn_v240_preclone_quarantine'
        echo 'table bridge vpn_v240_preclone_bridge'
        echo 'table netdev vpn_v240_preclone_underlay'
        ;;
esac
SH

cat > "$TMP/bin/ip" <<'SH'
#!/usr/bin/env bash
case_name=${VERIFY_CASE:?}
if [[ ${1-} == '-brief' && ${2-} == 'link' && ${3-} == 'show' ]]; then
    case $case_name in
        openvpn) echo 'tun-vpnks UNKNOWN' ;;
        combined) printf '%s\n' 'tun-vpnks UNKNOWN' 'vpnks-wg UNKNOWN' ;;
        wg-protected|wg-split) echo 'vpnks-wg UNKNOWN' ;;
        inventory-fail) : ;;
    esac
    exit 0
fi
if [[ ${1-} == '-4' && ${2-} == 'route' && ${3-} == 'get' ]]; then
    destination=${4-}
    if [[ $destination == '1.1.1.1' ]]; then
        case $case_name in
            openvpn|combined) echo '1.1.1.1 via 10.8.0.1 dev tun-vpnks src 10.8.0.14' ;;
            *) echo '1.1.1.1 via 192.168.200.1 dev wlan0 src 192.168.200.36' ;;
        esac
    else
        case $case_name in
            combined|wg-protected|wg-split) echo "$destination dev vpnks-wg src 10.66.10.7" ;;
            openvpn) echo "$destination via 10.8.0.1 dev tun-vpnks src 10.8.0.14" ;;
            baseline|inventory-fail) echo "$destination via 192.168.200.1 dev wlan0 src 192.168.200.36" ;;
        esac
    fi
    exit 0
fi
if [[ ${1-} == '-4' && ${2-} == 'route' && ${3-} == 'show' && ${4-} == 'table' ]]; then
    proto=${7-}
    if [[ $proto == '186' && ( $case_name == combined || $case_name == wg-protected || $case_name == wg-split ) ]]; then
        echo '203.0.113.10 via 192.168.200.1 dev wlan0 proto 186'
    fi
    exit 0
fi
if [[ ${1-} == '-4' && ${2-} == 'route' && ${3-} == 'show' && ${4-} == 'default' ]]; then
    echo 'default via 192.168.200.1 dev wlan0 proto dhcp src 192.168.200.36 metric 600'
    exit 0
fi
exit 0
SH

cat > "$TMP/bin/curl" <<'SH'
#!/usr/bin/env bash
if [[ ${VERIFY_CASE:?} == 'wg-protected' ]]; then
    exit 28
fi
case ${VERIFY_CASE:?} in
    openvpn|combined) echo '198.51.100.43' ;;
    *) echo '198.51.100.42' ;;
esac
SH
chmod +x "$TMP/bin/nmcli" "$TMP/bin/nft" "$TMP/bin/ip" "$TMP/bin/curl"

pass=0
fail=0
check() {
    local label=$1
    shift
    if "$@"; then
        echo "PASS: $label"
        ((pass+=1))
    else
        echo "FAIL: $label"
        ((fail+=1))
    fi
}

run_case() {
    local case_name=$1
    local output="$TMP/$case_name.out"
    local resolv="$TMP/$case_name.resolv"
    if [[ $case_name == openvpn || $case_name == combined ]]; then
        echo 'nameserver 10.8.0.1' > "$resolv"
    else
        echo 'nameserver 192.168.200.1' > "$resolv"
    fi
    VERIFY_CASE=$case_name \
    UBS24V_CONTROLLER="$TMP/controller" \
    UBS24V_DUAL_RECOVERY="$TMP/dual" \
    UBS24V_EMERGENCY_RECOVERY="$TMP/emergency" \
    UBS24V_RESOLV_CONF="$resolv" \
    PATH="$TMP/bin:$PATH" \
        "$TOOL" > "$output" 2>&1
    printf '%s\n' "$output"
}

baseline_out=$(run_case baseline)
openvpn_out=$(run_case openvpn)
combined_out=$(run_case combined)
wg_protected_out=$(run_case wg-protected)
wg_split_out=$(run_case wg-split)
inventory_fail_out=$(run_case inventory-fail)

check 'baseline shape classified' grep -q '^observed_shape=baseline$' "$baseline_out"
check 'OpenVPN-only shape classified' grep -q '^observed_shape=openvpn-only-protected$' "$openvpn_out"
check 'combined shape classified' grep -q '^observed_shape=combined-protected$' "$combined_out"
check 'WireGuard-only protected candidate shape classified' grep -q '^observed_shape=wireguard-only-protected-candidate$' "$wg_protected_out"
check 'WireGuard-only split candidate shape classified' grep -q '^observed_shape=wireguard-only-split-candidate$' "$wg_split_out"
check 'failed active inventory cannot be misclassified as baseline' grep -q '^observed_shape=ambiguous$' "$inventory_fail_out"
check 'baseline runs both read-only recovery inspectors' bash -c "grep -q 'MOCK DUAL RECOVERY CLEAN' '$baseline_out' && grep -q 'MOCK EMERGENCY RECOVERY CLEAN' '$baseline_out'"
check 'active managed session skips recovery inspectors' grep -q 'skipped while a managed VPN/WireGuard/tun session is active' "$combined_out"
check 'protected WireGuard internet failure is observational, not verifier failure' bash -c "grep -q 'unreachable: curl_exit=28' '$wg_protected_out' && grep -q 'RESULT: READ-ONLY STATE REPORT COMPLETE' '$wg_protected_out'"

if grep -Eq 'connection (delete|down|up)|nft[[:space:]].*(--file|-f)|--rollback' "$TOOL"; then
    echo 'FAIL: verifier contains forbidden mutation primitive text'
    ((fail+=1))
else
    echo 'PASS: verifier contains no controller/network mutation primitive'
    ((pass+=1))
fi

echo "RESULT: C23BI READ-ONLY STATE VERIFIER $pass/$((pass+fail))"
(( fail == 0 ))
