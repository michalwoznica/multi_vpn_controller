#!/usr/bin/env bash
# Multi VPN Controller 2.4.x — broad read-only state verifier.
# Observes baseline / OpenVPN-only / WireGuard-only / combined shapes.
# It never grants lifecycle authority and performs no controller mutations.
set -uo pipefail
umask 077
export LC_ALL=C

# MVC24_MONOLITH_VERIFY_FUNCTIONS_BEGIN
mvc24v_usage() {
    cat <<'USAGE'
Usage: sudo ./source/tools/verify-mvc-state-readonly.sh [--no-internet-check]

Print one concise read-only host-state report suitable after CONNECT or DISCONNECT.
The report includes controller status, active/saved managed profiles, routes, DNS,
nftables guard tables, fixed runtime roots, optional IPv4 Internet reachability,
and recovery-tool inspection when no managed VPN/WireGuard session is active.

The observed-shape classification is diagnostic only. It is not authentication,
cleanup authority, or permission to mutate controller/recovery state.
USAGE
}

mvc24v_section() {
    (( $# == 1 )) || return 2
    printf '\n=== %s ===\n' "$1"
}

mvc24v_run_observation() {
    (( $# >= 1 )) || return 2
    "$@" 2>&1 || printf '[command exit=%d]\n' "$?"
}

mvc24v_route_get() {
    (( $# == 1 )) || return 2
    local destination=$1
    local output rc
    if output=$(ip -4 route get "$destination" 2>&1); then
        rc=0
    else
        rc=$?
    fi
    if [[ -n $output ]]; then
        printf '%s\n' "$output"
    fi
    if (( rc != 0 )); then
        printf '[route-get exit=%d]\n' "$rc"
    fi
}

# Standalone default. The generated monolith deliberately overrides only this
# callback so `verify` observes the monolith's own internal read-only status
# path rather than invoking a sibling controller executable.
mvc24v_controller_status() {
    (( $# == 1 )) || return 2
    "$1" status
}

mvc24v_main() {
    local internet_check=yes
    case ${1-} in
        '') ;;
        --no-internet-check) internet_check=no ;;
        -h|--help) mvc24v_usage; return 0 ;;
        *) mvc24v_usage >&2; return 2 ;;
    esac
    [[ $# -le 1 ]] || { mvc24v_usage >&2; return 2; }

    if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
        echo 'ERROR: run this read-only verifier as root (sudo).' >&2
        return 2
    fi

    local tool_root controller dual_recovery emergency_recovery resolv_conf internet_url
    tool_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P) || return 1
    controller=${MVC24V_CONTROLLER:-"$tool_root/mvc"}
    dual_recovery=${MVC24V_DUAL_RECOVERY:-/root/mvc-dual-recovery}
    emergency_recovery=${MVC24V_EMERGENCY_RECOVERY:-/root/mvc-emergency-rollback}
    resolv_conf=${MVC24V_RESOLV_CONF:-/etc/resolv.conf}
    internet_url=${MVC24V_INTERNET_URL:-https://api.ipify.org}

    local active_rows saved_rows nft_rows active_rc saved_rc nft_rc
    if active_rows=$(nmcli --wait 10 --colors no -t -f TYPE,UUID,NAME,DEVICE connection show --active 2>&1); then
        active_rc=0
    else
        active_rc=$?
    fi
    if saved_rows=$(nmcli --wait 10 --colors no -t -f UUID,TYPE,NAME connection show 2>&1); then
        saved_rc=0
    else
        saved_rc=$?
    fi
    if nft_rows=$(nft list tables 2>&1); then
        nft_rc=0
    else
        nft_rc=$?
    fi

    local has_ovpn=0 has_wg=0 has_tun=0
    if (( active_rc == 0 )); then
        awk -F: '$1 == "vpn" && $3 == "vpnks-ovpn" {found=1} END {exit found ? 0 : 1}' <<<"$active_rows" && has_ovpn=1 || :
        awk -F: '$1 == "wireguard" && $3 == "vpnks-wg" {found=1} END {exit found ? 0 : 1}' <<<"$active_rows" && has_wg=1 || :
        awk -F: '$1 == "tun" && $3 == "tun-vpnks" {found=1} END {exit found ? 0 : 1}' <<<"$active_rows" && has_tun=1 || :
    fi

    local b4_count=0
    if (( nft_rc == 0 )); then
        grep -qx 'table inet mvc_preclone_quarantine' <<<"$nft_rows" && ((b4_count+=1)) || :
        grep -qx 'table bridge mvc_preclone_bridge' <<<"$nft_rows" && ((b4_count+=1)) || :
        grep -qx 'table netdev mvc_preclone_underlay' <<<"$nft_rows" && ((b4_count+=1)) || :
    fi

    local observed_shape=ambiguous
    if (( active_rc == 0 && nft_rc == 0 )); then
        if (( has_ovpn == 0 && has_wg == 0 && has_tun == 0 && b4_count == 0 )); then
            observed_shape=baseline
        elif (( has_ovpn == 1 && has_tun == 1 && has_wg == 0 && b4_count == 3 )); then
            observed_shape=openvpn-only-protected
        elif (( has_ovpn == 1 && has_tun == 1 && has_wg == 1 && b4_count == 3 )); then
            observed_shape=combined-protected
        elif (( has_ovpn == 0 && has_tun == 0 && has_wg == 1 && b4_count == 3 )); then
            observed_shape=wireguard-only-protected-candidate
        elif (( has_ovpn == 0 && has_tun == 0 && has_wg == 1 && b4_count == 0 )); then
            observed_shape=wireguard-only-split-candidate
        fi
    fi

    mvc24v_section 'REPORT IDENTITY'
    printf 'timestamp=%s\n' "$(date --iso-8601=seconds 2>/dev/null || date)"
    printf 'boot='; cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo '[unavailable]'
    printf 'observed_shape=%s\n' "$observed_shape"
    printf 'NOTE: observed_shape is diagnostic only; disconnect/recovery authenticate independently.\n'

    mvc24v_section 'CONTROLLER STATUS'
    mvc24v_run_observation mvc24v_controller_status "$controller"

    mvc24v_section 'ACTIVE CONNECTIONS'
    if (( active_rc == 0 )); then
        [[ -n $active_rows ]] && printf '%s\n' "$active_rows" || echo 'none'
    else
        printf '%s\n' "$active_rows"
        printf '[nmcli active inventory exit=%d]\n' "$active_rc"
    fi

    mvc24v_section 'TEMPORARY MANAGED PROFILES'
    local temp_rows
    if (( saved_rc == 0 )); then
        temp_rows=$(awk -F: '$3 == "vpnks-ovpn" || $3 == "vpnks-wg" {print}' <<<"$saved_rows")
        [[ -n $temp_rows ]] && printf '%s\n' "$temp_rows" || echo 'none'
    else
        printf '%s\n' "$saved_rows"
        printf '[nmcli saved inventory exit=%d]\n' "$saved_rc"
    fi

    mvc24v_section 'MANAGED KERNEL LINKS'
    local managed_links
    managed_links=$(ip -brief link show 2>&1 | grep -E '(^|[[:space:]])(tun-vpnks|vpnks-wg)(@|[[:space:]])' || :)
    [[ -n $managed_links ]] && printf '%s\n' "$managed_links" || echo 'none'

    mvc24v_section 'ORDINARY INTERNET ROUTE'
    mvc24v_route_get 1.1.1.1

    mvc24v_section 'MANAGED PRIVATE ROUTES'
    local private_routes
    private_routes=$(
        {
            ip -4 route show table all proto 187 2>/dev/null || :
            ip -4 route show table all dev vpnks-wg 2>/dev/null || :
        } | awk 'NF && !seen[$0]++'
    )
    [[ -n $private_routes ]] && printf '%s\n' "$private_routes" || echo 'none'

    mvc24v_section 'MVC ROUTE PROTOCOLS'
    local proto186 proto187
    echo '-- proto 186 --'
    proto186=$(ip -4 route show table all proto 186 2>&1 || :)
    [[ -n $proto186 ]] && printf '%s\n' "$proto186" || echo 'none'
    echo '-- proto 187 --'
    proto187=$(ip -4 route show table all proto 187 2>&1 || :)
    [[ -n $proto187 ]] && printf '%s\n' "$proto187" || echo 'none'

    mvc24v_section 'DEFAULT ROUTE'
    local default_rows
    default_rows=$(ip -4 route show default 2>&1 || :)
    [[ -n $default_rows ]] && printf '%s\n' "$default_rows" || echo 'none'

    mvc24v_section 'DNS'
    if [[ -f $resolv_conf && ! -L $resolv_conf ]]; then
        cat -- "$resolv_conf"
    elif [[ -e $resolv_conf || -L $resolv_conf ]]; then
        cat -- "$resolv_conf" 2>&1 || :
    else
        echo 'resolv.conf unavailable'
    fi

    mvc24v_section 'MVC NFT TABLES'
    local filtered_tables
    if (( nft_rc == 0 )); then
        filtered_tables=$(grep -E '^table (inet laptop_base|inet mvc_preclone_quarantine|bridge mvc_preclone_bridge|netdev mvc_preclone_underlay)$' <<<"$nft_rows" || :)
        [[ -n $filtered_tables ]] && printf '%s\n' "$filtered_tables" || echo 'none'
        printf 'b4_quarantine_tables=%d/3\n' "$b4_count"
    else
        printf '%s\n' "$nft_rows"
        printf '[nft inventory exit=%d]\n' "$nft_rc"
    fi

    mvc24v_section 'FIXED RUNTIME ROOTS'
    local p
    for p in \
        /run/mvc-controller \
        /run/mvc-activation \
        /run/mvc-output-transition \
        /run/mvc-disconnect \
        /run/mvc-completion \
        /run/mvc-wireguard \
        /run/mvc-public-session
    do
        if [[ -e $p || -L $p ]]; then
            echo "PRESENT: $p"
        else
            echo "ABSENT:  $p"
        fi
    done

    mvc24v_section 'INTERNET CHECK'
    local internet_result=skipped external_ip='' curl_rc
    if [[ $internet_check == no ]]; then
        echo 'skipped (--no-internet-check)'
    else
        if external_ip=$(curl -4 --max-time 10 -fsS "$internet_url" 2>&1); then
            curl_rc=0
        else
            curl_rc=$?
        fi
        if (( curl_rc == 0 )); then
            internet_result=reachable
            printf 'reachable: %s\n' "$external_ip"
        else
            internet_result=unreachable
            [[ -n $external_ip ]] && printf '%s\n' "$external_ip"
            printf 'unreachable: curl_exit=%d\n' "$curl_rc"
        fi
    fi

    mvc24v_section 'RECOVERY INSPECTION'
    if (( has_ovpn == 1 || has_wg == 1 || has_tun == 1 )); then
        echo 'skipped while a managed VPN/WireGuard/tun session is active'
    else
        if [[ -x $dual_recovery ]]; then
            echo '-- dual recovery --'
            mvc24v_run_observation "$dual_recovery" --inspect
        else
            echo "dual recovery unavailable: $dual_recovery"
        fi
        if [[ -x $emergency_recovery ]]; then
            echo '-- emergency rollback --'
            mvc24v_run_observation "$emergency_recovery" --inspect
        else
            echo "emergency rollback unavailable: $emergency_recovery"
        fi
    fi

    mvc24v_section 'SUMMARY'
    printf 'observed_shape=%s\n' "$observed_shape"
    printf 'managed_active: openvpn=%d wireguard=%d tun=%d\n' "$has_ovpn" "$has_wg" "$has_tun"
    printf 'b4_quarantine_tables=%d/3\n' "$b4_count"
    printf 'internet_check=%s\n' "$internet_result"
    echo 'RESULT: READ-ONLY STATE REPORT COMPLETE — NO LIFECYCLE AUTHORITY GRANTED'
}
# MVC24_MONOLITH_VERIFY_FUNCTIONS_END

mvc24v_main "$@"
