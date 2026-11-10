#!/usr/bin/env bash
# C23BL Stage 3 — standalone WireGuard split-mode compatibility lifecycle.
#
# Split mode intentionally installs NO B2/B4 kill switch. The selected saved
# WireGuard profile is cloned to the same pinned temporary vpnks-wg identity
# used by D4, its peer endpoint is pinned over the physical underlay by the
# owned proto-186 /32 route, and only the profile-derived private AllowedIPs
# route through vpnks-wg. Ordinary IPv4 Internet remains on the physical
# underlay. The saved profile semantics already reject DNS settings and /0
# AllowedIPs, so split activation must not take over DNS or the default route.
#
# Durable authority is same-boot only: the public transaction identifies
# wireguard-split mode and /run/mvc-wireguard/intent binds the exact saved
# profile hash, temporary UUID, endpoint, underlay and AllowedIPs. A dedicated
# split.lock in the public-session root serializes connect/disconnect without
# creating the protected-mode B2 controller root.

mvc24gws_reset() {
    MVC24GWS_STAGE=idle
    MVC24GWS_ATTEMPTED=no
    MVC24GWS_FD=''
}

mvc24gws_lock_path() {
    local runtime
    runtime=$(mvc24pub_session_runtime_root) || return 1
    printf '%s\n' "$runtime/split.lock"
}

mvc24gws_lock_valid() {
    (( $# == 0 )) && [[ ${MVC24GWS_FD:-} =~ ^[0-9]+$ ]] || return 1
    local path
    path=$(mvc24gws_lock_path) || return 1
    [[ -f $path && ! -L $path && $(stat -c '%u:%a:%h' -- "$path") == '0:600:1' ]] || return 1
    [[ $(stat -Lc '%d:%i' -- "/proc/self/fd/$MVC24GWS_FD") == "$(stat -c '%d:%i' -- "$path")" ]]
}

mvc24gws_lock_acquire_new() {
    (( $# == 0 )) || return 1
    [[ -z ${MVC24GWS_FD:-} ]] || return 1
    local runtime path fd
    runtime=$(mvc24pub_session_runtime_root) || return 1
    path=$(mvc24gws_lock_path) || return 1
    [[ -d $runtime && ! -L $runtime && $(stat -c '%u:%a:%h' -- "$runtime") == '0:700:2' &&
       -f $runtime/transaction && ! -L $runtime/transaction && ! -e $path && ! -L $path ]] || return 1
    (umask 077; set -C; : > "$path") || return 1
    chmod 600 -- "$path" || return 1
    exec {fd}< "$path" || return 1
    if ! flock -n "$fd"; then exec {fd}>&-; return 1; fi
    MVC24GWS_FD=$fd
    mvc24gws_lock_valid
}

mvc24gws_lock_reopen() {
    (( $# == 0 )) || return 1
    [[ -z ${MVC24GWS_FD:-} ]] || return 1
    local path fd
    path=$(mvc24gws_lock_path) || return 1
    [[ -f $path && ! -L $path && $(stat -c '%u:%a:%h' -- "$path") == '0:600:1' ]] || return 1
    exec {fd}< "$path" || return 1
    if ! flock -n "$fd"; then exec {fd}>&-; return 1; fi
    MVC24GWS_FD=$fd
    mvc24gws_lock_valid
}

mvc24gws_lock_close() {
    if [[ ${MVC24GWS_FD:-} =~ ^[0-9]+$ ]]; then
        exec {MVC24GWS_FD}>&- || :
    fi
    MVC24GWS_FD=''
}

mvc24gws_no_b4_tables() {
    (( $# == 0 )) || return 1
    ! mvc24pub_b4_table_present inet mvc_preclone_quarantine &&
      ! mvc24pub_b4_table_present bridge mvc_preclone_bridge &&
      ! mvc24pub_b4_table_present netdev mvc_preclone_underlay
}

mvc24gws_preflight_readonly() {
    (( $# == 1 )) || return 1
    local wg_name=$1 underlay source_sha temp_uuid endpoint ip port prefix
    [[ ${MVC24GWS_ATTEMPTED:-no} == no ]] || return 1
    MVC24GWS_STAGE=preflight-fixed-live-roots
    mvc24pubc_fixed_live_roots_absent || return 1
    MVC24GWS_STAGE=preflight-baseline
    mvc24pub_baseline_clean_readonly || return 1
    MVC24GWS_STAGE=preflight-profile-identity
    mvc24pub_bind_wireguard_name "$wg_name" || return 1
    MVC24GWS_STAGE=preflight-underlay
    mvc24gb4_no_active_vpn || return 1
    underlay=$(mvc24gb4_underlay) || return 1
    MVC24GWS_STAGE=preflight-wireguard
    mvc24gd2_assess_saved_profile "$MVC24PUB_WG_UUID" "$underlay" || return 1
    (( ${MVC24GD2_PEER_COUNT:-0} == 1 && ${#MVC24GD2_ENDPOINT_PORTS[@]} == 1 )) || return 1
    mvc24gd3_keyfile_ipv4_source "$MVC24GD2_KEYFILE" || return 1
    for prefix in "${MVC24GD2_ALLOWED_IPS[@]}"; do mvc24gd3_private_ipv4_prefix "$prefix" || return 1; done
    [[ -z $(ip -4 route show table all proto 186) && -z $(ip -4 route show table all proto 187) ]] || return 1
    source_sha=$(mvc24gd4_hash_file "$MVC24GD2_KEYFILE") || return 1
    temp_uuid=$(cat /proc/sys/kernel/random/uuid) || return 1
    mvc24_valid_uuid "$temp_uuid" || return 1
    endpoint=${MVC24GD2_ENDPOINT_CANDIDATES[0]:-}
    [[ $endpoint == *:* && $endpoint != *:*:* ]] || return 1
    ip=${endpoint%:*}; port=${endpoint##*:}
    wg23_validate_ipv4 "$ip" && [[ $port =~ ^[0-9]+$ ]] && (( 10#$port >= 1 && 10#$port <= 65535 )) || return 1

    MVC24PUBC_MODE=wireguard-split
    MVC24PUBC_WG_NAME=$wg_name
    MVC24PUBC_OVPN_NAME=-
    MVC24PUBC_WG_UUID=$MVC24PUB_WG_UUID
    MVC24PUBC_OVPN_UUID=-
    MVC24PUBC_UNDERLAY=$underlay
    MVC24PUBC_NM_OWNER=-
    MVC24PUBC_SOURCE_FILE=$MVC24GD2_KEYFILE
    MVC24PUBC_SOURCE_SHA=$source_sha
    MVC24PUBC_WG_SOURCE=$MVC24GD3_WG_SOURCE_IP
    MVC24PUBC_TEMP_UUID=$temp_uuid

    mvc24gd4_prepare_from_preflight "$MVC24PUBC_WG_UUID" "$MVC24PUBC_SOURCE_FILE" "$MVC24PUBC_SOURCE_SHA" \
      "$MVC24PUBC_WG_SOURCE" "$underlay" "$MVC24GD2_UNDERLAY_SOURCE" "$MVC24GD2_UNDERLAY_GATEWAY" "$temp_uuid" || return 1
    MVC24GD4_ENDPOINT_IP=$ip
    MVC24GD4_ENDPOINT_PORT=$port
    MVC24GD4_ALLOWED_IPS=("${MVC24GD2_ALLOWED_IPS[@]}")
    MVC24GD4_STAGE=protected-endpoint-resolved-no-wireguard-mutation-yet
    mvc24pubc_fixed_live_roots_absent || return 1
    mvc24pub_baseline_clean_readonly || return 1
    MVC24GWS_STAGE=fresh-public-wireguard-split-readonly-eligible
}

mvc24gws_internet_route_observed() {
    (( $# == 0 )) || return 1
    local json expected_gateway
    json=$(ip -j -4 route get 1.1.1.1) || return 1
    expected_gateway=$MVC24GD4_UNDERLAY_GATEWAY
    [[ $expected_gateway == - ]] && expected_gateway=''
    jq -e --arg d "$MVC24GD4_UNDERLAY" --arg s "$MVC24GD4_UNDERLAY_SOURCE" --arg gw "$expected_gateway" '
      type=="array" and length==1 and .[0].dev==$d and .[0].prefsrc==$s and
      ((.[0].gateway // "") == $gw) and ((.[0].multipath // [])|length==0)
    ' <<< "$json" >/dev/null 2>&1
}

mvc24gws_no_other_managed_vpn_active() {
    (( $# == 0 )) || return 1
    local rows
    rows=$(nmcli --wait 10 --colors no -t -f NAME,UUID,TYPE,DEVICE connection show --active 2>/dev/null) || return 1
    awk -F: -v u="$MVC24GD4_TEMP_UUID" '
      $3=="vpn" {bad=1}
      $3=="tun" && $1=="tun-vpnks" {bad=1}
      $3=="wireguard" && $2!=u {bad=1}
      END{exit bad?1:0}
    ' <<< "$rows"
}

mvc24gws_authority_witness() {
    (( $# == 0 )) || return 1
    if [[ ${MVC24PUBC_MODE:-none} == wireguard-split &&
          ${MVC24PUBC_OPERATION:-none} == connect &&
          ${MVC24PUBC_APPROVAL:-none} == approved-process-local &&
          ${MVC24PUBC_AUTHORITY:-none} == public-explicit-connect ]]; then
        case ${MVC24PUBC_STAGE:-idle} in authorizing-public-connect|starting-wireguard-split|cleanup-stopping-wireguard-split) ;; *) return 1 ;; esac
        mvc24pub_connect_admission_witness && mvc24gws_lock_valid && mvc24gb2_root_scope
        return
    fi
    if [[ ${MVC24PUBD_SESSION_MODE:-none} == wireguard-split &&
          ${MVC24PUBD_OPERATION:-none} == disconnect &&
          ${MVC24PUBD_APPROVAL:-none} == approved-process-local &&
          ${MVC24PUBD_AUTHORITY:-none} == public-explicit-disconnect ]]; then
        case ${MVC24PUBD_STAGE:-idle} in reobserving-wireguard-split|stopping-wireguard-split|resuming-wireguard-split-runtime-retirement) ;; *) return 1 ;; esac
        mvc24gws_lock_valid && mvc24gb2_root_scope
        return
    fi
    return 1
}

mvc24gws_active_observed() {
    (( $# == 0 )) || return 1
    local prefix target
    mvc24gws_authority_witness || return 1
    mvc24gd4_wg_nm_active && mvc24gd4_wg_kernel_endpoint && mvc24gd4_endpoint_route_observed || return 1
    for prefix in "${MVC24GD4_ALLOWED_IPS[@]}"; do
        target=${prefix%/*}
        mvc24gd4_route_get_json_matches "$target" "$MVC24GD4_TEMP_NAME" "$MVC24GD4_WG_SOURCE" || return 1
    done
    mvc24gws_internet_route_observed && mvc24gws_no_b4_tables && mvc24gws_no_other_managed_vpn_active
}

mvc24gws_activate() {
    (( $# == 0 )) || return 1
    local rc
    [[ ${MVC24GD4_STAGE:-} == owned-endpoint-route-observed ]] || return 1
    mvc24gws_authority_witness || return 1
    mvc24gd4_write_marker activation-attempt || return 1
    MVC24GWS_STAGE=wireguard-activation-outcome-uncertain
    set +e
    nmcli --wait 60 connection up uuid "$MVC24GD4_TEMP_UUID" >/dev/null 2>&1
    rc=$?
    set -e
    MVC24GD4_NM_UP_EXIT_STATUS=$rc
    if mvc24gws_active_observed; then
        MVC24GWS_STAGE=wireguard-only-split-running
        return 0
    fi
    return 1
}

mvc24gws_start_once() {
    (( $# == 0 )) || return 1
    [[ ${MVC24GWS_ATTEMPTED:-no} == no ]] || return 1
    MVC24GWS_ATTEMPTED=yes
    mvc24gd4_publish_profile || return 1
    mvc24gd4_add_endpoint_route || return 1
    mvc24gws_activate
}

mvc24gws_prepared_clean_observed() {
    (( $# == 0 )) || return 1
    local underlay
    [[ ! -e $(mvc24pub_wireguard_runtime_root) && ! -L $(mvc24pub_wireguard_runtime_root) ]] || return 1
    mvc24gwg_temp_profile_inventory_absent || return 1
    [[ -z $(ip -4 route show table all proto 186) && -z $(ip -4 route show table all proto 187) ]] || return 1
    ! ip link show dev vpnks-wg >/dev/null 2>&1 || return 1
    ! wg show vpnks-wg >/dev/null 2>&1 || return 1
    mvc24gb4_no_active_vpn || return 1
    underlay=$(mvc24gb4_underlay) || return 1
    [[ $underlay == "${MVC24PUBD_UNDERLAY:-$MVC24PUBC_UNDERLAY}" ]] || return 1
    mvc24gws_no_b4_tables
}

mvc24gws_network_clean_retirement_pending_observed() {
    (( $# == 0 )) || return 1
    mvc24gwg_temp_profile_inventory_absent || return 1
    [[ -z $(ip -4 route show table all proto 186) && -z $(ip -4 route show table all proto 187) ]] || return 1
    ! ip link show dev "$MVC24GD4_TEMP_NAME" >/dev/null 2>&1 || return 1
    ! wg show "$MVC24GD4_TEMP_NAME" >/dev/null 2>&1 || return 1
    mvc24gws_no_b4_tables && mvc24gws_internet_route_observed
}

mvc24gws_retire_prepared_once() {
    (( $# == 0 )) || return 1
    local public lock
    public=$(mvc24pub_session_runtime_root) || return 1
    lock=$(mvc24gws_lock_path) || return 1
    mvc24gws_lock_valid && mvc24gws_prepared_clean_observed || return 1
    [[ -f $public/transaction && ! -L $public/transaction ]] || return 1
    rm -f -- "$public/transaction" "$lock" || return 1
    mvc24gws_lock_close
    rmdir -- "$public" || return 1
    [[ ! -e $public && ! -L $public ]]
}

mvc24gws_retire_runtime_once() {
    (( $# == 0 )) || return 1
    local runtime public lock
    runtime=$(mvc24pub_wireguard_runtime_root) || return 1
    public=$(mvc24pub_session_runtime_root) || return 1
    lock=$(mvc24gws_lock_path) || return 1
    mvc24gws_lock_valid && mvc24gws_network_clean_retirement_pending_observed || return 1
    [[ -d $runtime && ! -L $runtime && -f $runtime/intent && ! -L $runtime/intent ]] || return 1
    [[ -d $public && ! -L $public && -f $public/transaction && ! -L $public/transaction && -f $lock && ! -L $lock ]] || return 1
    rm -rf -- "$runtime" || return 1
    [[ ! -e $runtime && ! -L $runtime ]] || return 1
    rm -f -- "$public/transaction" "$lock" || return 1
    mvc24gws_lock_close
    rmdir -- "$public" || return 1
    [[ ! -e $public && ! -L $public ]]
}

mvc24gws_stop_once() {
    (( $# == 0 )) || return 1
    local rc
    mvc24gws_active_observed || return 1
    MVC24GWS_STAGE=wireguard-disconnect-outcome-uncertain
    set +e
    nmcli --wait 60 connection down uuid "$MVC24GD4_TEMP_UUID" >/dev/null 2>&1
    rc=$?
    set -e
    MVC24GD4_NM_DOWN_EXIT_STATUS=$rc
    mvc24gd4_wg_down_observed || return 1
    MVC24GWS_STAGE=wireguard-down-split-internet-retained
    mvc24gwg_delete_route_once || return 1
    mvc24gwg_delete_profile_once || return 1
    MVC24GWS_STAGE=wireguard-residue-removed-runtime-retirement-pending
    mvc24gws_retire_runtime_once || return 1
    MVC24GWS_STAGE=wireguard-only-split-complete-sameboot-ready
}

mvc24pubc_connect_wireguard_split_once() {
    (( $# == 1 )) || return 1
    local wg_name=$1
    [[ ${MVC24PUBC_ATTEMPTED:-no} == no ]] || return 1
    if ! mvc24gws_preflight_readonly "$wg_name"; then
        MVC24PUBC_ATTEMPTED=yes
        return 1
    fi
    MVC24PUBC_ATTEMPTED=yes
    MVC24PUBC_OPERATION=connect
    MVC24PUBC_APPROVAL=approved-process-local
    MVC24PUBC_AUTHORITY=public-explicit-connect

    MVC24PUBC_STAGE=publishing-pre-mutation-transaction
    if ! mvc24pubc_transaction_write wireguard-split-prepared; then
        MVC24PUBC_STAGE=wireguard-split-pre-mutation-transaction-publication-failed
        mvc24pubc_consume_authority
        return 1
    fi
    if ! mvc24gws_lock_acquire_new; then
        MVC24PUBC_STAGE=wireguard-split-lock-acquisition-failed
        rm -f -- "$(mvc24pubd_transaction_path)" >/dev/null 2>&1 || :
        rmdir -- "$(mvc24pub_session_runtime_root)" >/dev/null 2>&1 || :
        mvc24pubc_consume_authority
        return 1
    fi

    MVC24PUBC_STAGE=authorizing-public-connect
    if ! mvc24pub_connect_admission_witness; then
        MVC24PUBC_STAGE=public-wireguard-split-authority-refused
        if mvc24gws_prepared_clean_observed; then mvc24gws_retire_prepared_once || :; fi
        mvc24pubc_consume_authority
        return 1
    fi

    MVC24PUBC_STAGE=starting-wireguard-split
    if ! mvc24gws_start_once; then
        MVC24PUBC_STAGE="wireguard-split-start-failed-${MVC24GWS_STAGE:-unknown}-use-dual-recovery"
        mvc24gws_lock_close
        mvc24pubc_consume_authority
        return 1
    fi

    if ! mvc24pubc_transaction_write wireguard-split; then
        MVC24PUBC_STAGE=wireguard-split-transaction-update-failed
        MVC24PUBC_STAGE=cleanup-stopping-wireguard-split
        if mvc24gws_stop_once; then
            MVC24PUBC_STAGE=wireguard-split-transaction-update-failed-auto-cleaned-baseline
        else
            MVC24PUBC_STAGE="wireguard-split-transaction-update-failed-cleanup-refused-${MVC24GWS_STAGE:-unknown}"
        fi
        mvc24pubc_consume_authority
        return 1
    fi

    MVC24PUBC_STAGE=wireguard-only-split-session-published-connect-complete
    mvc24gws_lock_close
    mvc24pubc_consume_authority
    return 0
}
