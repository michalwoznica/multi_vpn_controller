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

ubs24gws_reset() {
    UBS24GWS_STAGE=idle
    UBS24GWS_ATTEMPTED=no
    UBS24GWS_FD=''
}

ubs24gws_lock_path() {
    local runtime
    runtime=$(ubs24pub_session_runtime_root) || return 1
    printf '%s\n' "$runtime/split.lock"
}

ubs24gws_lock_valid() {
    (( $# == 0 )) && [[ ${UBS24GWS_FD:-} =~ ^[0-9]+$ ]] || return 1
    local path
    path=$(ubs24gws_lock_path) || return 1
    [[ -f $path && ! -L $path && $(stat -c '%u:%a:%h' -- "$path") == '0:600:1' ]] || return 1
    [[ $(stat -Lc '%d:%i' -- "/proc/self/fd/$UBS24GWS_FD") == "$(stat -c '%d:%i' -- "$path")" ]]
}

ubs24gws_lock_acquire_new() {
    (( $# == 0 )) || return 1
    [[ -z ${UBS24GWS_FD:-} ]] || return 1
    local runtime path fd
    runtime=$(ubs24pub_session_runtime_root) || return 1
    path=$(ubs24gws_lock_path) || return 1
    [[ -d $runtime && ! -L $runtime && $(stat -c '%u:%a:%h' -- "$runtime") == '0:700:2' &&
       -f $runtime/transaction && ! -L $runtime/transaction && ! -e $path && ! -L $path ]] || return 1
    (umask 077; set -C; : > "$path") || return 1
    chmod 600 -- "$path" || return 1
    exec {fd}< "$path" || return 1
    if ! flock -n "$fd"; then exec {fd}>&-; return 1; fi
    UBS24GWS_FD=$fd
    ubs24gws_lock_valid
}

ubs24gws_lock_reopen() {
    (( $# == 0 )) || return 1
    [[ -z ${UBS24GWS_FD:-} ]] || return 1
    local path fd
    path=$(ubs24gws_lock_path) || return 1
    [[ -f $path && ! -L $path && $(stat -c '%u:%a:%h' -- "$path") == '0:600:1' ]] || return 1
    exec {fd}< "$path" || return 1
    if ! flock -n "$fd"; then exec {fd}>&-; return 1; fi
    UBS24GWS_FD=$fd
    ubs24gws_lock_valid
}

ubs24gws_lock_close() {
    if [[ ${UBS24GWS_FD:-} =~ ^[0-9]+$ ]]; then
        exec {UBS24GWS_FD}>&- || :
    fi
    UBS24GWS_FD=''
}

ubs24gws_no_b4_tables() {
    (( $# == 0 )) || return 1
    ! ubs24pub_b4_table_present inet mvc_preclone_quarantine &&
      ! ubs24pub_b4_table_present bridge mvc_preclone_bridge &&
      ! ubs24pub_b4_table_present netdev mvc_preclone_underlay
}

ubs24gws_preflight_readonly() {
    (( $# == 1 )) || return 1
    local wg_name=$1 underlay source_sha temp_uuid endpoint ip port prefix
    [[ ${UBS24GWS_ATTEMPTED:-no} == no ]] || return 1
    UBS24GWS_STAGE=preflight-fixed-live-roots
    ubs24pubc_fixed_live_roots_absent || return 1
    UBS24GWS_STAGE=preflight-baseline
    ubs24pub_baseline_clean_readonly || return 1
    UBS24GWS_STAGE=preflight-profile-identity
    ubs24pub_bind_wireguard_name "$wg_name" || return 1
    UBS24GWS_STAGE=preflight-underlay
    ubs24gb4_no_active_vpn || return 1
    underlay=$(ubs24gb4_underlay) || return 1
    UBS24GWS_STAGE=preflight-wireguard
    ubs24gd2_assess_saved_profile "$UBS24PUB_WG_UUID" "$underlay" || return 1
    (( ${UBS24GD2_PEER_COUNT:-0} == 1 && ${#UBS24GD2_ENDPOINT_PORTS[@]} == 1 )) || return 1
    ubs24gd3_keyfile_ipv4_source "$UBS24GD2_KEYFILE" || return 1
    for prefix in "${UBS24GD2_ALLOWED_IPS[@]}"; do ubs24gd3_private_ipv4_prefix "$prefix" || return 1; done
    [[ -z $(ip -4 route show table all proto 186) && -z $(ip -4 route show table all proto 187) ]] || return 1
    source_sha=$(ubs24gd4_hash_file "$UBS24GD2_KEYFILE") || return 1
    temp_uuid=$(cat /proc/sys/kernel/random/uuid) || return 1
    ubs24_valid_uuid "$temp_uuid" || return 1
    endpoint=${UBS24GD2_ENDPOINT_CANDIDATES[0]:-}
    [[ $endpoint == *:* && $endpoint != *:*:* ]] || return 1
    ip=${endpoint%:*}; port=${endpoint##*:}
    wg23_validate_ipv4 "$ip" && [[ $port =~ ^[0-9]+$ ]] && (( 10#$port >= 1 && 10#$port <= 65535 )) || return 1

    UBS24PUBC_MODE=wireguard-split
    UBS24PUBC_WG_NAME=$wg_name
    UBS24PUBC_OVPN_NAME=-
    UBS24PUBC_WG_UUID=$UBS24PUB_WG_UUID
    UBS24PUBC_OVPN_UUID=-
    UBS24PUBC_UNDERLAY=$underlay
    UBS24PUBC_NM_OWNER=-
    UBS24PUBC_SOURCE_FILE=$UBS24GD2_KEYFILE
    UBS24PUBC_SOURCE_SHA=$source_sha
    UBS24PUBC_WG_SOURCE=$UBS24GD3_WG_SOURCE_IP
    UBS24PUBC_TEMP_UUID=$temp_uuid

    ubs24gd4_prepare_from_preflight "$UBS24PUBC_WG_UUID" "$UBS24PUBC_SOURCE_FILE" "$UBS24PUBC_SOURCE_SHA" \
      "$UBS24PUBC_WG_SOURCE" "$underlay" "$UBS24GD2_UNDERLAY_SOURCE" "$UBS24GD2_UNDERLAY_GATEWAY" "$temp_uuid" || return 1
    UBS24GD4_ENDPOINT_IP=$ip
    UBS24GD4_ENDPOINT_PORT=$port
    UBS24GD4_ALLOWED_IPS=("${UBS24GD2_ALLOWED_IPS[@]}")
    UBS24GD4_STAGE=protected-endpoint-resolved-no-wireguard-mutation-yet
    ubs24pubc_fixed_live_roots_absent || return 1
    ubs24pub_baseline_clean_readonly || return 1
    UBS24GWS_STAGE=fresh-public-wireguard-split-readonly-eligible
}

ubs24gws_internet_route_observed() {
    (( $# == 0 )) || return 1
    local json expected_gateway
    json=$(ip -j -4 route get 1.1.1.1) || return 1
    expected_gateway=$UBS24GD4_UNDERLAY_GATEWAY
    [[ $expected_gateway == - ]] && expected_gateway=''
    jq -e --arg d "$UBS24GD4_UNDERLAY" --arg s "$UBS24GD4_UNDERLAY_SOURCE" --arg gw "$expected_gateway" '
      type=="array" and length==1 and .[0].dev==$d and .[0].prefsrc==$s and
      ((.[0].gateway // "") == $gw) and ((.[0].multipath // [])|length==0)
    ' <<< "$json" >/dev/null 2>&1
}

ubs24gws_no_other_managed_vpn_active() {
    (( $# == 0 )) || return 1
    local rows
    rows=$(nmcli --wait 10 --colors no -t -f NAME,UUID,TYPE,DEVICE connection show --active 2>/dev/null) || return 1
    awk -F: -v u="$UBS24GD4_TEMP_UUID" '
      $3=="vpn" {bad=1}
      $3=="tun" && $1=="tun-vpnks" {bad=1}
      $3=="wireguard" && $2!=u {bad=1}
      END{exit bad?1:0}
    ' <<< "$rows"
}

ubs24gws_authority_witness() {
    (( $# == 0 )) || return 1
    if [[ ${UBS24PUBC_MODE:-none} == wireguard-split &&
          ${UBS24PUBC_OPERATION:-none} == connect &&
          ${UBS24PUBC_APPROVAL:-none} == approved-process-local &&
          ${UBS24PUBC_AUTHORITY:-none} == public-explicit-connect ]]; then
        case ${UBS24PUBC_STAGE:-idle} in authorizing-public-connect|starting-wireguard-split|cleanup-stopping-wireguard-split) ;; *) return 1 ;; esac
        ubs24pub_connect_admission_witness && ubs24gws_lock_valid && ubs24gb2_root_scope
        return
    fi
    if [[ ${UBS24PUBD_SESSION_MODE:-none} == wireguard-split &&
          ${UBS24PUBD_OPERATION:-none} == disconnect &&
          ${UBS24PUBD_APPROVAL:-none} == approved-process-local &&
          ${UBS24PUBD_AUTHORITY:-none} == public-explicit-disconnect ]]; then
        case ${UBS24PUBD_STAGE:-idle} in reobserving-wireguard-split|stopping-wireguard-split|resuming-wireguard-split-runtime-retirement) ;; *) return 1 ;; esac
        ubs24gws_lock_valid && ubs24gb2_root_scope
        return
    fi
    return 1
}

ubs24gws_active_observed() {
    (( $# == 0 )) || return 1
    local prefix target
    ubs24gws_authority_witness || return 1
    ubs24gd4_wg_nm_active && ubs24gd4_wg_kernel_endpoint && ubs24gd4_endpoint_route_observed || return 1
    for prefix in "${UBS24GD4_ALLOWED_IPS[@]}"; do
        target=${prefix%/*}
        ubs24gd4_route_get_json_matches "$target" "$UBS24GD4_TEMP_NAME" "$UBS24GD4_WG_SOURCE" || return 1
    done
    ubs24gws_internet_route_observed && ubs24gws_no_b4_tables && ubs24gws_no_other_managed_vpn_active
}

ubs24gws_activate() {
    (( $# == 0 )) || return 1
    local rc
    [[ ${UBS24GD4_STAGE:-} == owned-endpoint-route-observed ]] || return 1
    ubs24gws_authority_witness || return 1
    ubs24gd4_write_marker activation-attempt || return 1
    UBS24GWS_STAGE=wireguard-activation-outcome-uncertain
    set +e
    nmcli --wait 60 connection up uuid "$UBS24GD4_TEMP_UUID" >/dev/null 2>&1
    rc=$?
    set -e
    UBS24GD4_NM_UP_EXIT_STATUS=$rc
    if ubs24gws_active_observed; then
        UBS24GWS_STAGE=wireguard-only-split-running
        return 0
    fi
    return 1
}

ubs24gws_start_once() {
    (( $# == 0 )) || return 1
    [[ ${UBS24GWS_ATTEMPTED:-no} == no ]] || return 1
    UBS24GWS_ATTEMPTED=yes
    ubs24gd4_publish_profile || return 1
    ubs24gd4_add_endpoint_route || return 1
    ubs24gws_activate
}

ubs24gws_prepared_clean_observed() {
    (( $# == 0 )) || return 1
    local underlay
    [[ ! -e $(ubs24pub_wireguard_runtime_root) && ! -L $(ubs24pub_wireguard_runtime_root) ]] || return 1
    ubs24gwg_temp_profile_inventory_absent || return 1
    [[ -z $(ip -4 route show table all proto 186) && -z $(ip -4 route show table all proto 187) ]] || return 1
    ! ip link show dev vpnks-wg >/dev/null 2>&1 || return 1
    ! wg show vpnks-wg >/dev/null 2>&1 || return 1
    ubs24gb4_no_active_vpn || return 1
    underlay=$(ubs24gb4_underlay) || return 1
    [[ $underlay == "${UBS24PUBD_UNDERLAY:-$UBS24PUBC_UNDERLAY}" ]] || return 1
    ubs24gws_no_b4_tables
}

ubs24gws_network_clean_retirement_pending_observed() {
    (( $# == 0 )) || return 1
    ubs24gwg_temp_profile_inventory_absent || return 1
    [[ -z $(ip -4 route show table all proto 186) && -z $(ip -4 route show table all proto 187) ]] || return 1
    ! ip link show dev "$UBS24GD4_TEMP_NAME" >/dev/null 2>&1 || return 1
    ! wg show "$UBS24GD4_TEMP_NAME" >/dev/null 2>&1 || return 1
    ubs24gws_no_b4_tables && ubs24gws_internet_route_observed
}

ubs24gws_retire_prepared_once() {
    (( $# == 0 )) || return 1
    local public lock
    public=$(ubs24pub_session_runtime_root) || return 1
    lock=$(ubs24gws_lock_path) || return 1
    ubs24gws_lock_valid && ubs24gws_prepared_clean_observed || return 1
    [[ -f $public/transaction && ! -L $public/transaction ]] || return 1
    rm -f -- "$public/transaction" "$lock" || return 1
    ubs24gws_lock_close
    rmdir -- "$public" || return 1
    [[ ! -e $public && ! -L $public ]]
}

ubs24gws_retire_runtime_once() {
    (( $# == 0 )) || return 1
    local runtime public lock
    runtime=$(ubs24pub_wireguard_runtime_root) || return 1
    public=$(ubs24pub_session_runtime_root) || return 1
    lock=$(ubs24gws_lock_path) || return 1
    ubs24gws_lock_valid && ubs24gws_network_clean_retirement_pending_observed || return 1
    [[ -d $runtime && ! -L $runtime && -f $runtime/intent && ! -L $runtime/intent ]] || return 1
    [[ -d $public && ! -L $public && -f $public/transaction && ! -L $public/transaction && -f $lock && ! -L $lock ]] || return 1
    rm -rf -- "$runtime" || return 1
    [[ ! -e $runtime && ! -L $runtime ]] || return 1
    rm -f -- "$public/transaction" "$lock" || return 1
    ubs24gws_lock_close
    rmdir -- "$public" || return 1
    [[ ! -e $public && ! -L $public ]]
}

ubs24gws_stop_once() {
    (( $# == 0 )) || return 1
    local rc
    ubs24gws_active_observed || return 1
    UBS24GWS_STAGE=wireguard-disconnect-outcome-uncertain
    set +e
    nmcli --wait 60 connection down uuid "$UBS24GD4_TEMP_UUID" >/dev/null 2>&1
    rc=$?
    set -e
    UBS24GD4_NM_DOWN_EXIT_STATUS=$rc
    ubs24gd4_wg_down_observed || return 1
    UBS24GWS_STAGE=wireguard-down-split-internet-retained
    ubs24gwg_delete_route_once || return 1
    ubs24gwg_delete_profile_once || return 1
    UBS24GWS_STAGE=wireguard-residue-removed-runtime-retirement-pending
    ubs24gws_retire_runtime_once || return 1
    UBS24GWS_STAGE=wireguard-only-split-complete-sameboot-ready
}

ubs24pubc_connect_wireguard_split_once() {
    (( $# == 1 )) || return 1
    local wg_name=$1
    [[ ${UBS24PUBC_ATTEMPTED:-no} == no ]] || return 1
    if ! ubs24gws_preflight_readonly "$wg_name"; then
        UBS24PUBC_ATTEMPTED=yes
        return 1
    fi
    UBS24PUBC_ATTEMPTED=yes
    UBS24PUBC_OPERATION=connect
    UBS24PUBC_APPROVAL=approved-process-local
    UBS24PUBC_AUTHORITY=public-explicit-connect

    UBS24PUBC_STAGE=publishing-pre-mutation-transaction
    if ! ubs24pubc_transaction_write wireguard-split-prepared; then
        UBS24PUBC_STAGE=wireguard-split-pre-mutation-transaction-publication-failed
        ubs24pubc_consume_authority
        return 1
    fi
    if ! ubs24gws_lock_acquire_new; then
        UBS24PUBC_STAGE=wireguard-split-lock-acquisition-failed
        rm -f -- "$(ubs24pubd_transaction_path)" >/dev/null 2>&1 || :
        rmdir -- "$(ubs24pub_session_runtime_root)" >/dev/null 2>&1 || :
        ubs24pubc_consume_authority
        return 1
    fi

    UBS24PUBC_STAGE=authorizing-public-connect
    if ! ubs24pub_connect_admission_witness; then
        UBS24PUBC_STAGE=public-wireguard-split-authority-refused
        if ubs24gws_prepared_clean_observed; then ubs24gws_retire_prepared_once || :; fi
        ubs24pubc_consume_authority
        return 1
    fi

    UBS24PUBC_STAGE=starting-wireguard-split
    if ! ubs24gws_start_once; then
        UBS24PUBC_STAGE="wireguard-split-start-failed-${UBS24GWS_STAGE:-unknown}-use-dual-recovery"
        ubs24gws_lock_close
        ubs24pubc_consume_authority
        return 1
    fi

    if ! ubs24pubc_transaction_write wireguard-split; then
        UBS24PUBC_STAGE=wireguard-split-transaction-update-failed
        UBS24PUBC_STAGE=cleanup-stopping-wireguard-split
        if ubs24gws_stop_once; then
            UBS24PUBC_STAGE=wireguard-split-transaction-update-failed-auto-cleaned-baseline
        else
            UBS24PUBC_STAGE="wireguard-split-transaction-update-failed-cleanup-refused-${UBS24GWS_STAGE:-unknown}"
        fi
        ubs24pubc_consume_authority
        return 1
    fi

    UBS24PUBC_STAGE=wireguard-only-split-session-published-connect-complete
    ubs24gws_lock_close
    ubs24pubc_consume_authority
    return 0
}
