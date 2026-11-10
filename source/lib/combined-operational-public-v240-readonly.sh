#!/usr/bin/env bash
# C23AT — public v2.4 read-only profile identity/list/status scaffolding.
# No function in this file mutates NetworkManager, nftables, routes or /run.
# C23AX corrects real-host profile enumeration and active-session filtering; this module remains read-only.

ubs24pub_reset() {
    UBS24PUB_WG_UUID=
    UBS24PUB_OVPN_UUID=
    UBS24PUB_STATUS=unverified
}

ubs24pub_nm_saved_uuids() {
    nmcli --wait 10 --colors no -g UUID connection show 2>/dev/null
}

ubs24pub_nm_get() {
    (( $# == 2 )) || return 1
    local uuid=$1 key=$2
    ubs24_valid_uuid "$uuid" || return 1
    case $key in
        connection.id|connection.type|vpn.service-type) ;;
        *) return 1 ;;
    esac
    nmcli --wait 10 --colors no -g "$key" connection show uuid "$uuid" 2>/dev/null
}

# Resolve one human-facing saved profile name by enumerating exact UUIDs first.
# This deliberately avoids trusting nmcli's potentially ambiguous name selector.
# Output is the UUID only; any duplicate name is rejected.
ubs24pub_resolve_saved_name_exact() {
    (( $# == 1 )) || return 1
    local wanted=$1 uuid id matches=0 selected=
    ubs24_valid_name "$wanted" || return 1
    while IFS= read -r uuid; do
        [[ -n $uuid ]] || continue
        ubs24_valid_uuid "$uuid" || return 1
        id=$(ubs24pub_nm_get "$uuid" connection.id) || return 1
        if [[ $id == "$wanted" ]]; then
            ((matches+=1))
            selected=$uuid
        fi
    done < <(ubs24pub_nm_saved_uuids) || return 1
    (( matches == 1 )) || return 1
    printf '%s\n' "$selected"
}

ubs24pub_saved_profile_kind() {
    (( $# == 1 )) || return 1
    local name=$1 uuid type service
    ubs24_valid_name "$name" || return 1
    uuid=$(ubs24pub_resolve_saved_name_exact "$name") || return 1
    type=$(ubs24pub_nm_get "$uuid" connection.type) || return 1
    case $type in
        wireguard) printf '%s\n' wireguard ;;
        vpn)
            service=$(ubs24pub_nm_get "$uuid" vpn.service-type) || return 1
            [[ $service == org.freedesktop.NetworkManager.openvpn ]] || return 1
            printf '%s\n' openvpn
            ;;
        *) return 1 ;;
    esac
}

ubs24pub_bind_openvpn_name() {
    (( $# == 1 )) || return 1
    local ovpn_name=$1 ovpn_uuid ovpn_type ovpn_service
    UBS24PUB_WG_UUID= UBS24PUB_OVPN_UUID=
    ubs24_valid_name "$ovpn_name" || return 1
    ovpn_uuid=$(ubs24pub_resolve_saved_name_exact "$ovpn_name") || return 1
    ovpn_type=$(ubs24pub_nm_get "$ovpn_uuid" connection.type) || return 1
    ovpn_service=$(ubs24pub_nm_get "$ovpn_uuid" vpn.service-type) || return 1
    [[ $ovpn_type == vpn && $ovpn_service == org.freedesktop.NetworkManager.openvpn ]] || return 1
    UBS24PUB_OVPN_UUID=$ovpn_uuid
}

ubs24pub_bind_wireguard_name() {
    (( $# == 1 )) || return 1
    local wg_name=$1 wg_uuid wg_type
    UBS24PUB_WG_UUID= UBS24PUB_OVPN_UUID=
    ubs24_valid_name "$wg_name" || return 1
    wg_uuid=$(ubs24pub_resolve_saved_name_exact "$wg_name") || return 1
    wg_type=$(ubs24pub_nm_get "$wg_uuid" connection.type) || return 1
    [[ $wg_type == wireguard ]] || return 1
    UBS24PUB_WG_UUID=$wg_uuid
}

ubs24pub_bind_combined_names() {
    (( $# == 2 )) || return 1
    local wg_name=$1 ovpn_name=$2 wg_uuid ovpn_uuid wg_type ovpn_type ovpn_service
    UBS24PUB_WG_UUID= UBS24PUB_OVPN_UUID=
    ubs24_valid_name "$wg_name" && ubs24_valid_name "$ovpn_name" && [[ $wg_name != "$ovpn_name" ]] || return 1
    wg_uuid=$(ubs24pub_resolve_saved_name_exact "$wg_name") || return 1
    ovpn_uuid=$(ubs24pub_resolve_saved_name_exact "$ovpn_name") || return 1
    [[ $wg_uuid != "$ovpn_uuid" ]] || return 1
    wg_type=$(ubs24pub_nm_get "$wg_uuid" connection.type) || return 1
    ovpn_type=$(ubs24pub_nm_get "$ovpn_uuid" connection.type) || return 1
    ovpn_service=$(ubs24pub_nm_get "$ovpn_uuid" vpn.service-type) || return 1
    [[ $wg_type == wireguard && $ovpn_type == vpn &&
       $ovpn_service == org.freedesktop.NetworkManager.openvpn ]] || return 1
    UBS24PUB_WG_UUID=$wg_uuid
    UBS24PUB_OVPN_UUID=$ovpn_uuid
}

ubs24pub_list_readonly() {
    (( $# == 0 )) || return 2
    local uuid id type service
    printf '%-40s %-12s %s\n' PROFILE TYPE UUID
    while IFS= read -r uuid; do
        [[ -n $uuid ]] || continue
        ubs24_valid_uuid "$uuid" || return 1
        id=$(ubs24pub_nm_get "$uuid" connection.id) || return 1
        type=$(ubs24pub_nm_get "$uuid" connection.type) || return 1
        case $type in
            wireguard) service=WireGuard ;;
            vpn)
                service=$(ubs24pub_nm_get "$uuid" vpn.service-type) || return 1
                [[ $service == org.freedesktop.NetworkManager.openvpn ]] || continue
                service=OpenVPN
                ;;
            *) continue ;;
        esac
        [[ $id != vpnks-wg && $id != vpnks-ovpn ]] || continue
        printf '%-40s %-12s %s\n' "$id" "$service" "$uuid"
    done < <(ubs24pub_nm_saved_uuids)
}

ubs24pub_active_vpn_rows() {
    local rows
    rows=$(nmcli --wait 10 --colors no -t -f TYPE,UUID,NAME connection show --active 2>/dev/null) || return 1
    awk -F: '$1 == "vpn" || $1 == "wireguard" || ($1 == "tun" && $3 == "tun-vpnks") { print }' <<<"$rows"
}

ubs24pub_b4_table_present() {
    (( $# == 2 )) || return 1
    local family=$1 table=$2
    case "$family:$table" in
        inet:mvc_preclone_quarantine|bridge:mvc_preclone_bridge|netdev:mvc_preclone_underlay) ;;
        *) return 1 ;;
    esac
    nft list table "$family" "$table" >/dev/null 2>&1
}

ubs24pub_any_runtime_present() {
    local p public_runtime
    for p in /run/mvc-controller /run/mvc-activation /run/mvc-output-transition \
             /run/mvc-disconnect /run/mvc-completion /run/mvc-wireguard; do
        [[ ! -e $p && ! -L $p ]] || return 0
    done
    public_runtime=$(ubs24pub_session_runtime_root) || return 0
    [[ ! -e $public_runtime && ! -L $public_runtime ]] || return 0
    return 1
}

ubs24pub_baseline_clean_readonly() {
    (( $# == 0 )) || return 1
    local active
    active=$(ubs24pub_active_vpn_rows) || return 1
    [[ -z $active ]] || return 1
    ! ubs24pub_b4_table_present inet mvc_preclone_quarantine || return 1
    ! ubs24pub_b4_table_present bridge mvc_preclone_bridge || return 1
    ! ubs24pub_b4_table_present netdev mvc_preclone_underlay || return 1
    ! ubs24pub_any_runtime_present
}

# Public status remains intentionally conservative. It can certify only a clean
# baseline. Any v2.4 runtime/guard/active VPN is reported as unverified until
# the strict public session/transaction observer authenticates it.
ubs24pub_status_readonly() {
    (( $# == 0 )) || return 2
    UBS24PUB_STATUS=unverified
    if ubs24pub_baseline_clean_readonly; then
        UBS24PUB_STATUS=baseline-clean
        printf '%s\n' 'Managed v2.4 session: none; controller guard: OFF (baseline networking).'
        return 0
    fi
    UBS24PUB_STATUS=state-present-needs-strict-public-observer
    printf '%s\n' 'Managed v2.4 state is present; status remains conservative and does not itself grant lifecycle authority.'
    printf '%s\n' 'RESULT: UNVERIFIED — disconnect will independently authenticate exact same-boot ownership before any mutation; use recovery inspection for ambiguous/interrupted state.'
    return 0
}
