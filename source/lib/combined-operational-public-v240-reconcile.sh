#!/usr/bin/env bash
# C23BD — public same-boot reconciliation helpers for authenticated partial
# WireGuard startup. This module does not grant authority by itself. Callers
# must already hold the genuine B2 lock and public connect/disconnect authority,
# and must reconstruct the immutable D4 intent before using these helpers.
#
# Safety model mirrors recover-v240-dual-local.sh:
#   * inventory exact temporary NM profile/kernel link/endpoint route/keyfile;
#   * accept only exact C11 or exact atomic parallel guard shape;
#   * establish exact private unreachable holds before removing WG state;
#   * never retry an ambiguous NM/nft/ip mutation;
#   * restore exact C11 before deleting the endpoint route/profile;
#   * leave D4's existing post-OpenVPN hold-release machinery authoritative.

mvc24pubr_reset() {
    MVC24PUBR_STAGE=idle
    MVC24PUBR_NM_STATUS=unknown
    MVC24PUBR_KERNEL_STATUS=unknown
    MVC24PUBR_ROUTE_STATUS=unknown
    MVC24PUBR_KEYFILE_STATUS=unknown
    MVC24PUBR_HOLD_STATUS=unknown
    MVC24PUBR_GUARD_STATUS=unknown
    MVC24PUBR_OVPN_GUARD_STATUS=unknown
    MVC24PUBR_OVPN_CLONE_STATUS=unknown
}

mvc24pubr_context_witness() {
    (( $# == 0 )) || return 1
    mvc24gb2_root_scope && mvc24gb2_lock_valid || return 1
    if [[ ${MVC24GCO_STAGE:-} == protected-openvpn-absent-reconciliation &&
          ${MVC24PUBD_AUTHORITY:-none} == public-explicit-disconnect &&
          ${MVC24PUBD_STAGE:-} == reconciling-openvpn-dropout-wireguard ]]; then
        mvc24pub_disconnect_admission_witness
        return
    fi
    [[ ${MVC24GCO_STAGE:-} == protected-openvpn-observed &&
       ${MVC24GC17_STAGE:-} == protected-ovpn-stages-observed-no-operational-authority ]] || return 1
    if [[ ${MVC24PUBC_AUTHORITY:-none} == public-explicit-connect ]]; then
        [[ ${MVC24PUBC_STAGE:-} == cleanup-reconciling-partial-wireguard ]] || return 1
        mvc24pub_connect_admission_witness
        return
    fi
    [[ ${MVC24PUBD_AUTHORITY:-none} == public-explicit-disconnect ]] || return 1
    case ${MVC24PUBD_STAGE:-} in
      reconciling-partial-wireguard|observing-published-wireguard-dropout|reconciling-published-wireguard-dropout) ;;
      *) return 1 ;;
    esac
    mvc24pub_disconnect_admission_witness
}

mvc24pubr_nm_inventory() {
    (( $# == 0 )) || return 1
    local rows line uuid type name n=0 active found=0 iface
    MVC24PUBR_NM_STATUS=unknown
    rows=$(nmcli --wait 10 --colors no -t -f UUID,TYPE,NAME connection show 2>/dev/null) || return 1
    while IFS= read -r line; do
        [[ -n $line ]] || continue
        IFS=: read -r uuid type name <<< "$line"
        [[ -n ${uuid:-} && -n ${type:-} && -n ${name:-} ]] || return 1
        if [[ $name == "$MVC24GD4_TEMP_NAME" || $uuid == "$MVC24GD4_TEMP_UUID" ]]; then
            [[ $uuid == "$MVC24GD4_TEMP_UUID" && $type == wireguard && $name == "$MVC24GD4_TEMP_NAME" ]] || return 1
            ((n+=1))
        fi
    done <<< "$rows"
    (( n <= 1 )) || return 1
    active=$(nmcli --wait 10 --colors no -t -f UUID connection show --active 2>/dev/null) || return 1
    while IFS= read -r line; do
        [[ $line == "$MVC24GD4_TEMP_UUID" ]] && ((found+=1))
    done <<< "$active"
    (( found <= 1 && found <= n )) || return 1
    if (( n == 0 )); then
        MVC24PUBR_NM_STATUS=absent
    elif (( found == 1 )); then
        MVC24PUBR_NM_STATUS=active
    else
        MVC24PUBR_NM_STATUS=down
    fi
    if [[ $MVC24PUBR_NM_STATUS != absent ]]; then
        iface=$(nmcli --wait 10 --colors no -g connection.interface-name connection show uuid "$MVC24GD4_TEMP_UUID" 2>/dev/null) || return 1
        [[ $iface == "$MVC24GD4_TEMP_NAME" ]] || return 1
    fi
}

mvc24pubr_kernel_inventory() {
    (( $# == 0 )) || return 1
    local link=no wg=no
    MVC24PUBR_KERNEL_STATUS=absent
    ip link show dev "$MVC24GD4_TEMP_NAME" >/dev/null 2>&1 && link=yes
    wg show "$MVC24GD4_TEMP_NAME" >/dev/null 2>&1 && wg=yes
    [[ $link == "$wg" ]] || return 1
    [[ $link == yes ]] && MVC24PUBR_KERNEL_STATUS=active
    case $MVC24PUBR_NM_STATUS in
      active) [[ $MVC24PUBR_KERNEL_STATUS == active ]] ;;
      down|absent) [[ $MVC24PUBR_KERNEL_STATUS == absent ]] ;;
      *) return 1 ;;
    esac
}

mvc24pubr_route_inventory() {
    (( $# == 0 )) || return 1
    local all count exact
    MVC24PUBR_ROUTE_STATUS=unknown
    all=$(ip -j -N -4 route show table all proto 186) || return 1
    jq -e 'type=="array" and length<=1' <<< "$all" >/dev/null 2>&1 || return 1
    count=$(jq -r 'length' <<< "$all") || return 1
    if (( count == 1 )); then
        mvc24gd4_endpoint_route_observed || return 1
        MVC24PUBR_ROUTE_STATUS=owned
        return 0
    fi
    exact=$(ip -j -N -4 route show exact "$MVC24GD4_ENDPOINT_IP/32" table main) || return 1
    jq -e 'type=="array" and length==0' <<< "$exact" >/dev/null 2>&1 || return 1
    MVC24PUBR_ROUTE_STATUS=absent
}

mvc24pubr_keyfile_inventory() {
    (( $# == 0 )) || return 1
    MVC24PUBR_KEYFILE_STATUS=absent
    if [[ -e $MVC24GD4_TEMP_FILE || -L $MVC24GD4_TEMP_FILE ]]; then
        [[ -f $MVC24GD4_TEMP_FILE && ! -L $MVC24GD4_TEMP_FILE &&
           $(stat -c '%u:%a:%h' -- "$MVC24GD4_TEMP_FILE") == '0:600:1' &&
           $(mvc24gd2_keyfile_scalar "$MVC24GD4_TEMP_FILE" connection uuid) == "$MVC24GD4_TEMP_UUID" &&
           $(mvc24gd2_keyfile_scalar "$MVC24GD4_TEMP_FILE" connection id) == "$MVC24GD4_TEMP_NAME" &&
           $(mvc24gd2_keyfile_scalar "$MVC24GD4_TEMP_FILE" connection type) == wireguard &&
           $(mvc24gd2_keyfile_scalar "$MVC24GD4_TEMP_FILE" connection interface-name) == "$MVC24GD4_TEMP_NAME" ]] || return 1
        MVC24PUBR_KEYFILE_STATUS=owned
    fi
}

mvc24pubr_hold_inventory() {
    (( $# == 0 )) || return 1
    local json type prefix metric profile_prefix candidate count=0 exact
    local -A wanted=() seen=()
    MVC24PUBR_HOLD_STATUS=unknown
    for prefix in "${MVC24GD4_ALLOWED_IPS[@]}"; do
        mvc24gd3_private_ipv4_prefix "$prefix" && [[ -z ${wanted[$prefix]:-} ]] || return 1
        wanted[$prefix]=1
    done
    json=$(ip -j -N -4 route show table all proto "${MVC24GD4_HOLD_PROTO:-187}") || return 1
    jq -e 'type=="array"' <<< "$json" >/dev/null 2>&1 || return 1
    while IFS=$'\t' read -r type prefix metric; do
        [[ -n $prefix ]] || continue
        [[ ( $type == unreachable || $type == 7 ) && $metric == "${MVC24GD4_HOLD_METRIC:-4241}" ]] || return 1
        profile_prefix=$prefix
        if [[ -z ${wanted[$profile_prefix]:-} ]] && wg23_validate_ipv4 "$profile_prefix"; then
            candidate="${profile_prefix}/32"
            [[ -n ${wanted[$candidate]:-} ]] && profile_prefix=$candidate
        fi
        [[ -n ${wanted[$profile_prefix]:-} && -z ${seen[$profile_prefix]:-} ]] || return 1
        exact=$(ip -j -N -4 route show exact "$profile_prefix" table main type unreachable) || return 1
        mvc24gd4_private_hold_exact_observed "$profile_prefix" || return 1
        seen[$profile_prefix]=1
        ((count+=1))
    done < <(jq -r '.[] | [(.type // "unicast"), (.dst // ""), ((.metric // "")|tostring)] | @tsv' <<< "$json")
    if (( count == 0 )); then
        MVC24PUBR_HOLD_STATUS=absent
    elif (( count == ${#MVC24GD4_ALLOWED_IPS[@]} )); then
        MVC24PUBR_HOLD_STATUS=full
    else
        MVC24PUBR_HOLD_STATUS=partial
    fi
}

mvc24pubr_ensure_hold_routes() {
    (( $# == 0 )) || return 1
    local prefix json rc
    mvc24pubr_hold_inventory || return 1
    for prefix in "${MVC24GD4_ALLOWED_IPS[@]}"; do
        json=$(ip -j -N -4 route show exact "$prefix" table main type unreachable) || return 1
        jq -e 'type=="array"' <<< "$json" >/dev/null 2>&1 || return 1
        if ! jq -e 'length==0' <<< "$json" >/dev/null 2>&1; then
            mvc24gd4_private_hold_exact_observed "$prefix" || return 1
            continue
        fi
        set +e
        ip -4 route add unreachable "$prefix" proto "${MVC24GD4_HOLD_PROTO:-187}" metric "${MVC24GD4_HOLD_METRIC:-4241}" >/dev/null 2>&1
        rc=$?
        set -e
        : "$rc"
        mvc24gd4_private_hold_exact_observed "$prefix" || return 1
    done
    mvc24pubr_hold_inventory && [[ $MVC24PUBR_HOLD_STATUS == full ]]
}

mvc24pubr_guard_inventory() {
    (( $# == 0 )) || return 1
    local scratch first second result=1
    MVC24PUBR_GUARD_STATUS=unknown
    scratch=$(umask 077; mktemp -d /dev/shm/ubs-v240-pubr-guard.XXXXXXXX) || return 1
    first=$scratch/first.json second=$scratch/second.json
    if mvc24gb1_capture_nft "$first" && mvc24gb1_capture_nft "$second" && cmp -s -- "$first" "$second" &&
       mvc24gd4_foreign_policy_unchanged "$first"; then
        if mvc24gc11_postshape_observation "$first" "$MVC24GC3_IFACE" "$MVC24GC3_SOURCE" "$MVC24GC3_REMOTE" "$MVC24GC3_PORT" \
             "$MVC24GC11_TUNNEL" "$MVC24GC11_TUNNEL_SOURCE"; then
            MVC24PUBR_GUARD_STATUS=c11
            result=0
        elif mvc24gd4_parallel_guard_observation "$first" "$MVC24GD4_UNDERLAY" "$MVC24GD4_UNDERLAY_SOURCE" \
             "$MVC24GC3_REMOTE" "$MVC24GC3_PORT" "$MVC24GC11_TUNNEL" "$MVC24GC11_TUNNEL_SOURCE" \
             "$MVC24GD4_TEMP_NAME" "$MVC24GD4_WG_SOURCE" "$MVC24GD4_ENDPOINT_IP" "$MVC24GD4_ENDPOINT_PORT" \
             "${MVC24GD4_ALLOWED_IPS[@]}"; then
            MVC24PUBR_GUARD_STATUS=parallel
            result=0
        fi
    fi
    rm -f -- "$first" "$second" || result=1
    rmdir -- "$scratch" || result=1
    (( result == 0 ))
}

mvc24pubr_inventory_all() {
    (( $# == 0 )) || return 1
    mvc24pubr_context_witness || return 1
    mvc24pubr_nm_inventory && mvc24pubr_kernel_inventory && mvc24pubr_route_inventory &&
      mvc24pubr_keyfile_inventory && mvc24pubr_hold_inventory && mvc24pubr_guard_inventory
}

# v2.4.1 C24A Stage 2: classify only the inverse post-publication dropout
# where OpenVPN has already been rehydrated as healthy by the public disconnect
# coordinator but the exact authenticated WG side is no longer active.  Do not
# turn a generic dual-active observation failure into cleanup authority: require
# the WG profile/link to be down/absent, no pre-existing private holds, the exact
# parallel guard, and only owned-or-absent endpoint/keyfile residue.
mvc24pubr_published_wg_absent_observed() {
    (( $# == 0 )) || return 1
    mvc24pubr_inventory_all || return 1
    [[ ( $MVC24PUBR_NM_STATUS == down || $MVC24PUBR_NM_STATUS == absent ) &&
       $MVC24PUBR_KERNEL_STATUS == absent &&
       ( $MVC24PUBR_ROUTE_STATUS == owned || $MVC24PUBR_ROUTE_STATUS == absent ) &&
       ( $MVC24PUBR_KEYFILE_STATUS == owned || $MVC24PUBR_KEYFILE_STATUS == absent ) &&
       $MVC24PUBR_HOLD_STATUS == absent &&
       $MVC24PUBR_GUARD_STATUS == parallel ]]
}

# Normalize an authenticated published combined session whose WG side has
# independently disappeared while OpenVPN remains healthy.  Establish private
# holds before changing the parallel guard, restore exact C11, retire any exact
# remaining endpoint/profile/keyfile residue, and end at the same D4 handback
# state as the ordinary WG-first stop path.  This function is intentionally
# separate from startup-partial reconciliation so the older admission contract
# is not broadened.
mvc24pubr_reconcile_published_wg_absent_to_openvpn_hold() {
    (( $# == 0 )) || return 1
    MVC24PUBR_STAGE=inventory-published-wireguard-dropout
    mvc24pubr_inventory_all || return 1
    [[ ( $MVC24PUBR_NM_STATUS == down || $MVC24PUBR_NM_STATUS == absent ) &&
       $MVC24PUBR_KERNEL_STATUS == absent &&
       ( $MVC24PUBR_ROUTE_STATUS == owned || $MVC24PUBR_ROUTE_STATUS == absent ) &&
       ( $MVC24PUBR_KEYFILE_STATUS == owned || $MVC24PUBR_KEYFILE_STATUS == absent ) &&
       $MVC24PUBR_HOLD_STATUS == absent &&
       $MVC24PUBR_GUARD_STATUS == parallel ]] || return 1

    MVC24PUBR_STAGE=establishing-private-holds-published-wireguard-dropout
    mvc24pubr_ensure_hold_routes || return 1

    # WG is already down/absent by classification; re-observe route/guard before
    # the one firewall transition.  Unlike startup-partial reconciliation, an
    # endpoint route already lost with the underlay is an admitted observation.
    mvc24pubr_route_inventory && mvc24pubr_guard_inventory || return 1
    [[ $MVC24PUBR_ROUTE_STATUS == owned || $MVC24PUBR_ROUTE_STATUS == absent ]] || return 1
    [[ $MVC24PUBR_GUARD_STATUS == parallel ]] || return 1
    MVC24GD4_STAGE=wireguard-down-parallel-guard-retained-private-hold
    MVC24PUBR_STAGE=restoring-openvpn-guard-published-wireguard-dropout
    mvc24gd4_restore_openvpn_guard || return 1
    MVC24PUBR_GUARD_STATUS=c11

    MVC24PUBR_STAGE=removing-endpoint-route-published-wireguard-dropout
    mvc24pubr_remove_endpoint_route_if_owned || return 1
    MVC24GD4_STAGE=owned-endpoint-route-absent-profile-remains-private-hold

    MVC24PUBR_STAGE=removing-temporary-profile-published-wireguard-dropout
    mvc24pubr_remove_profile_if_owned || return 1
    MVC24GD4_STAGE=temporary-profile-absent-pure-openvpn-protected-private-hold

    MVC24PUBR_STAGE=verifying-openvpn-handback-published-wireguard-dropout
    mvc24gd4_finish_teardown || return 1
    [[ ${MVC24GD4_STAGE:-} == wireguard-residue-removed-openvpn-protected-private-hold ]] || return 1
    MVC24PUBR_STAGE=published-wireguard-dropout-reconciled-openvpn-protected-private-hold
}

mvc24pubr_disconnect_wg_if_active() {
    (( $# == 0 )) || return 1
    local rc
    mvc24pubr_nm_inventory && mvc24pubr_kernel_inventory || return 1
    if [[ $MVC24PUBR_NM_STATUS == active ]]; then
        [[ $MVC24PUBR_GUARD_STATUS == parallel && $MVC24PUBR_ROUTE_STATUS == owned ]] || return 1
        set +e
        nmcli --wait 60 connection down uuid "$MVC24GD4_TEMP_UUID" >/dev/null 2>&1
        rc=$?
        set -e
        MVC24GD4_NM_DOWN_EXIT_STATUS=$rc
        mvc24pubr_nm_inventory && mvc24pubr_kernel_inventory || return 1
        [[ $MVC24PUBR_NM_STATUS == down || $MVC24PUBR_NM_STATUS == absent ]] || return 1
    fi
}


# v2.4.1 dropout variant: the physical underlay can disappear long enough for
# NetworkManager to remove the proto-186 endpoint route while the exact WG
# connection/link survives. In that authenticated state, route=absent is not an
# ambiguity. Require the exact parallel guard before issuing the one NM down.
mvc24pubr_disconnect_wg_dropout_if_active() {
    (( $# == 0 )) || return 1
    local rc
    mvc24pubr_nm_inventory && mvc24pubr_kernel_inventory && mvc24pubr_route_inventory || return 1
    if [[ $MVC24PUBR_NM_STATUS == active ]]; then
        [[ $MVC24PUBR_GUARD_STATUS == parallel &&
           ( $MVC24PUBR_ROUTE_STATUS == owned || $MVC24PUBR_ROUTE_STATUS == absent ) ]] || return 1
        set +e
        nmcli --wait 60 connection down uuid "$MVC24GD4_TEMP_UUID" >/dev/null 2>&1
        rc=$?
        set -e
        MVC24GD4_NM_DOWN_EXIT_STATUS=$rc
        mvc24pubr_nm_inventory && mvc24pubr_kernel_inventory || return 1
        [[ $MVC24PUBR_NM_STATUS == down || $MVC24PUBR_NM_STATUS == absent ]] || return 1
    fi
}

mvc24pubr_remove_endpoint_route_if_owned() {
    (( $# == 0 )) || return 1
    local -a argv
    local rc
    mvc24pubr_route_inventory || return 1
    if [[ $MVC24PUBR_ROUTE_STATUS == owned ]]; then
        argv=(-4 route del "$MVC24GD4_ENDPOINT_IP/32")
        [[ $MVC24GD4_UNDERLAY_GATEWAY == - ]] || argv+=(via "$MVC24GD4_UNDERLAY_GATEWAY")
        argv+=(dev "$MVC24GD4_UNDERLAY" src "$MVC24GD4_UNDERLAY_SOURCE" proto 186 metric 4240)
        set +e
        ip "${argv[@]}" >/dev/null 2>&1
        rc=$?
        set -e
        : "$rc"
        mvc24pubr_route_inventory && [[ $MVC24PUBR_ROUTE_STATUS == absent ]] || return 1
    fi
}

mvc24pubr_remove_profile_if_owned() {
    (( $# == 0 )) || return 1
    local rc
    mvc24pubr_nm_inventory && mvc24pubr_kernel_inventory && mvc24pubr_keyfile_inventory || return 1
    [[ $MVC24PUBR_NM_STATUS != active ]] || return 1
    if [[ $MVC24PUBR_NM_STATUS == down ]]; then
        set +e
        nmcli --wait 30 connection delete uuid "$MVC24GD4_TEMP_UUID" >/dev/null 2>&1
        rc=$?
        set -e
        : "$rc"
        mvc24pubr_nm_inventory && mvc24pubr_kernel_inventory || return 1
        [[ $MVC24PUBR_NM_STATUS == absent ]] || return 1
    fi
    mvc24pubr_keyfile_inventory || return 1
    if [[ $MVC24PUBR_KEYFILE_STATUS == owned ]]; then
        rm -f -- "$MVC24GD4_TEMP_FILE" || return 1
    fi
    mvc24pubr_nm_inventory && mvc24pubr_kernel_inventory && mvc24pubr_keyfile_inventory || return 1
    [[ $MVC24PUBR_NM_STATUS == absent && $MVC24PUBR_KERNEL_STATUS == absent && $MVC24PUBR_KEYFILE_STATUS == absent ]]
}

# Normalize any authenticated D4 startup residue to the same state produced by
# successful mvc24gd4_stop_once immediately before OpenVPN-only reobservation:
# exact C11 guard, no WG profile/link/endpoint route, and full private holds.
mvc24pubr_reconcile_partial_d4_to_openvpn_hold() {
    (( $# == 0 )) || return 1
    MVC24PUBR_STAGE=inventory-partial-wireguard
    mvc24pubr_inventory_all || return 1

    # WG cannot legitimately be active before the parallel guard is exact.
    if [[ $MVC24PUBR_NM_STATUS == active && $MVC24PUBR_GUARD_STATUS != parallel ]]; then
        MVC24PUBR_STAGE=impossible-active-wireguard-without-parallel-guard
        return 1
    fi

    MVC24PUBR_STAGE=establishing-private-holds
    mvc24pubr_ensure_hold_routes || return 1

    MVC24PUBR_STAGE=stopping-partial-wireguard
    mvc24pubr_disconnect_wg_if_active || return 1

    # Re-observe guard/route after any NM down before changing firewall state.
    mvc24pubr_route_inventory && mvc24pubr_guard_inventory || return 1
    if [[ $MVC24PUBR_GUARD_STATUS == parallel ]]; then
        [[ $MVC24PUBR_ROUTE_STATUS == owned ]] || return 1
        MVC24GD4_STAGE=wireguard-down-parallel-guard-retained-private-hold
        MVC24PUBR_STAGE=restoring-openvpn-guard
        mvc24gd4_restore_openvpn_guard || return 1
        MVC24PUBR_GUARD_STATUS=c11
    else
        [[ $MVC24PUBR_GUARD_STATUS == c11 ]] || return 1
    fi

    MVC24PUBR_STAGE=removing-endpoint-route
    mvc24pubr_remove_endpoint_route_if_owned || return 1
    MVC24GD4_STAGE=owned-endpoint-route-absent-profile-remains-private-hold

    MVC24PUBR_STAGE=removing-temporary-profile
    mvc24pubr_remove_profile_if_owned || return 1
    MVC24GD4_STAGE=temporary-profile-absent-pure-openvpn-protected-private-hold

    MVC24PUBR_STAGE=verifying-openvpn-handback
    mvc24gd4_finish_teardown || return 1
    [[ ${MVC24GD4_STAGE:-} == wireguard-residue-removed-openvpn-protected-private-hold ]] || return 1
    MVC24PUBR_STAGE=partial-wireguard-reconciled-openvpn-protected-private-hold
}

# Normalize the exact post-publication dropout observed on 2026-11-06:
# OpenVPN/tun is already absent, the authenticated WG survivor may be active,
# and its proto-186 route may already be gone after underlay loss. Establish
# private holds first, remove WG once, restore exact C11 if D4 is still present,
# then retire route/profile residue without requiring an OpenVPN default route.
mvc24pubr_reconcile_d4_to_c11_hold_openvpn_absent() {
    (( $# == 0 )) || return 1
    MVC24PUBR_STAGE=inventory-openvpn-dropout-wireguard
    mvc24pubr_inventory_all || return 1

    [[ $MVC24PUBR_HOLD_STATUS != partial ]] || return 1
    if [[ $MVC24PUBR_NM_STATUS == active ]]; then
        [[ $MVC24PUBR_GUARD_STATUS == parallel &&
           ( $MVC24PUBR_ROUTE_STATUS == owned || $MVC24PUBR_ROUTE_STATUS == absent ) ]] || return 1
    fi
    case $MVC24PUBR_GUARD_STATUS in parallel|c11) ;; *) return 1 ;; esac

    MVC24PUBR_STAGE=establishing-private-holds-openvpn-dropout
    mvc24pubr_ensure_hold_routes || return 1

    MVC24PUBR_STAGE=stopping-wireguard-openvpn-dropout
    mvc24pubr_disconnect_wg_dropout_if_active || return 1

    mvc24pubr_route_inventory && mvc24pubr_guard_inventory || return 1
    if [[ $MVC24PUBR_GUARD_STATUS == parallel ]]; then
        MVC24GD4_STAGE=wireguard-down-parallel-guard-retained-private-hold
        MVC24PUBR_STAGE=restoring-c11-after-openvpn-dropout
        mvc24gd4_restore_openvpn_guard || return 1
        MVC24PUBR_GUARD_STATUS=c11
    else
        [[ $MVC24PUBR_GUARD_STATUS == c11 ]] || return 1
    fi

    MVC24PUBR_STAGE=removing-endpoint-route-openvpn-dropout
    mvc24pubr_remove_endpoint_route_if_owned || return 1
    MVC24GD4_STAGE=owned-endpoint-route-absent-profile-remains-private-hold

    MVC24PUBR_STAGE=removing-temporary-profile-openvpn-dropout
    mvc24pubr_remove_profile_if_owned || return 1

    MVC24PUBR_STAGE=verifying-c11-hold-openvpn-absent
    mvc24pubr_inventory_all || return 1
    [[ $MVC24PUBR_NM_STATUS == absent &&
       $MVC24PUBR_KERNEL_STATUS == absent &&
       $MVC24PUBR_ROUTE_STATUS == absent &&
       $MVC24PUBR_KEYFILE_STATUS == absent &&
       $MVC24PUBR_HOLD_STATUS == full &&
       $MVC24PUBR_GUARD_STATUS == c11 ]] || return 1
    MVC24GD4_STAGE=wireguard-residue-removed-openvpn-absent-c11-private-hold
    MVC24PUBR_STAGE=openvpn-dropout-wireguard-reconciled-c11-private-hold
}

mvc24pubr_reset
