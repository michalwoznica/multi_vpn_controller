#!/usr/bin/env bash
# Step 2B2C3D: read-only host NM owner and selected-underlay evidence bound
# to ONE authenticated, prepared OpenVPN session under the verified flock.
# A success is evidence consistency only; NEVER permission for nft or NM writes.
# No new parser for NetworkManager nested settings, no profile creation,
# no DNS, no host runtime repair, no activation and no teardown.

mvc24op_session_nm_identity() {
    MVC24OP_SESSION_NM_IDENTITY=''
    (( $# == 0 )) || return 1
    local initial final pid_reply uid_reply owner pid uid
    local owner_re='^s "(:[0-9]+\.[0-9]+)"$'
    declare -F mvc24g_call_readonly >/dev/null || return 1
    initial=$(mvc24g_call_readonly org.freedesktop.DBus /org/freedesktop/DBus \
        org.freedesktop.DBus GetNameOwner s org.freedesktop.NetworkManager s) || return 1
    [[ $initial =~ $owner_re ]] || return 1
    owner=${BASH_REMATCH[1]}
    pid_reply=$(mvc24g_call_readonly org.freedesktop.DBus /org/freedesktop/DBus \
        org.freedesktop.DBus GetConnectionUnixProcessID s "$owner" u) || return 1
    [[ $pid_reply =~ ^u[[:space:]]([1-9][0-9]*)$ ]] || return 1
    pid=${BASH_REMATCH[1]}
    uid_reply=$(mvc24g_call_readonly org.freedesktop.DBus /org/freedesktop/DBus \
        org.freedesktop.DBus GetConnectionUnixUser s "$owner" u) || return 1
    # System NetworkManager daemon is expected to run under root; refuse a
    # different bus-owner UID rather than treating it as privileged evidence.
    [[ $uid_reply == 'u 0' ]] || return 1
    uid=0
    final=$(mvc24g_call_readonly org.freedesktop.DBus /org/freedesktop/DBus \
        org.freedesktop.DBus GetNameOwner s org.freedesktop.NetworkManager s) || return 1
    [[ $initial == "$final" ]] || return 1
    MVC24OP_SESSION_NM_IDENTITY="$owner|$pid|$uid"
}

# Parameterised testable check. The two nft observations MUST originate from
# an independent trusted capture in production. Never interpret the returned
# finding as an authorisation token or accept caller-provided host evidence.
mvc24op_session_underlay_prepared_locked() {
    MVC24OP_SESSION_UNDERLAY_FINDING=''
    (( $# == 4 )) || return 1
    local runtime=$1 uid=$2 first=$3 second=$4
    local owner_before state_before profile_before nm_before nm_after
    local owner_after state_after profile_after underlay
    [[ $uid == "$EUID" && -n $first && $first == "$second" ]] || return 1
    mvc24s_lock_descriptor_verified || return 1
    [[ ${MVC24S_LOCK_PATH:-} == "$runtime/controller.lock" ]] || return 1
    mvc24op_session_nm_identity || return 1
    nm_before=$MVC24OP_SESSION_NM_IDENTITY
    owner_before=$(sha256sum -- "$runtime/session/ownership") || return 1
    state_before=$(sha256sum -- "$runtime/state") || return 1
    profile_before=$(sha256sum -- "$runtime/session/ovpn-source.nmconnection") || return 1
    # Includes exact captured profile/endpoint/transport, saved source hashes,
    # actual physical NM device and its selected IPv4 route, and lock recheck.
    mvc24op_live_underlay_prepared_locked "$runtime" "$uid" "$first" "$second" || return 1
    [[ ${MVC24OP_LIVE_UNDERLAY_FINDING:-} == prepared-underlay-observed-only ]] || return 1
    underlay=${MVC24OP_UNDERLAY_SNAPSHOT:-}
    [[ -n $underlay ]] || return 1
    mvc24op_session_nm_identity || return 1
    nm_after=$MVC24OP_SESSION_NM_IDENTITY
    [[ -n $nm_before && $nm_before == "$nm_after" ]] || return 1
    owner_after=$(sha256sum -- "$runtime/session/ownership") || return 1
    state_after=$(sha256sum -- "$runtime/state") || return 1
    profile_after=$(sha256sum -- "$runtime/session/ovpn-source.nmconnection") || return 1
    [[ $owner_before == "$owner_after" && $state_before == "$state_after" &&
       $profile_before == "$profile_after" ]] || return 1
    mvc24s24oa_inspect_locked "$runtime" "$runtime/session" "$uid" || return 1
    mvc24s_lock_descriptor_verified || return 1
    MVC24OP_SESSION_UNDERLAY_FINDING=prepared-session-bound-live-underlay-readonly
}

# Only this fixed-root wrapper may inspect a production-prepared session. It
# requires root and never creates /run, a lockfile, records or nft rules.
mvc24op_session_underlay_production_locked() {
    MVC24OP_SESSION_UNDERLAY_FINDING=''
    (( $# == 0 && EUID == 0 )) || return 1
    mvc24e_production_root_valid && mvc24s_lock_descriptor_verified || return 1
    [[ ${MVC24S_LOCK_PATH:-} == /run/ubs-vpn-controller-v240/controller.lock ]] || return 1
    local first second third
    first=$(mvc24oc_read_kernel) || return 1
    second=$(mvc24oc_read_kernel) || return 1
    mvc24op_session_underlay_prepared_locked /run/ubs-vpn-controller-v240 0 \
        "$first" "$second" || return 1
    third=$(mvc24oc_read_kernel) || { MVC24OP_SESSION_UNDERLAY_FINDING=''; return 1; }
    if [[ $second != "$third" ]] || ! mvc24s_lock_descriptor_verified; then
        MVC24OP_SESSION_UNDERLAY_FINDING=''
        return 1
    fi
}

mvc24op_session_underlay_production_inspect() {
    MVC24OP_SESSION_UNDERLAY_FINDING=''
    (( $# == 0 && EUID == 0 )) || return 1
    mvc24e_production_root_valid || return 1
    [[ -f /run/ubs-vpn-controller-v240/controller.lock ]] || return 1
    if ! mvc24s_with_lock /run/ubs-vpn-controller-v240/controller.lock \
        mvc24op_session_underlay_production_locked; then
        MVC24OP_SESSION_UNDERLAY_FINDING=''
        return 1
    fi
}

mvc24op_session_underlay_authorize_nft() { return 1; }
mvc24op_session_underlay_authorize_nm_start() { return 1; }
mvc24op_session_underlay_authorize_disarm() { return 1; }
mvc24op_session_underlay_authorize_recovery() { return 1; }
