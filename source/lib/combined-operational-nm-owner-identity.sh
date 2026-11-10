#!/usr/bin/env bash
# Root-neutral NetworkManager D-Bus owner identity witness.
# Extracted from combined-operational-session-underlay-binding.sh so the
# reconstructed /run/ubs-v240-* composition does not import the older
# older controller runtime family merely to obtain this helper.
# Read-only: no NetworkManager, D-Bus, nftables, route, DNS or file writes.

ubs24op_session_nm_identity() {
    UBS24OP_SESSION_NM_IDENTITY=''
    (( $# == 0 )) || return 1
    local initial final pid_reply uid_reply owner pid uid
    local owner_re='^s "(:[0-9]+\.[0-9]+)"$'
    declare -F ubs24g_call_readonly >/dev/null || return 1
    initial=$(ubs24g_call_readonly org.freedesktop.DBus /org/freedesktop/DBus \
        org.freedesktop.DBus GetNameOwner s org.freedesktop.NetworkManager s) || return 1
    [[ $initial =~ $owner_re ]] || return 1
    owner=${BASH_REMATCH[1]}
    pid_reply=$(ubs24g_call_readonly org.freedesktop.DBus /org/freedesktop/DBus \
        org.freedesktop.DBus GetConnectionUnixProcessID s "$owner" u) || return 1
    [[ $pid_reply =~ ^u[[:space:]]([1-9][0-9]*)$ ]] || return 1
    pid=${BASH_REMATCH[1]}
    uid_reply=$(ubs24g_call_readonly org.freedesktop.DBus /org/freedesktop/DBus \
        org.freedesktop.DBus GetConnectionUnixUser s "$owner" u) || return 1
    [[ $uid_reply == 'u 0' ]] || return 1
    uid=0
    final=$(ubs24g_call_readonly org.freedesktop.DBus /org/freedesktop/DBus \
        org.freedesktop.DBus GetNameOwner s org.freedesktop.NetworkManager s) || return 1
    [[ $initial == "$final" ]] || return 1
    UBS24OP_SESSION_NM_IDENTITY="$owner|$pid|$uid"
}
