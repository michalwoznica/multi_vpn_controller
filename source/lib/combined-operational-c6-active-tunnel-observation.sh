#!/usr/bin/env bash
# Gate C6: PRIVATE READ-ONLY observation following successful C5 NM activation.
# Requires the SAME held B2/C3 lock and C1 endpoint-restricted firewall.
# A result is a bounded NM/IPv4 route observation ONLY: no OpenVPN peer/socket,
# packet egress, DNS, FORWARD transition, credentials, teardown or authority.
# No host or public driver imports this file. No NM, nft or route writes.

mvc24gc6_reset() {
    MVC24GC6_STAGE=unverified
    MVC24GC6_AUTHORITY=none
    MVC24GC6_NM_SNAPSHOT=
    MVC24GC6_ROUTE_SNAPSHOT=
}

mvc24gc6_authorize_activation() { return 1; }
mvc24gc6_authorize_traffic() { return 1; }
mvc24gc6_authorize_cleanup() { return 1; }
mvc24gc6_authorize_disarm() { return 1; }
mvc24gc6_authorize_recovery() { return 1; }

# Underlay and tunnel are distinct kernel interface roles. The B1 validator
# intentionally excludes tun* and wg* from PHYSICAL underlay selection.
# Using it to attest the VPN device prevents every legitimate tun* route
# from ever passing C6. Only a literal, kernel-bounded tun* name is accepted
# for the VPN role; do not weaken the B1 physical-underlay validator.
mvc24gc6_valid_tunnel_ifname() {
    (( $# == 1 )) || return 1
    [[ $1 =~ ^tun[a-zA-Z0-9_.-]*$ && ${#1} -le 15 ]]
}

# Strictly observe the known C5 ActiveConnection and its IPv4 default-route
# ownership. This NM property does not establish the kernel route or tun peer.
mvc24gc6_nm_ipv4_snapshot() {
    (( $# == 2 )) || return 1
    local clone=$1 owner=$2 identity active settings config default
    identity=$(mvc24gc5_active_snapshot "$clone" "$owner") || return 1
    [[ $identity =~ ^(/org/freedesktop/NetworkManager/ActiveConnection/[0-9]+)\|(/org/freedesktop/NetworkManager/Settings/[0-9]+)$ ]] || return 1
    active=${BASH_REMATCH[1]} settings=${BASH_REMATCH[2]}
    local config_re='^o "(/org/freedesktop/NetworkManager/IP4Config/[0-9]+)"$'
    declare -F mvc24g_get_property >/dev/null || return 1
    config=$(mvc24g_get_property org.freedesktop.NetworkManager "$active" \
        org.freedesktop.NetworkManager.Connection.Active Ip4Config o) || return 1
    default=$(mvc24g_get_property org.freedesktop.NetworkManager "$active" \
        org.freedesktop.NetworkManager.Connection.Active Default b) || return 1
    [[ $config =~ $config_re &&
       $default == 'b true' ]] || return 1
    printf '%s|%s|%s\n' "$active" "$settings" "${BASH_REMATCH[1]}"
}

# Parse ONE exact route-get object; no packet is sent. Reject missing, null,
# multiple, malformed or unexpected dev/source fields (no fuzzy matching).
mvc24gc6_route_get() {
    (( $# == 1 )) || return 1
    local raw summary interface address
    mvc24gc1_ipv4 "$1" || return 1
    raw=$(ip -j -4 route get "$1" 2>/dev/null) || return 1
    summary=$(jq -er '
      if type == "array" and length == 1 and (.[0]|type) == "object" then
        .[0] | if (.dev|type)=="string" and (.dev|length)>0 and
                  ((.prefsrc // .src)|type)=="string" then
                [.dev, (.prefsrc // .src)] | join("|")
               else empty end
      else empty end
    ' <<< "$raw") || return 1
    [[ $summary =~ ^([a-zA-Z0-9_.-]+)\|([0-9.]+)$ ]] || return 1
    interface=${BASH_REMATCH[1]} address=${BASH_REMATCH[2]}
    if [[ $interface == tun* ]]; then
        mvc24gc6_valid_tunnel_ifname "$interface" || return 1
    else
        mvc24gb1_valid_ifname "$interface" || return 1
    fi
    mvc24gc1_ipv4 "$address" || return 1
    printf '%s\n' "$summary"
}

# Two unrelated numeric IPv4 lookups must select the SAME non-underlay tun
# interface/source. The pinned remote must retain its exact underlay/source.
# No DNS resolution, external connect, fake traffic success or route changes.
mvc24gc6_kernel_ipv4_snapshot() {
    (( $# == 3 )) || return 1
    local underlay=$1 source=$2 remote=$3 endpoint primary secondary dev tunnel_ip
    local address link
    mvc24gb1_valid_ifname "$underlay" && mvc24gc1_ipv4 "$source" &&
        mvc24gc1_ipv4 "$remote" || return 1
    [[ $remote != 1.1.1.1 && $remote != 9.9.9.9 ]] || return 1
    endpoint=$(mvc24gc6_route_get "$remote") || return 1
    [[ $endpoint == "$underlay|$source" ]] || return 1
    primary=$(mvc24gc6_route_get 1.1.1.1) || return 1
    secondary=$(mvc24gc6_route_get 9.9.9.9) || return 1
    [[ $primary == "$secondary" && $primary != "$endpoint" &&
       $primary =~ ^(tun[a-zA-Z0-9_.-]*)\|([0-9.]+)$ ]] || return 1
    dev=${BASH_REMATCH[1]} tunnel_ip=${BASH_REMATCH[2]}
    mvc24gc1_ipv4 "$tunnel_ip" &&
        mvc24gc6_valid_tunnel_ifname "$dev" &&
        [[ $dev != "$underlay" ]] || return 1
    address=$(ip -j -4 address show dev "$dev" 2>/dev/null) || return 1
    jq -e --arg dev "$dev" --arg src "$tunnel_ip" '
        type=="array" and length==1 and .[0].ifname==$dev and
        (.[0].addr_info|type)=="array" and
        ([.[0].addr_info[]|select(.family=="inet" and .local==$src)]|length)==1
    ' <<< "$address" >/dev/null 2>&1 || return 1
    link=$(ip -j link show dev "$dev" 2>/dev/null) || return 1
    jq -e --arg dev "$dev" '
        type=="array" and length==1 and .[0].ifname==$dev and
        (.[0].flags|type)=="array" and (.[0].flags|index("UP"))!=null
    ' <<< "$link" >/dev/null 2>&1 || return 1
    printf '%s|%s|%s|%s\n' "$underlay" "$source" "$dev" "$tunnel_ip"
}

mvc24gc6_observe_active_once() {
    (( $# == 0 )) || return 1
    MVC24GC6_STAGE=unverified
    MVC24GC6_AUTHORITY=none
    MVC24GC6_NM_SNAPSHOT= MVC24GC6_ROUTE_SNAPSHOT=
    [[ ${MVC24GC5_STAGE:-} == nm-openvpn-active-and-bootstrap-guard-observed-no-traffic-authority &&
       ${MVC24GC5_AUTHORITY:-} == none && ${MVC24GC5_ATTEMPTED:-} == yes &&
       ${MVC24GC3_STAGE:-} == pinned-bootstrap-verified-no-vpn-authority &&
       ${MVC24GC3_AUTHORITY:-} == none &&
       -n ${MVC24GA3_PREPARED_CLONE_UUID:-} &&
       -n ${MVC24GC5_NM_OWNER:-} ]] || return 1
    local nm_first nm_second route_first route_second
    mvc24gc5_guard_witness && mvc24gc5_prepared_profile_witness || return 1
    nm_first=$(mvc24gc6_nm_ipv4_snapshot "$MVC24GA3_PREPARED_CLONE_UUID" "$MVC24GC5_NM_OWNER") || return 1
    route_first=$(mvc24gc6_kernel_ipv4_snapshot "$MVC24GC3_IFACE" "$MVC24GC3_SOURCE" "$MVC24GC3_REMOTE") || return 1
    route_second=$(mvc24gc6_kernel_ipv4_snapshot "$MVC24GC3_IFACE" "$MVC24GC3_SOURCE" "$MVC24GC3_REMOTE") || return 1
    nm_second=$(mvc24gc6_nm_ipv4_snapshot "$MVC24GA3_PREPARED_CLONE_UUID" "$MVC24GC5_NM_OWNER") || return 1
    [[ -n $nm_first && $nm_first == "$nm_second" &&
       -n $route_first && $route_first == "$route_second" ]] || return 1
    mvc24gc5_guard_witness && mvc24gc5_prepared_profile_witness || return 1
    MVC24GC6_NM_SNAPSHOT=$nm_first
    MVC24GC6_ROUTE_SNAPSHOT=$route_first
    MVC24GC6_STAGE=nm-active-and-selected-ipv4-tun-observed-no-traffic-authority
}
