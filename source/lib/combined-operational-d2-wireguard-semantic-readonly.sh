#!/usr/bin/env bash
# C23AG D2 — narrow READ-ONLY WireGuard source admission for the first
# physically testable WG+OpenVPN vertical.
#
# This is deliberately NOT the historical combined controller and grants no
# NetworkManager/nft/ip mutation authority. It answers only whether one saved
# WireGuard profile is simple enough to use directly in the first prototype:
# fixed interface name, IPv4-only private AllowedIPs, no explicit DNS/default
# route takeover, and one or more IPv4 transport candidates that currently
# route over the same physical underlay as the proven C23AE OpenVPN preflight.
#
# Omitted NetworkManager settings are interpreted only where the documented
# default is safe for this already-constrained profile shape. Hostname peer
# endpoints are resolved read-only here only to prove present resolvability and
# physical-route provenance. This preflight answer set grants no later
# authority: the live dual stage must re-resolve after protected OpenVPN DNS is
# established, then bind that protected-session answer set to its guard.
#
# Requires: dual-session.sh, wireguard-peers.sh, combined-preflight.sh,
# combined-networkmanager-backend.sh (read-only validator only).

mvc24gd2_reset() {
    MVC24GD2_STAGE=unverified
    MVC24GD2_KEYFILE=
    MVC24GD2_IFACE=
    MVC24GD2_PEER_COUNT=0
    MVC24GD2_ALLOWED_COUNT=0
    MVC24GD2_ENDPOINT_CANDIDATE_COUNT=0
    MVC24GD2_ENDPOINTS=()
    MVC24GD2_ENDPOINT_HOSTS=()
    MVC24GD2_ENDPOINT_PORTS=()
    MVC24GD2_ENDPOINT_CANDIDATES=()
    MVC24GD2_ALLOWED_IPS=()
    MVC24GD2_UNDERLAY_GATEWAY=
    MVC24GD2_UNDERLAY_SOURCE=
}

mvc24gd2_valid_wg_ifname() {
    (( $# == 2 )) || return 1
    local iface=$1 underlay=$2
    [[ $iface =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}$ &&
       $iface != lo && $iface != tun-vpnks && $iface != "$underlay" ]]
}

mvc24gd2_find_saved_keyfile() {
    (( $# == 1 )) || return 1
    local uuid=$1 dir file candidate=
    mvc24_valid_uuid "$uuid" || return 1
    for dir in /etc/NetworkManager/system-connections /run/NetworkManager/system-connections; do
        [[ -d $dir && ! -L $dir ]] || continue
        while IFS= read -r -d '' file; do
            [[ -f $file && ! -L $file ]] || continue
            if grep -Fxq -- "uuid=$uuid" "$file"; then
                [[ -z $candidate ]] || return 1
                candidate=$file
            fi
        done < <(find "$dir" -maxdepth 1 -type f -name '*.nmconnection' -print0)
    done
    [[ -n $candidate && -f $candidate && ! -L $candidate &&
       $(stat -c '%u:%a:%h' -- "$candidate") == '0:600:1' ]] || return 1
    MVC24GD2_KEYFILE=$candidate
}

mvc24gd2_keyfile_scalar() {
    (( $# == 3 )) || return 1
    local file=$1 section=$2 key=$3
    awk -v section="[$section]" -v key="$key" '
        /^\[/ { in_section=($0==section); next }
        in_section {
            n=index($0,"=")
            if (!n) next
            k=substr($0,1,n-1)
            if (k==key) { if (++count>1) exit 2; value=substr($0,n+1) }
        }
        END { if (count!=1) exit 1; print value }
    ' "$file"
}

mvc24gd2_keyfile_optional_scalar() {
    (( $# == 3 )) || return 1
    local file=$1 section=$2 key=$3
    awk -v section="[$section]" -v key="$key" '
        /^\[/ { in_section=($0==section); next }
        in_section {
            n=index($0,"=")
            if (!n) next
            k=substr($0,1,n-1)
            if (k==key) { if (++count>1) exit 2; value=substr($0,n+1) }
        }
        END { if (count>1) exit 2; if (count==1) print value }
    ' "$file"
}

mvc24gd2_true() { [[ ${1:-} == true || ${1:-} == yes || ${1:-} == 1 ]]; }
mvc24gd2_false() { [[ ${1:-} == false || ${1:-} == no || ${1:-} == 0 ]]; }

mvc24gd2_disjoint_ipv4_prefixes() {
    (( $# >= 1 && $# <= 512 )) || return 1
    local item j network mask
    local -a nets=() masks=()
    for item in "$@"; do
        [[ $item != *:* ]] && mvc24c_parse_cidr "$item" &&
            (( MVC24C_CIDR_PREFIX >= 8 )) || return 1
        network=$MVC24C_CIDR_NET mask=$MVC24C_CIDR_MASK
        for ((j=0; j<${#nets[@]}; j++)); do
            if (( (network & masks[j]) == nets[j] ||
                  (nets[j] & mask) == network )); then
                return 1
            fi
        done
        nets+=("$network") masks+=("$mask")
    done
}

# Emit a unique, bounded IPv4 answer set for one endpoint host. Numeric hosts
# are returned unchanged. Hostnames use the system NSS resolver, matching the
# ordinary host resolution path without granting any mutation authority.
mvc24gd2_resolve_ipv4_candidates() {
    (( $# == 1 )) || return 1
    local host=$1 raw ip
    local -A seen=()
    local -a out=()
    if wg23_validate_ipv4 "$host"; then
        MVC24GD2_RESOLVED_IPS=("$host")
        return 0
    fi
    wg23_validate_hostname "$host" || return 1
    command -v getent >/dev/null 2>&1 || return 1
    raw=$(getent ahostsv4 "$host") || return 1
    [[ -n $raw ]] || return 1
    while read -r ip _; do
        [[ -n $ip ]] || continue
        wg23_validate_ipv4 "$ip" || return 1
        if [[ -z ${seen[$ip]+x} ]]; then
            seen[$ip]=1
            out+=("$ip")
            (( ${#out[@]} <= 16 )) || return 1
        fi
    done <<< "$raw"
    (( ${#out[@]} >= 1 )) || return 1
    MVC24GD2_RESOLVED_IPS=("${out[@]}")
}

# Pure/keyfile-only shape check. No live networking or DNS is read here.
mvc24gd2_validate_keyfile() {
    (( $# == 3 )) || return 1
    local file=$1 uuid=$2 underlay=$3 iface peer_routes ip4_auto ip6_auto fwmark
    local v4_method v6_method v4_dns v6_dns autoconnect ep prefix host port
    MVC24GD2_STAGE=keyfile-shape
    [[ -f $file && ! -L $file && -r $file ]] || return 1
    mvc24_valid_uuid "$uuid" || return 1
    mvc24n_validate_source wg "$file" || return 1
    [[ $(mvc24gd2_keyfile_scalar "$file" connection uuid) == "$uuid" &&
       $(mvc24gd2_keyfile_scalar "$file" connection type) == wireguard ]] || return 1
    iface=$(mvc24gd2_keyfile_scalar "$file" connection interface-name) || return 1
    mvc24gd2_valid_wg_ifname "$iface" "$underlay" || return 1
    autoconnect=$(mvc24gd2_keyfile_scalar "$file" connection autoconnect) || return 1
    mvc24gd2_false "$autoconnect" || return 1

    # NetworkManager defaults are admitted only where the already-constrained
    # profile shape makes them safe. peer-routes defaults true. Auto-default-
    # route defaults are harmless here because /0 AllowedIPs are rejected
    # below; explicit TRUE remains rejected for the first vertical.
    peer_routes=$(mvc24gd2_keyfile_optional_scalar "$file" wireguard peer-routes) || return 1
    [[ -z $peer_routes ]] || mvc24gd2_true "$peer_routes" || return 1
    ip4_auto=$(mvc24gd2_keyfile_optional_scalar "$file" wireguard ip4-auto-default-route) || return 1
    ip6_auto=$(mvc24gd2_keyfile_optional_scalar "$file" wireguard ip6-auto-default-route) || return 1
    [[ -z $ip4_auto ]] || mvc24gd2_false "$ip4_auto" || return 1
    [[ -z $ip6_auto ]] || mvc24gd2_false "$ip6_auto" || return 1
    fwmark=$(mvc24gd2_keyfile_optional_scalar "$file" wireguard fwmark) || return 1
    [[ -z $fwmark || $fwmark == 0 ]] || return 1

    v4_method=$(mvc24gd2_keyfile_scalar "$file" ipv4 method) || return 1
    v6_method=$(mvc24gd2_keyfile_scalar "$file" ipv6 method) || return 1
    [[ $v4_method == manual && $v6_method == disabled ]] || return 1

    # A manual/disabled WG profile cannot learn DHCP/SLAAC DNS, so requiring
    # ignore-auto-dns=true would only duplicate a NetworkManager default that
    # is irrelevant here. Instead reject any explicit DNS payload outright.
    v4_dns=$(mvc24gd2_keyfile_optional_scalar "$file" ipv4 dns) || return 1
    v6_dns=$(mvc24gd2_keyfile_optional_scalar "$file" ipv6 dns) || return 1
    [[ -z $v4_dns && -z $v6_dns ]] || return 1
    v4_dns=$(mvc24gd2_keyfile_optional_scalar "$file" ipv4 dns-search) || return 1
    v6_dns=$(mvc24gd2_keyfile_optional_scalar "$file" ipv6 dns-search) || return 1
    [[ -z $v4_dns && -z $v6_dns ]] || return 1

    wg23_parse_profile "$file" syntax || return 1
    (( ${#WG23_PEER_ENDPOINTS[@]} == 1 &&
       ${#WG23_PEER_ENDPOINTS[@]} == ${#WG23_PEER_HOSTS[@]} &&
       ${#WG23_PEER_ENDPOINTS[@]} == ${#WG23_PEER_PORTS[@]} )) || return 1

    mvc24c_read_allowed_ips "$file" || return 1
    (( ${#MVC24C_ALLOWED_IPS[@]} >= 1 )) || return 1
    for prefix in "${MVC24C_ALLOWED_IPS[@]}"; do
        [[ $prefix != *:* ]] || return 1
    done
    mvc24gd2_disjoint_ipv4_prefixes "${MVC24C_ALLOWED_IPS[@]}" || return 1

    # Numeric endpoints can be checked against AllowedIPs immediately.
    # Hostnames are checked after read-only resolution in assess_saved_profile.
    for ((ep=0; ep<${#WG23_PEER_HOSTS[@]}; ep++)); do
        host=${WG23_PEER_HOSTS[ep]}
        port=${WG23_PEER_PORTS[ep]}
        [[ $port =~ ^[0-9]+$ ]] || return 1
        if wg23_validate_ipv4 "$host"; then
            for prefix in "${MVC24C_ALLOWED_IPS[@]}"; do
                ! mvc24c_cidr_contains "$prefix" "$host" || return 1
            done
        else
            wg23_validate_hostname "$host" || return 1
        fi
    done

    MVC24GD2_KEYFILE=$file
    MVC24GD2_IFACE=$iface
    MVC24GD2_ENDPOINTS=("${WG23_PEER_ENDPOINTS[@]}")
    MVC24GD2_ENDPOINT_HOSTS=("${WG23_PEER_HOSTS[@]}")
    MVC24GD2_ENDPOINT_PORTS=("${WG23_PEER_PORTS[@]}")
    MVC24GD2_ALLOWED_IPS=("${MVC24C_ALLOWED_IPS[@]}")
    MVC24GD2_PEER_COUNT=${#MVC24GD2_ENDPOINTS[@]}
    MVC24GD2_ALLOWED_COUNT=${#MVC24GD2_ALLOWED_IPS[@]}
    MVC24GD2_STAGE=keyfile-eligible-hostname-or-numeric-ipv4-private-only
}

# Live, read-only route/NM binding. The current host is expected to be in the
# same clean state required by the C23AE OpenVPN --diagnose preflight.
mvc24gd2_assess_saved_profile() {
    (( $# == 2 )) || return 1
    local uuid=$1 underlay=$2 type route ip host port gateway= source= prefix i ep
    local -A seen_candidates=()
    local -a candidate_endpoints=()
    mvc24gd2_reset
    MVC24GD2_STAGE=source-uuid
    mvc24_valid_uuid "$uuid" || return 1
    MVC24GD2_STAGE=nm-type
    type=$(nmcli --wait 10 -g connection.type connection show uuid "$uuid" 2>/dev/null) || return 1
    [[ $type == wireguard ]] || return 1
    MVC24GD2_STAGE=keyfile-discovery
    mvc24gd2_find_saved_keyfile "$uuid" || return 1
    mvc24gd2_validate_keyfile "$MVC24GD2_KEYFILE" "$uuid" "$underlay" || return 1

    # Resolve every source endpoint read-only to prove the current clean-host
    # resolver and physical route can reach it. These candidates are diagnostic
    # only; a later protected-running stage must re-resolve through OpenVPN DNS
    # before deriving any endpoint/firewall authority.
    MVC24GD2_STAGE=endpoint-resolution
    for ((i=0; i<${#MVC24GD2_ENDPOINT_HOSTS[@]}; i++)); do
        host=${MVC24GD2_ENDPOINT_HOSTS[i]}
        port=${MVC24GD2_ENDPOINT_PORTS[i]}
        mvc24gd2_resolve_ipv4_candidates "$host" || return 1
        for ip in "${MVC24GD2_RESOLVED_IPS[@]}"; do
            for prefix in "${MVC24GD2_ALLOWED_IPS[@]}"; do
                ! mvc24c_cidr_contains "$prefix" "$ip" || return 1
            done
            if [[ -z ${seen_candidates["$ip:$port"]+x} ]]; then
                seen_candidates["$ip:$port"]=1
                candidate_endpoints+=("$ip:$port")
                (( ${#candidate_endpoints[@]} <= 64 )) || return 1
            fi
        done
    done
    (( ${#candidate_endpoints[@]} >= 1 )) || return 1

    MVC24GD2_STAGE=endpoint-routes
    for ep in "${candidate_endpoints[@]}"; do
        ip=${ep%:*}
        route=$(ip -4 route get "$ip") || return 1
        mvc24c_parse_physical_route "$ip" "$route" || return 1
        [[ $MVC24C_IFACE == "$underlay" ]] || return 1
        if [[ -z $source ]]; then
            source=$MVC24C_SOURCE gateway=$MVC24C_GATEWAY
        else
            [[ $MVC24C_SOURCE == "$source" && $MVC24C_GATEWAY == "$gateway" ]] || return 1
        fi
    done
    [[ -n $source ]] || return 1

    # Private AllowedIPs must not capture the current gateway or underlay source.
    for prefix in "${MVC24GD2_ALLOWED_IPS[@]}"; do
        [[ $gateway == - ]] || ! mvc24c_cidr_contains "$prefix" "$gateway" || return 1
        ! mvc24c_cidr_contains "$prefix" "$source" || return 1
    done

    MVC24GD2_ENDPOINT_CANDIDATES=("${candidate_endpoints[@]}")
    MVC24GD2_ENDPOINT_CANDIDATE_COUNT=${#candidate_endpoints[@]}
    MVC24GD2_UNDERLAY_GATEWAY=$gateway
    MVC24GD2_UNDERLAY_SOURCE=$source
    MVC24GD2_STAGE=eligible-direct-source-first-dual-vertical
}

mvc24gd2_authorize_activation() { return 1; }
mvc24gd2_authorize_firewall() { return 1; }
mvc24gd2_authorize_routes() { return 1; }
mvc24gd2_authorize_cleanup() { return 1; }
mvc24gd2_authorize_recovery() { return 1; }
