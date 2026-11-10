#!/usr/bin/env bash
# UBS VPN Controller v2.4.0 - Phase B (OFFLINE DEVELOPMENT LIBRARY).
# Source into tests or a future integration; no commands here change networking.
# IPv4 transport only. No eval, no arbitrary nftables input interpolation.
# Requires the companion Phase A library dual-session.sh to be sourced.

mvc24b_error() { printf 'MVC combined-guard: %s\n' "$*" >&2; return 1; }

# Canonical numeric ports avoid nftables pretty-printing/normalisation
# diverging from the state used for exact integrity comparisons.
mvc24b_canonical_endpoint() {
    mvc24_valid_endpoint "$1" && [[ "${1##*:}" != 0* ]]
}

mvc24b_valid_ifname() {
    [[ "$1" =~ ^[A-Za-z0-9_.-]{1,15}$ && "$1" != -* && "$1" != lo &&
       "$1" != vpnks-wg && "$1" != tun-vpnks ]]
}

# Use one preselected underlying physical uplink in Phase B. Phase C must
# discover the actual uplink using NetworkManager/iproute2 BEFORE OpenVPN
# activation and revalidate it after changes. Never guess an interface.
# Arguments: PHYSICAL_IFACE OVPN_PROTO OVPN_IPV4:PORT WG_IPV4:PORT...
# Prepares ONLY the OpenVPN transport. Crucially, WireGuard DNS lookups are
# not required until OpenVPN has connected behind the first kill-switch stage.
# A fresh call invalidates any previously prepared WireGuard endpoint data.
mvc24b_prepare_openvpn() {
    local iface=${1:-} proto=${2:-} ovpn=${3:-}
    UBS24B_IFACE='' UBS24B_OVPN_PROTO='' UBS24B_OVPN_PAIR=''
    UBS24B_WG_PAIRS=() UBS24B_WG_IPS=()
    (( $# == 3 )) || return 1
    mvc24b_valid_ifname "$iface" || { mvc24b_error 'Invalid physical interface.'; return 1; }
    [[ "$proto" == udp || "$proto" == tcp ]] || { mvc24b_error 'Invalid OpenVPN transport.'; return 1; }
    mvc24b_canonical_endpoint "$ovpn" || { mvc24b_error 'Invalid OpenVPN endpoint.'; return 1; }
    UBS24B_IFACE=$iface UBS24B_OVPN_PROTO=$proto
    UBS24B_OVPN_PAIR="${ovpn%:*} . ${ovpn##*:}"
}

# AFTER the OpenVPN stage is already protected, resolve and pin WireGuard
# endpoints through its tunnel, then call this function.  Failures clear all
# WireGuard endpoint data (the existing OpenVPN protection is unchanged).
mvc24b_prepare_wireguard() {
    local endpoint ip port
    local -a pairs=() ips=()
    UBS24B_WG_PAIRS=() UBS24B_WG_IPS=()
    mvc24b_require_openvpn_prepared || return 1
    (( $# >= 1 && $# <= 64 )) || { mvc24b_error 'Expected 1-64 WireGuard peer endpoints.'; return 1; }
    for endpoint in "$@"; do
        mvc24b_canonical_endpoint "$endpoint" || { mvc24b_error 'Invalid WireGuard endpoint.'; return 1; }
        ip=${endpoint%:*}; port=${endpoint##*:}
        pairs+=("$ip . $port")
        ips+=("$ip")
    done
    mapfile -t UBS24B_WG_PAIRS < <(printf '%s\n' "${pairs[@]}" | LC_ALL=C sort -u)
    mapfile -t UBS24B_WG_IPS < <(printf '%s\n' "${ips[@]}" | LC_ALL=C sort -u)
}

# Backwards-compatible convenience API for existing offline test fixtures.
# A real combined connection must use the staged preparation functions above.
mvc24b_prepare() {
    if (( $# < 4 )); then
        UBS24B_IFACE='' UBS24B_OVPN_PROTO='' UBS24B_OVPN_PAIR=''
        UBS24B_WG_PAIRS=() UBS24B_WG_IPS=()
        return 1
    fi
    mvc24b_prepare_openvpn "$1" "$2" "$3" || return 1
    shift 3
    mvc24b_prepare_wireguard "$@"
}

mvc24b_require_openvpn_prepared() {
    mvc24b_valid_ifname "${UBS24B_IFACE:-}" &&
        [[ "${UBS24B_OVPN_PROTO:-}" == udp || "${UBS24B_OVPN_PROTO:-}" == tcp ]] &&
        [[ -n "${UBS24B_OVPN_PAIR:-}" ]]
}
mvc24b_require_prepared() {
    mvc24b_require_openvpn_prepared &&
        (( ${#UBS24B_WG_PAIRS[@]} >= 1 && ${#UBS24B_WG_PAIRS[@]} <= 64 ))
}

# Proposed v2.4 guard includes the v2.3 legacy sets (for standalone VPNs)
# but combined mode keeps those legacy sets EMPTY. This prevents unbound
# IPv4 endpoint exceptions from circumventing physical-interface matching.
# The active guard is rendered from the validated runtime policy in this module.
# TRANSACTION OUTPUT ONLY. Do not run on a live firewall in Phase B.
mvc24b_render_openvpn_stage() {
    mvc24b_require_openvpn_prepared || return 1
    local ovpn_set=direct_ovpn_udp
    [[ "$UBS24B_OVPN_PROTO" == tcp ]] && ovpn_set=direct_ovpn_tcp
    cat <<'NFT'
flush set inet vpn_guard tunnel_interfaces
flush set inet vpn_guard udp_endpoints
flush set inet vpn_guard tcp_endpoints
flush set inet vpn_guard direct_wg_udp
flush set inet vpn_guard direct_ovpn_udp
flush set inet vpn_guard direct_ovpn_tcp
add element inet vpn_guard tunnel_interfaces { "tun-vpnks" }
NFT
    printf 'add element inet vpn_guard %s { "%s" . %s }\n' \
        "$ovpn_set" "$UBS24B_IFACE" "$UBS24B_OVPN_PAIR"
    cat <<'NFT'
add chain inet vpn_guard active_output { type filter hook output priority -10; policy accept; }
add rule inet vpn_guard active_output jump restricted_output
NFT
}

# Second atomic transaction. Execute ONLY once OpenVPN's firewall and
# default route are verified, WireGuard endpoints resolved via OpenVPN, and
# each /32 route installed and verified on the physical interface. Rendering
# does not activate or modify any connection or firewall.
mvc24b_render_add_wireguard_stage() {
    mvc24b_require_prepared || return 1
    local pair
    printf '%s\n' 'flush set inet vpn_guard direct_wg_udp'
    for pair in "${UBS24B_WG_PAIRS[@]}"; do
        printf 'add element inet vpn_guard direct_wg_udp { "%s" . %s }\n' \
            "$UBS24B_IFACE" "$pair"
    done
    printf '%s\n' 'add element inet vpn_guard tunnel_interfaces { "vpnks-wg" }'
}

# For an IPv4 /32 route, retain the gateway and preferred source learned
# from the physical route before connecting OpenVPN. '-' denotes on-link.
# Phase C should create routes with "ip -4 route add", never "replace", and
# refuse to overwrite pre-existing host routes. The following function merely
# returns a safe argv array. No shell expansion/eval is needed.
# Arguments: ENDPOINT_IP PHYSICAL_IFACE GATEWAY_OR_- SOURCE_IP
mvc24b_route_add_argv() {
    local dest=${1:-} iface=${2:-} via=${3:-} source=${4:-}
    UBS24B_ROUTE_ARGV=()
    mvc24_valid_ip "$dest" && mvc24b_valid_ifname "$iface" &&
        mvc24_valid_ip "$source" || return 1
    [[ "$via" == '-' ]] || mvc24_valid_ip "$via" || return 1
    UBS24B_ROUTE_ARGV=(-4 route add "$dest/32")
    [[ "$via" == '-' ]] || UBS24B_ROUTE_ARGV+=(via "$via")
    UBS24B_ROUTE_ARGV+=(dev "$iface" src "$source" proto 186 metric 4240)
}

# Validate an exact /32 route returned from "ip -4 route show exact X/32
# table main". Must be exactly one route, with our dedicated protocol and
# metric. Reject linkdown, multipath, replaced gateways and other owners.
# Arguments: destination, iface, gateway_or_-, source_ip, route_output
mvc24b_route_show_matches() {
    local dest=${1:-} iface=${2:-} via=${3:-} source=${4:-} output=${5:-}
    local -a parts=()
    local token i found_dev='' found_via='-' found_src='' found_proto='' found_metric=''
    mvc24b_route_add_argv "$dest" "$iface" "$via" "$source" || return 1
    [[ -n "$output" && "$output" != *$'\n'* && "$output" != *$'\r'* ]] || return 1
    read -r -a parts <<< "$output"
    [[ ${parts[0]:-} == "$dest" || ${parts[0]:-} == "$dest/32" ]] || return 1
    for ((i=1;i<${#parts[@]};i++)); do
        token=${parts[i]}
        case "$token" in
            via|dev|src|proto|metric)
                (( i+1 < ${#parts[@]} )) || return 1
                case "$token" in
                    via)    [[ "$found_via" == '-' ]] || return 1; found_via=${parts[++i]} ;;
                    dev)    [[ -z "$found_dev" ]] || return 1; found_dev=${parts[++i]} ;;
                    src)    [[ -z "$found_src" ]] || return 1; found_src=${parts[++i]} ;;
                    proto)  [[ -z "$found_proto" ]] || return 1; found_proto=${parts[++i]} ;;
                    metric) [[ -z "$found_metric" ]] || return 1; found_metric=${parts[++i]} ;;
                esac
                ;;
            scope)
                (( i+1 < ${#parts[@]} )) && [[ "${parts[i+1]}" == link ]] || return 1
                (( i+=1 )) ;;
            *) return 1 ;;
        esac
    done
    [[ "$found_dev" == "$iface" && "$found_via" == "$via" &&
       "$found_src" == "$source" && "$found_proto" == 186 &&
       "$found_metric" == 4240 ]]
}

# Check the route actually selected by the kernel with ip -4 route get X.
# This catches a /32 route silently bypassed by policy routing. The route
# get output can include "uid N" and "cache" metadata; reject ambiguous
# nexthop and multiple data lines.
# Arguments: endpoint_ip physical_iface gateway_or_- source_ip route_get_output
mvc24b_route_get_matches() {
    local dest=${1:-} iface=${2:-} via=${3:-} source=${4:-} output=${5:-}
    local -a parts=()
    local token i dev='' gateway='-' src=''
    mvc24b_route_add_argv "$dest" "$iface" "$via" "$source" || return 1
    [[ -n "$output" && "$output" != *$'\r'* ]] || return 1
    # iproute2 may print an optional indented `cache` line with trailing
    # spaces (as observed on Arch). Reject any other second/extra line.
    local -a route_lines=()
    mapfile -t route_lines <<< "$output"
    (( ${#route_lines[@]} >= 1 && ${#route_lines[@]} <= 2 )) || return 1
    if (( ${#route_lines[@]} == 2 )); then
        [[ ${route_lines[1]} =~ ^[[:blank:]]*cache[[:blank:]]*$ ]] || return 1
    fi
    read -r -a parts <<< "${route_lines[0]}"
    [[ ${parts[0]:-} == "$dest" ]] || return 1
    for ((i=1;i<${#parts[@]};i++)); do
        token=${parts[i]}
        case "$token" in
            via|dev|src)
                (( i+1 < ${#parts[@]} )) || return 1
                case "$token" in
                    via) [[ "$gateway" == '-' ]] || return 1; gateway=${parts[++i]} ;;
                    dev) [[ -z "$dev" ]] || return 1; dev=${parts[++i]} ;;
                    src) [[ -z "$src" ]] || return 1; src=${parts[++i]} ;;
                esac
                ;;
            uid|tos)
                (( i+1 < ${#parts[@]} )) || return 1
                (( i+=1 )) ;;
            table|mark)
                # Explicit routing tables/packet marks need their own
                # proof, not main-table assumptions.
                return 1 ;;
            cache) : ;;
            *) return 1 ;;
        esac
    done
    [[ "$dev" == "$iface" && "$gateway" == "$via" && "$src" == "$source" ]]
}

# Validation of user-provided AllowedIPs tokens before integration:
# only reject IPv4/IPv6 default routes here. Phase C must additionally check
# that WireGuard peer routes cannot steal either VPN transport endpoint or
# the chosen OpenVPN default route (including overlapping /1 routes).
mvc24b_reject_default_allowedips() {
    local token
    for token in "$@"; do
        [[ "$token" != '0.0.0.0/0' && "$token" != '::/0' ]] || return 1
    done
}

# INTEGRITY VERIFIER (read-only). Queries nftables output; it never changes
# the live rules. During Phase B, tests substitute a fixture `nft` executable.
# Exact checks must pass before Phase C permits a live state transition.
mvc24b_nft_chain_body() {
    local name=$1
    nft -n -s -y list chain inet "${UBS24B_TABLE:-vpn_guard}" "$name" | awk -v name="$name" '
        $1 == "chain" && $2 == name && $3 == "{" {inside=1; next}
        inside && $1 == "}" {exit}
        inside {sub(/^[[:space:]]+/, ""); sub(/[[:space:]]+$/, "");
                gsub(/[[:space:]]+/, " "); if (length($0)) print}
    '
}
mvc24b_nft_set_body() {
    local name=$1
    nft -n list set inet "${UBS24B_TABLE:-vpn_guard}" "$name" | awk -v name="$name" '
        $1 == "set" && $2 == name && $3 == "{" {inside=1; next}
        inside && $1 == "}" {exit}
        inside {sub(/^[[:space:]]+/, ""); sub(/[[:space:]]+$/, "");
                gsub(/[[:space:]]+/, " "); if (length($0)) print}
    '
}
mvc24b_nft_triples() {
    local name=$1 body flat inside part ifname ip port
    local -a items=() tuples=() sorted=()
    body=$(mvc24b_nft_set_body "$name") || return 1
    flat=$(printf '%s' "$body" | tr '\n' ' ' | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//')
    if [[ "$flat" == 'type ifname . ipv4_addr . inet_service' ]]; then
        return 0
    fi
    [[ "$flat" =~ ^type\ ifname\ \.\ ipv4_addr\ \.\ inet_service\ elements\ =\ \{\ (.*)\ \}$ ]] || return 1
    inside=${BASH_REMATCH[1]}
    IFS=, read -r -a items <<< "$inside"
    (( ${#items[@]} >= 1 && ${#items[@]} <= 64 )) || return 1
    for part in "${items[@]}"; do
        part=$(sed -E 's/^ *//; s/ *$//; s/ +/ /g' <<< "$part")
        [[ "$part" =~ ^\"([A-Za-z0-9_.-]{1,15})\"\ \.\ ([0-9.]+)\ \.\ ([0-9]+)$ ]] || return 1
        ifname=${BASH_REMATCH[1]} ip=${BASH_REMATCH[2]} port=${BASH_REMATCH[3]}
        mvc24b_valid_ifname "$ifname" && mvc24_valid_ip "$ip" && mvc24_valid_port "$port" || return 1
        tuples+=("$ifname . $ip . $port")
    done
    mapfile -t sorted < <(printf '%s\n' "${tuples[@]}" | LC_ALL=C sort -u)
    (( ${#sorted[@]} == ${#tuples[@]} )) || return 1
    printf '%s\n' "${sorted[@]}"
}
mvc24b_nft_ifaces() {
    local body flat inside part
    local -a items=() names=() sorted=()
    body=$(mvc24b_nft_set_body tunnel_interfaces) || return 1
    flat=$(printf '%s' "$body" | tr '\n' ' ' | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//')
    [[ "$flat" =~ ^type\ ifname\ elements\ =\ \{\ (.*)\ \}$ ]] || return 1
    inside=${BASH_REMATCH[1]}
    IFS=, read -r -a items <<< "$inside"
    for part in "${items[@]}"; do
        part=$(sed -E 's/^ *//; s/ *$//' <<< "$part")
        [[ "$part" =~ ^\"([A-Za-z0-9_.-]{1,15})\"$ ]] || return 1
        names+=("${BASH_REMATCH[1]}")
    done
    mapfile -t sorted < <(printf '%s\n' "${names[@]}" | LC_ALL=C sort -u)
    (( ${#sorted[@]} == ${#names[@]} )) || return 1
    printf '%s\n' "${sorted[@]}"
}

mvc24b_verify_guard() {
    local stage=$1 restricted active names set_names ifaces wg ovpn_udp ovpn_tcp expected body pair
    [[ "$stage" == openvpn || "$stage" == combined ]] || return 1
    if [[ "$stage" == openvpn ]]; then
        mvc24b_require_openvpn_prepared || return 1
    else
        mvc24b_require_prepared || return 1
    fi
    restricted=$(mvc24b_nft_chain_body restricted_output) || return 1
    [[ "$restricted" == "$(cat <<'RULES'
oifname "lo" accept
oifname @tunnel_interfaces accept
oifname . ip daddr . udp dport @direct_wg_udp accept
oifname . ip daddr . udp dport @direct_ovpn_udp accept
oifname . ip daddr . tcp dport @direct_ovpn_tcp accept
ip daddr . udp dport @udp_endpoints accept
ip daddr . tcp dport @tcp_endpoints accept
meta nfproto 2 udp sport 68 udp dport 67 accept
icmpv6 type { 133, 135, 136 } accept
counter drop
RULES
)" ]] || return 1
    active=$(mvc24b_nft_chain_body active_output) || return 1
    [[ "$active" == $'type filter hook output priority -10; policy accept;\njump restricted_output' ]] || return 1
    names=$(nft -n list table inet "${UBS24B_TABLE:-vpn_guard}" | awk '$1 == "chain" {print $2}' | LC_ALL=C sort) || return 1
    if [[ "${UBS24PI_GUARD_MODE:-}" == private_ipv4_v1 || "${UBS24PI_GUARD_MODE:-}" == private_ipv4_v2 ]]; then
        [[ "$names" == $'active_output\nprivate_wg_output\nrestricted_output' ]] || return 1
    else
        [[ -z "${UBS24PI_GUARD_MODE:-}" ]] || return 1
        [[ "$names" == $'active_output\nrestricted_output' ]] || return 1
    fi
    set_names=$(nft -n list table inet "${UBS24B_TABLE:-vpn_guard}" | awk '$1 == "set" {print $2}' | LC_ALL=C sort) || return 1
    if [[ "${UBS24PI_GUARD_MODE:-}" == private_ipv4_v1 || "${UBS24PI_GUARD_MODE:-}" == private_ipv4_v2 ]]; then
        [[ "$set_names" == $'direct_ovpn_tcp\ndirect_ovpn_udp\ndirect_wg_udp\nprivate_wg_ipv4\ntcp_endpoints\ntunnel_interfaces\nudp_endpoints' ]] || return 1
        declare -F mvc24pi_verify_private_active >/dev/null || return 1
        mvc24pi_verify_private_active || return 1
    else
        [[ "$set_names" == $'direct_ovpn_tcp\ndirect_ovpn_udp\ndirect_wg_udp\ntcp_endpoints\ntunnel_interfaces\nudp_endpoints' ]] || return 1
    fi
    # Unbound legacy exception sets MUST remain empty in combined mode.
    body=$(mvc24b_nft_set_body udp_endpoints) || return 1
    [[ "$body" == 'type ipv4_addr . inet_service' ]] || return 1
    body=$(mvc24b_nft_set_body tcp_endpoints) || return 1
    [[ "$body" == 'type ipv4_addr . inet_service' ]] || return 1
    ifaces=$(mvc24b_nft_ifaces) || return 1
    if [[ "$stage" == openvpn ]]; then
        [[ "$ifaces" == 'tun-vpnks' ]] || return 1
    else
        [[ "$ifaces" == $'tun-vpnks\nvpnks-wg' ]] || return 1
    fi
    ovpn_udp=$(mvc24b_nft_triples direct_ovpn_udp) || return 1
    ovpn_tcp=$(mvc24b_nft_triples direct_ovpn_tcp) || return 1
    pair="$UBS24B_IFACE . $UBS24B_OVPN_PAIR"
    if [[ "$UBS24B_OVPN_PROTO" == udp ]]; then
        [[ "$ovpn_udp" == "$pair" && -z "$ovpn_tcp" ]] || return 1
    else
        [[ "$ovpn_tcp" == "$pair" && -z "$ovpn_udp" ]] || return 1
    fi
    wg=$(mvc24b_nft_triples direct_wg_udp) || return 1
    if [[ "$stage" == openvpn ]]; then
        [[ -z "$wg" ]] || return 1
    else
        expected=''
        for pair in "${UBS24B_WG_PAIRS[@]}"; do
            expected+="${UBS24B_IFACE} . $pair"$'\n'
        done
        expected=${expected%$'\n'}
        [[ "$wg" == "$expected" ]]
    fi
}
