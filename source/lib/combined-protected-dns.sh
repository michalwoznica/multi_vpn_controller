#!/usr/bin/env bash
# UBS VPN Controller 2.4.0: protected WireGuard endpoint resolution.
# DEVELOPMENT COMPONENT ONLY: not wired to a live controller.
# Dependencies: wireguard-peers.sh, dual-session.sh, combined-routing-guard.sh,
# combined-preflight.sh, combined-lifecycle.sh, combined-kernel-backend.sh,
# combined-networkmanager-backend.sh.
# This module never mutates NM, ip routes or nftables.

ubs24d_error() { printf 'MVC protected DNS: %s\n' "$*" >&2; return 1; }

# Treat every outgoing DNS destination as untrusted. Verify the selected route
# really uses OpenVPN, and bind dig to the corresponding tunnel source IP.
# A route to the physical network, changed policy rules or ambiguous output
# must fail, not silently fall back to system DNS.
ubs24d_tunnel_source_for() {
    (( $# == 1 )) || return 1
    local target=$1 output line tok i dev='' src='' seen_dev=0 seen_src=0
    local -a tokens=() lines=()
    wg23_validate_ipv4 "$target" || return 1
    output=$(ip -4 route get "$target") || return 1
    [[ -n "$output" && "$output" != *$'\r'* ]] || return 1
    mapfile -t lines <<< "$output"
    (( ${#lines[@]} == 1 || ${#lines[@]} == 2 )) || return 1
    if (( ${#lines[@]} == 2 )); then
        [[ ${lines[1]} =~ ^[[:blank:]]*cache[[:blank:]]*$ ]] || return 1
    fi
    read -r -a tokens <<< "${lines[0]}"
    [[ "${tokens[0]:-}" == "$target" ]] || return 1
    for ((i=1; i<${#tokens[@]}; i++)); do
        tok=${tokens[i]}
        case "$tok" in
            dev|src|via|uid|tos)
                (( i+1 < ${#tokens[@]} )) || return 1
                case "$tok" in
                    dev) (( ++seen_dev == 1 )) || return 1; dev=${tokens[i+1]} ;;
                    src) (( ++seen_src == 1 )) || return 1; src=${tokens[i+1]} ;;
                esac
                ((i+=1)) ;;
            table|mark|nexthop|encap|onlink|cache|unreachable|blackhole|prohibit)
                return 1 ;;
            *) return 1 ;;
        esac
    done
    [[ "$dev" == tun-vpnks && $seen_dev == 1 && $seen_src == 1 ]] || return 1
    wg23_validate_ipv4 "$src" || return 1
    UBS24D_TUN_SOURCE=$src
}

# All queries are issued to explicit *numeric* DNS server addresses. The
# nameserver hostname is NEVER passed to dig as @hostname; doing so might
# trigger a resolver query through the physical network.
# Query modes: recursive lookup via active OpenVPN's resolver, or
# non-recursive lookup on the authoritative nameserver over OpenVPN.
ubs24d_query() {
    (( $# == 4 )) || return 1
    local server=$1 name=$2 type=$3 mode=$4 response
    wg23_validate_ipv4 "$server" && wg23_validate_hostname "${name%.}" || return 1
    [[ "$type" == SOA || "$type" == NS || "$type" == A ]] || return 1
    [[ "$mode" == recursive || "$mode" == authoritative ]] || return 1
    ubs24d_verify_protection || return 1
    ubs24d_tunnel_source_for "$server" || {
        ubs24d_error 'DNS server would not be reached over the OpenVPN tunnel.'; return 1;
    }
    local -a opts=(+time=3 +tries=1 +noall +answer +comments)
    if [[ "$mode" == authoritative ]]; then opts+=(+norecurse); else opts+=(+recurse); fi
    response=$(LC_ALL=C dig -4 -b "$UBS24D_TUN_SOURCE" "@$server" "$name" "$type" "${opts[@]}") || return 1
    [[ "$response" == *'status: NOERROR'* && "$response" != *$'\r'* ]] || return 1
    if [[ "$mode" == authoritative ]]; then
        # An answer from a recursive cache does not prove freshness.
        awk '/^;; flags:/ {for(i=1;i<=NF;i++) if ($i == "aa" || $i == "aa;") found=1}
             END {exit !found}' <<< "$response" || return 1
    fi
    UBS24D_ANSWER=$response
    # Evidence of the LAST successful query only. These are observations, not
    # authenticated DNSSEC material or proof of physical packet egress.
    UBS24D_LAST_QUERY_SERVER=$server
    UBS24D_LAST_QUERY_SOURCE=$UBS24D_TUN_SOURCE
    UBS24D_LAST_QUERY_NAME=${name,,}
    UBS24D_LAST_QUERY_MODE=$mode
}

# Take a matching answer from the DNS ANSWER SECTION only; bounded to one
# record. Do not interpret additional-section or authority-section material.
ubs24d_answer_value() {
    (( $# == 3 )) || return 1
    local reply=$1 qname=${2%.} rrtype=$3
    awk -v q="${qname,,}." -v rr="$rrtype" '
        /^;; ANSWER SECTION:/ {inside=1; next}
        /^;; [A-Z][A-Z ]*SECTION:/ && inside {inside=0}
        inside && NF>=5 && tolower($1)==q && $4==rr {print $5; exit}
    ' <<< "$reply"
}

# The only recursive DNS server used for discovery comes from the ACTIVE
# OpenVPN tunnel's NM IP4.DNS metadata. No hardcoded external resolver.
ubs24d_get_vpn_resolver() {
    local list line
    list=$(nmcli -g IP4.DNS device show tun-vpnks) || return 1
    UBS24D_VPN_RESOLVER='' UBS24D_VPN_DNS=()
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        wg23_validate_ipv4 "$line" || {
            ubs24d_error 'Non-IPv4 or malformed OpenVPN resolver.'; return 1;
        }
        UBS24D_VPN_DNS+=("$line")
        if [[ -z "$UBS24D_VPN_RESOLVER" ]]; then UBS24D_VPN_RESOLVER=$line; fi
    done <<< "$list"
    [[ -n "$UBS24D_VPN_RESOLVER" ]] ||
        ubs24d_error 'OpenVPN did not provide an IPv4 DNS resolver.'
}

ubs24d_verify_protection() {
    ubs24l_read_state "$UBS24D_STATE" && [[ "$UBS24L_STAGE" == ovpn_active ]] || return 1
    ubs24n_is_active "$UBS24L_OVPN_UUID" || return 1
    ubs24b_prepare_openvpn "$UBS24L_IFACE" "$UBS24L_OVPN_PROTO" "$UBS24L_OVPN_ENDPOINT" || return 1
    ubs24k_use_table
    ubs24b_verify_guard openvpn && ubs24k_verify_openvpn_route "$UBS24D_STATE"
}

ubs24d_resolve_name() {
    (( $# == 1 )) || return 1
    local current=${1,,} zone ns_host ns_ip response answer cname hop
    wg23_validate_hostname "$current" || return 1
    for ((hop=0; hop<8; hop++)); do
        zone=$current
        # Ascend zone labels until the recursive OpenVPN resolver identifies
        # the exact zone's SOA. Do not use implicit system DNS during discovery.
        while [[ "$zone" == *.* ]]; do
            ubs24d_query "$UBS24D_VPN_RESOLVER" "$zone" SOA recursive || return 1
            response=$UBS24D_ANSWER
            answer=$(ubs24d_answer_value "$response" "$zone" SOA) || return 1
            [[ -z "$answer" ]] || break
            zone=${zone#*.}
        done
        [[ "$zone" == *.* ]] || return 1
        ubs24d_query "$UBS24D_VPN_RESOLVER" "$zone" NS recursive || return 1
        ns_host=$(ubs24d_answer_value "$UBS24D_ANSWER" "$zone" NS) || return 1
        ns_host=${ns_host%.}
        wg23_validate_hostname "$ns_host" || return 1
        ubs24d_query "$UBS24D_VPN_RESOLVER" "$ns_host" A recursive || return 1
        ns_ip=$(ubs24d_answer_value "$UBS24D_ANSWER" "$ns_host" A) || return 1
        wg23_validate_ipv4 "$ns_ip" || return 1
        ubs24d_query "$ns_ip" "$current" A authoritative || return 1
        response=$UBS24D_ANSWER
        answer=$(ubs24d_answer_value "$response" "$current" A) || return 1
        if [[ -n "$answer" ]]; then
            wg23_validate_ipv4 "$answer" || return 1
            UBS24D_RESOLVED_IP=$answer
            UBS24D_RESOLVED_AUTH_SERVER=$UBS24D_LAST_QUERY_SERVER
            UBS24D_RESOLVED_TUN_SOURCE=$UBS24D_LAST_QUERY_SOURCE
            UBS24D_RESOLVED_ANSWER_NAME=$current
            UBS24D_RESOLVED_ANSWER_SHA=$(printf '%s' "$response" | sha256sum)
            UBS24D_RESOLVED_ANSWER_SHA=${UBS24D_RESOLVED_ANSWER_SHA%% *}
            return 0
        fi
        cname=$(ubs24d_answer_value "$response" "$current" CNAME) || return 1
        current=${cname%.}
        wg23_validate_hostname "$current" || return 1
        current=${current,,}
    done
    ubs24d_error 'DNS alias chain exceeds eight hops.'
}

# Resolve all original WG peers in original section order, then verify that
# AllowedIPs cannot capture the VPN transports. The caller receives endpoint
# strings for pinned NM profile rendering, with no partially exposed result.
# Arguments: state_file original_WG_keyfile
ubs24d_resolve_wireguard() {
    (( $# == 2 )) || return 1
    local state=$1 source=$2 raw ep index host ip ovpn_ip
    local -a ordered=() wg_ips=() observations=()
    UBS24D_PINNED_PEERS=() UBS24D_PEER_OBSERVATIONS=()
    UBS24D_STATE=$state
    [[ -f "$source" && ! -L "$source" && -r "$source" ]] || return 1
    ubs24d_verify_protection || return 1
    ubs24d_get_vpn_resolver || return 1
    local server
    for server in "${UBS24D_VPN_DNS[@]}"; do
        ubs24d_tunnel_source_for "$server" || return 1
    done
    raw=$(wg23_read_peer_endpoints "$source") || return 1
    [[ -n "$raw" ]] || return 1
    while IFS=$'\t' read -r index ep; do
        wg23_split_endpoint "$ep" || return 1
        host=$WG23_PARSED_HOST
        if wg23_validate_ipv4 "$host"; then
            ip=$host
            observations+=("literal"$'\t'"-"$'\t'"-"$'\t'"-"$'\t'"-")
        else
            ubs24d_resolve_name "$host" || return 1
            ip=$UBS24D_RESOLVED_IP
            observations+=("observed-A"$'\t'"$UBS24D_RESOLVED_AUTH_SERVER"$'\t'"$UBS24D_RESOLVED_TUN_SOURCE"$'\t'"$UBS24D_RESOLVED_ANSWER_NAME"$'\t'"$UBS24D_RESOLVED_ANSWER_SHA")
        fi
        ordered+=("$ip:$WG23_PARSED_PORT")
        wg_ips+=("$ip")
    done <<< "$raw"
    (( ${#ordered[@]} >= 1 && ${#ordered[@]} <= 64 )) || return 1
    ubs24d_verify_protection || return 1
    ubs24c_read_allowed_ips "$source" || return 1
    ovpn_ip=${UBS24L_OVPN_ENDPOINT%:*}
    # WG AllowedIPs may not hijack the active OpenVPN DNS servers after WG
    # comes up, or DNS for ordinary internet could stop using OpenVPN.
    ubs24c_check_allowed_routes "$UBS24L_GATEWAY" "$ovpn_ip" "${wg_ips[@]}" "${UBS24D_VPN_DNS[@]}" || return 1
    # Preserve the endpoint for EVERY source peer, in source order, even if
    # multiple peers share the same destination. The durable lifecycle state
    # derives the unique nftables/route allowlist separately on read.
    UBS24D_PINNED_PEERS=("${ordered[@]}")
    UBS24D_PEER_OBSERVATIONS=("${observations[@]}")
}
