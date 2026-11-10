#!/usr/bin/env bash
# UBS VPN Controller v2.4.0 Phase C: read-only preflight helpers.
# NO kernel mutations, no profile modifications, no credentials printed.
# Source lib/dual-session.sh first.
ubs24c_error() { printf 'UBS combined preflight: %s\n' "$*" >&2; return 1; }

ubs24c_ip_number() {
    local addr=$1 a b c d
    ubs24_valid_ip "$addr" || return 1
    IFS=. read -r a b c d <<< "$addr"
    UBS24C_IP_NUMBER=$(( (10#$a << 24) | (10#$b << 16) | (10#$c << 8) | 10#$d ))
}
ubs24c_parse_cidr() {
    local cidr=$1 network prefix
    [[ "$cidr" == */* && "$cidr" != */*/* ]] || return 1
    network=${cidr%/*}; prefix=${cidr##*/}
    ubs24c_ip_number "$network" || return 1
    [[ "$prefix" =~ ^(0|[1-9][0-9]?)$ ]] || return 1
    (( prefix <= 32 )) || return 1
    UBS24C_CIDR_NET=$UBS24C_IP_NUMBER
    UBS24C_CIDR_PREFIX=$prefix
    if (( prefix == 0 )); then UBS24C_CIDR_MASK=0
    else UBS24C_CIDR_MASK=$(( (0xffffffff << (32-prefix)) & 0xffffffff ))
    fi
    (( (UBS24C_CIDR_NET & UBS24C_CIDR_MASK) == UBS24C_CIDR_NET )) || return 1
}
ubs24c_cidr_contains() {
    local subnet=$1 address=$2 network mask
    ubs24c_parse_cidr "$subnet" || return 1
    network=$UBS24C_CIDR_NET mask=$UBS24C_CIDR_MASK
    ubs24c_ip_number "$address" || return 1
    (( (UBS24C_IP_NUMBER & mask) == network ))
}

# Only inspect [wireguard-peer.X] sections. Require exactly one allowed-ips
# property per peer, and reject duplicates/blank data as an unsafe profile.
# NM keyfiles typically separate allowed-ips with semicolons; comma is also
# accepted for compatibility. Never emit private-key or preshared-key lines.
ubs24c_read_allowed_ips() {
    local source=$1 records item
    local -a tokens=()
    [[ -f "$source" && -r "$source" ]] || return 1
    records=$(awk '
        /^\[/ {
            if (peer && allowed_count != 1) bad=1
            peer=($0 ~ /^\[wireguard-peer\.[^]]+\]$/)
            if ($0 ~ /^\[wireguard-peer\./ && !peer) bad=1
            if (peer) { peers++; allowed_count=0; if (seen[$0]++) bad=1 }
            next
        }
        peer && /^allowed-ips=/ {
            allowed_count++
            if (allowed_count == 1) print substr($0,13)
        }
        END { if (peer && allowed_count != 1) bad=1; if (!peers || peers > 64 || bad) exit 1 }
    ' "$source") || { ubs24c_error 'Missing/duplicate allowed-ips or malformed peer sections.'; return 1; }
    [[ -n "$records" ]] || return 1
    # Preserve one entire record per peer: reject an empty element or an
    # unexpected separator instead of inventing a wider route policy.
    local line token
    while IFS= read -r line; do
        line=${line//;/,}
        [[ -n "$line" && "$line" != ,* && "$line" != *,,* ]] || return 1
        while [[ "$line" == *, ]]; do line=${line%,}; done
        [[ -n "$line" ]] || return 1
        local -a fields=()
        IFS=, read -r -a fields <<< "$line"
        (( ${#fields[@]} >= 1 )) || return 1
        for token in "${fields[@]}"; do
            [[ "$token" != *[[:space:]]* ]] || return 1
            if [[ "$token" == *:* ]]; then
                # IPv6 *inside* WireGuard remains possible, but no IPv6
                # default route or IPv6 internet capture in combined mode.
                [[ "$token" == */* && "$token" != */*/* ]] || return 1
                local v6prefix=${token##*/}
                [[ "$v6prefix" =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
                (( v6prefix >= 8 && v6prefix <= 128 )) || return 1
                # NetworkManager validates the IPv6 address itself when the
                # profile is loaded; never accept a broad IPv6 prefix here.
            else
                ubs24c_parse_cidr "$token" || { ubs24c_error "Invalid IPv4 AllowedIPs: $token"; return 1; }
                # Reject broad captures, including the two /1 internet halves.
                (( UBS24C_CIDR_PREFIX >= 8 )) || { ubs24c_error "Overly broad IPv4 AllowedIPs: $token"; return 1; }
            fi
            tokens+=("$token")
        done
    done <<< "$records"
    (( ${#tokens[@]} >= 1 && ${#tokens[@]} <= 512 )) || return 1
    UBS24C_ALLOWED_IPS=("${tokens[@]}")
}

# Prevent WG peer routes from capturing OpenVPN's transport, the physical
# gateway or the direct WG endpoints. Supports fully resolved numeric inputs.
# Arguments: physical_gateway or '-', OpenVPN_IP, WG_IP...
ubs24c_check_allowed_routes() {
    local gateway=${1:-} ovpn=${2:-} wg ep route
    shift "$(( $# >= 2 ? 2 : $# ))"
    ubs24_valid_ip "$ovpn" || return 1
    [[ "$gateway" == '-' ]] || ubs24_valid_ip "$gateway" || return 1
    (( $# >= 1 )) || return 1
    local -a sensitive=("$ovpn" "$@")
    [[ "$gateway" == '-' ]] || sensitive+=("$gateway")
    for ep in "${sensitive[@]}"; do ubs24_valid_ip "$ep" || return 1; done
    for route in "${UBS24C_ALLOWED_IPS[@]}"; do
        [[ "$route" != *:* ]] || continue
        for ep in "${sensitive[@]}"; do
            if ubs24c_cidr_contains "$route" "$ep"; then
                ubs24c_error "WireGuard AllowedIPs $route captures protected transport/gateway $ep"
                return 1
            fi
        done
    done
}

# Parse a simple, uncontended physical route, checking syntax rather than
# allowing a VPN/tunnel/device or ambiguous nexthop. Result is captured in
# UBS24C_IFACE, UBS24C_GATEWAY, UBS24C_SOURCE.
ubs24c_parse_physical_route() {
    local destination=${1:-} output=${2:-}
    UBS24C_IFACE='' UBS24C_GATEWAY='' UBS24C_SOURCE=''
    ubs24_valid_ip "$destination" || return 1
    [[ -n "$output" && "$output" != *$'\r'* ]] || return 1
    # iproute2 may indent its optional `cache` line and add trailing
    # whitespace. Validate the whole second line semantically, not by
    # requiring one exact byte-for-byte spelling of "\n    cache".
    # Additional lines or unrecognised trailing data must still fail closed.
    local -a lines=() words=()
    mapfile -t lines <<< "$output"
    (( ${#lines[@]} >= 1 && ${#lines[@]} <= 2 )) || return 1
    if (( ${#lines[@]} == 2 )); then
        [[ ${lines[1]} =~ ^[[:blank:]]*cache[[:blank:]]*$ ]] || return 1
    fi
    local i token via='' dev='' src=''
    read -r -a words <<< "${lines[0]}"
    [[ "${words[0]:-}" == "$destination" ]] || return 1
    for ((i=1;i<${#words[@]};i++)); do
        token=${words[i]}
        case "$token" in
            via|dev|src)
                (( i+1 < ${#words[@]} )) || return 1
                case "$token" in
                    via) [[ -z "$via" ]] || return 1; via=${words[++i]} ;;
                    dev) [[ -z "$dev" ]] || return 1; dev=${words[++i]} ;;
                    src) [[ -z "$src" ]] || return 1; src=${words[++i]} ;;
                esac ;;
            uid|table|mark|tos)
                (( i+1 < ${#words[@]} )) || return 1
                # Non-main-table lookup or marked route needs separate design.
                [[ "$token" != table && "$token" != mark ]] || return 1
                (( i++ )) ;;
            cache) : ;;
            *) return 1 ;;
        esac
    done
    ubs24_valid_ip "$src" || return 1
    [[ -z "$via" ]] || ubs24_valid_ip "$via" || return 1
    [[ "$dev" =~ ^[a-zA-Z0-9_.-]{1,15}$ ]] || return 1
    [[ "$dev" != lo && "$dev" != tun* && "$dev" != wg* && "$dev" != vpnks* ]] || return 1
    UBS24C_IFACE=$dev UBS24C_GATEWAY=${via:--} UBS24C_SOURCE=$src
}

# Require precisely the three ordinary IPv4 policy rules. iproute2 can
# separate the priority and selectors with either tabs or spaces depending
# on version/formatting; match rule semantics rather than literal spacing.
# Reject extra rules, priorities, selectors and trailing rule attributes.
ubs24c_standard_ipv4_rules() {
    (( $# == 1 )) || return 1
    local -a lines expected_priorities=(0 32766 32767) expected_tables=(local main default)
    local i
    mapfile -t lines <<< "$1"
    (( ${#lines[@]} == 3 )) || return 1
    for i in 0 1 2; do
        [[ "${lines[i]}" =~ ^[[:blank:]]*([0-9]+):[[:blank:]]+from[[:blank:]]+all[[:blank:]]+lookup[[:blank:]]+(local|main|default)[[:blank:]]*$ ]] || return 1
        [[ ${BASH_REMATCH[1]} == "${expected_priorities[i]}" &&
           ${BASH_REMATCH[2]} == "${expected_tables[i]}" ]] || return 1
    done
}

# Refuse changed uplink/gateway/source between preflight and activation.
ubs24c_route_matches_snapshot() {
    local dest=$1 output=$2 expected_dev=$3 expected_gw=$4 expected_src=$5
    ubs24c_parse_physical_route "$dest" "$output" || return 1
    [[ "$UBS24C_IFACE" == "$expected_dev" &&
       "$UBS24C_GATEWAY" == "$expected_gw" &&
       "$UBS24C_SOURCE" == "$expected_src" ]]
}
