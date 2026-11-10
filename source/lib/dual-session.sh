#!/usr/bin/env bash
# UBS VPN Controller v2.4.0 - Phase A (development library)
# This file does not run any NetworkManager or nftables commands.
# Load with: source lib/dual-session.sh
# Sets UBS24_COMMAND / UBS24_MODE / UBS24_PRIMARY_PROFILE / UBS24_OVPN_PROFILE.
# State helpers here are an evolving development schema, not a replacement
# for the stable v2.3.0 state format. Do NOT point them at /run/vpnks/state.

ubs24_error() { printf 'Multi VPN Controller: %s\n' "$*" >&2; return 1; }

ubs24_valid_name() {
    local name=$1
    [[ -n "$name" && ${#name} -le 255 && "$name" != -* &&
       "$name" != *$'\n'* && "$name" != *$'\r'* && "$name" != *$'\t'* &&
       "$name" != *'\'* ]] || return 1
    # Profile names must not contain ASCII control characters.
    [[ "$name" != *[$'\001'-$'\010'$'\013'$'\014'$'\016'-$'\037'$'\177']* ]]
}

ubs24_parse_command() {
    UBS24_COMMAND='' UBS24_MODE='' UBS24_PRIMARY_PROFILE='' UBS24_OVPN_PROFILE=''
    local command=${1:-}
    case "$command" in
        version|--version|list|status|disconnect)
            (( $# == 1 )) || { ubs24_error "Unexpected arguments to $command"; return 2; }
            UBS24_COMMAND=${command#--}
            return 0
            ;;
        connect)
            (( $# >= 2 && $# <= 4 )) || { ubs24_error 'Usage: connect PROFILE [--split [OPENVPN_PROFILE]]'; return 2; }
            ubs24_valid_name "$2" || { ubs24_error 'Invalid selected profile name'; return 2; }
            UBS24_COMMAND=connect
            UBS24_PRIMARY_PROFILE=$2 # Type is resolved by NetworkManager later.
            UBS24_MODE=protected
            if (( $# >= 3 )); then
                [[ "$3" == --split ]] || { ubs24_error 'Expected --split after WireGuard profile'; return 2; }
                UBS24_MODE=split
                if (( $# == 4 )); then
                    ubs24_valid_name "$4" || { ubs24_error 'Invalid OpenVPN profile name'; return 2; }
                    [[ "$4" != "$2" ]] || { ubs24_error 'Both profiles cannot be the same'; return 2; }
                    UBS24_OVPN_PROFILE=$4
                    UBS24_MODE=combined
                fi
            fi
            return 0
            ;;
        *) ubs24_error 'Unknown command'; return 2 ;;
    esac
}

# No network access. The live manager will obtain these values through
# nmcli by UUID before performing ANY firewall or routing change.
# Arguments: primary_type primary_vpn_service secondary_type secondary_vpn_service
ubs24_validate_profile_types() {
    local primary=$1 primary_service=$2 secondary=${3:-} secondary_service=${4:-}
    case "$UBS24_MODE" in
        protected)
            [[ -z "$secondary" && -z "$secondary_service" ]] || return 1
            [[ "$primary" == wireguard ]] ||
                [[ "$primary" == vpn && "$primary_service" == org.freedesktop.NetworkManager.openvpn ]]
            ;;
        split)
            [[ "$primary" == wireguard && -z "$secondary" && -z "$secondary_service" ]]
            ;;
        combined)
            [[ "$primary" == wireguard && "$secondary" == vpn &&
               "$secondary_service" == org.freedesktop.NetworkManager.openvpn ]]
            ;;
        *) return 1 ;;
    esac
}

ubs24_valid_uuid() {
    [[ "$1" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]
}
ubs24_valid_ip() {
    local ip=$1 octet
    local -a octets
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS=. read -r -a octets <<< "$ip"
    (( ${#octets[@]} == 4 )) || return 1
    for octet in "${octets[@]}"; do
        [[ "$octet" == 0 || "$octet" != 0* ]] || return 1
        (( 10#$octet <= 255 )) || return 1
    done
}
ubs24_valid_port() {
    local port=$1
    [[ "$port" =~ ^[0-9]{1,5}$ ]] || return 1
    (( 10#$port >= 1 && 10#$port <= 65535 ))
}
ubs24_valid_endpoint() {
    local pair=$1 ip port
    [[ "$pair" == *:* && "$pair" != *:*:* ]] || return 1
    ip=${pair%:*} port=${pair##*:}
    ubs24_valid_ip "$ip" && ubs24_valid_port "$port"
}

ubs24_normalize_endpoints() {
    local ep
    local -a input=("$@")
    UBS24_ENDPOINTS=()
    (( ${#input[@]} >= 1 && ${#input[@]} <= 64 )) || return 1
    for ep in "${input[@]}"; do ubs24_valid_endpoint "$ep" || return 1; done
    mapfile -t UBS24_ENDPOINTS < <(printf '%s\n' "${input[@]}" | LC_ALL=C sort -u)
    (( ${#UBS24_ENDPOINTS[@]} >= 1 && ${#UBS24_ENDPOINTS[@]} <= 64 ))
}

# Development-only dual-session metadata: no credentials and no shell eval.
# The physical-route implementation in Phase B must add route ownership and
# validate it before this schema is integrated into the live VPN manager.
# Signature: path WG_UUID OPENVPN_UUID OPENVPN_PROTO OPENVPN_IP OPENVPN_PORT WG_IP:PORT...
ubs24_write_combined_state() {
    (( $# >= 7 )) || return 1
    local path=$1 wg=$2 ovpn=$3 proto=$4 ip=$5 port=$6
    shift 6
    ubs24_valid_uuid "$wg" && ubs24_valid_uuid "$ovpn" && [[ "$wg" != "$ovpn" ]] || return 1
    [[ "$proto" == udp || "$proto" == tcp ]] || return 1
    ubs24_valid_ip "$ip" && ubs24_valid_port "$port" || return 1
    ubs24_normalize_endpoints "$@" || return 1
    [[ ! -e "$path" && ! -L "$path" ]] || return 1
    [[ -d "$(dirname -- "$path")" ]] || return 1
    local tmp
    tmp=$(mktemp "$(dirname -- "$path")/.ubs-vpn-state.XXXXXXXX") || return 1
    chmod 600 "$tmp" || { rm -f -- "$tmp"; return 1; }
    {
        printf '%s\n' 'ubs-vpn-state-v4-draft' 'mode=combined' \
            "wg_uuid=$wg" "ovpn_uuid=$ovpn" 'wg_tunnel=vpnks-wg' \
            'ovpn_tunnel=tun-vpnks' "ovpn_proto=$proto" "ovpn_endpoint=$ip:$port"
        printf 'wg_endpoint=%s\n' "${UBS24_ENDPOINTS[@]}"
    } > "$tmp" || { rm -f -- "$tmp"; return 1; }
    # Atomic publication without overwriting another writer's state file.
    ln -- "$tmp" "$path" || { rm -f -- "$tmp"; return 1; }
    rm -f -- "$tmp"
}

ubs24_read_combined_state() {
    local path=$1 row endpoint i
    local -a lines=() endpoints=() canon=()
    UBS24_STATE_WG_UUID='' UBS24_STATE_OVPN_UUID='' UBS24_STATE_OVPN_PROTO=''
    UBS24_STATE_OVPN_ENDPOINT='' UBS24_STATE_WG_ENDPOINTS=()
    [[ -f "$path" && ! -L "$path" && -r "$path" ]] || return 1
    [[ "$(stat -c %a -- "$path")" == 600 ]] || return 1
    mapfile -t lines < "$path" || return 1
    (( ${#lines[@]} >= 9 && ${#lines[@]} <= 72 )) || return 1
    [[ "${lines[0]}" == 'ubs-vpn-state-v4-draft' &&
       "${lines[1]}" == 'mode=combined' &&
       "${lines[2]}" == wg_uuid=* && "${lines[3]}" == ovpn_uuid=* &&
       "${lines[4]}" == 'wg_tunnel=vpnks-wg' &&
       "${lines[5]}" == 'ovpn_tunnel=tun-vpnks' &&
       "${lines[6]}" == ovpn_proto=* && "${lines[7]}" == ovpn_endpoint=* ]] || return 1
    local wg=${lines[2]#wg_uuid=} ovpn=${lines[3]#ovpn_uuid=}
    local proto=${lines[6]#ovpn_proto=} openvpn_ep=${lines[7]#ovpn_endpoint=}
    ubs24_valid_uuid "$wg" && ubs24_valid_uuid "$ovpn" && [[ "$wg" != "$ovpn" ]] || return 1
    [[ "$proto" == udp || "$proto" == tcp ]] && ubs24_valid_endpoint "$openvpn_ep" || return 1
    for ((i=8; i<${#lines[@]}; i++)); do
        row=${lines[i]}
        [[ "$row" == wg_endpoint=* ]] || return 1
        endpoint=${row#wg_endpoint=}
        ubs24_valid_endpoint "$endpoint" || return 1
        endpoints+=("$endpoint")
    done
    ubs24_normalize_endpoints "${endpoints[@]}" || return 1
    (( ${#UBS24_ENDPOINTS[@]} == ${#endpoints[@]} )) || return 1
    for ((i=0; i<${#endpoints[@]}; i++)); do
        [[ "${UBS24_ENDPOINTS[i]}" == "${endpoints[i]}" ]] || return 1
    done
    UBS24_STATE_WG_UUID=$wg UBS24_STATE_OVPN_UUID=$ovpn
    UBS24_STATE_OVPN_PROTO=$proto UBS24_STATE_OVPN_ENDPOINT=$openvpn_ep
    UBS24_STATE_WG_ENDPOINTS=("${endpoints[@]}")
}
