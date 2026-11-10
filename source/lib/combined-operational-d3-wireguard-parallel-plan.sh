#!/usr/bin/env bash
# C23AH D3 — NON-ADMITTING plan for the first parallel WireGuard+OpenVPN stage.
#
# This file grants no host mutation authority. It only constructs and validates:
#   * one temporary WG keyfile derived from the selected saved source profile,
#     with a numeric IPv4 peer endpoint and temporary identity;
#   * one exact /32 physical-underlay endpoint route argument vector; and
#   * one prospective nft batch extending the physically-proven C23AE guard
#     with the WG transport endpoint plus profile-derived AllowedIPs.
#
# The design is deliberately parallel, NOT WG-over-OpenVPN:
#   - WG UDP transport is pinned to the physical underlay;
#   - profile AllowedIPs are admitted only on the WG tunnel;
#   - ordinary/default traffic remains on the already-protected OpenVPN tunnel;
#   - FORWARD/bridge remain default-drop for this first host-only vertical.
#
# Requires: dual-session.sh, wireguard-peers.sh, combined-preflight.sh,
# combined-networkmanager-backend.sh, combined-operational-d2-...-readonly.sh.

mvc24gd3_reset() {
    UBS24GD3_STAGE=unverified
    UBS24GD3_TEMP_NAME=vpnks-wg
    UBS24GD3_TEMP_UUID=
    UBS24GD3_WG_SOURCE=
    UBS24GD3_WG_SOURCE_IP=
    UBS24GD3_ENDPOINT_IP=
    UBS24GD3_ENDPOINT_PORT=
    UBS24GD3_UNDERLAY=
    UBS24GD3_UNDERLAY_SOURCE=
    UBS24GD3_UNDERLAY_GATEWAY=
    UBS24GD3_ROUTE_ADD_ARGS=()
    UBS24GD3_ROUTE_DEL_ARGS=()
}

mvc24gd3_valid_temp_ifname() {
    (( $# == 1 )) || return 1
    local iface=$1
    [[ $iface =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}$ &&
       $iface != lo && $iface != tun-vpnks ]]
}

# First dual vertical intentionally accepts exactly one IPv4 local address.
# This matches a common single-address WireGuard profile style while
# avoiding assumptions about multi-address source selection until it is needed.
mvc24gd3_keyfile_ipv4_source() {
    (( $# == 1 )) || return 1
    local file=$1 raw addr cidr count=0
    [[ -f $file && ! -L $file && -r $file ]] || return 1
    raw=$(awk '
      /^\[/ { in4=($0=="[ipv4]"); next }
      in4 && /^address[0-9]+=/ { print substr($0,index($0,"=")+1) }
    ' "$file") || return 1
    [[ -n $raw ]] || return 1
    while IFS= read -r addr; do
        [[ -n $addr ]] || continue
        ((++count == 1)) || return 1
        # NM keyfile addressN may carry an optional gateway after a comma.
        cidr=${addr%%,*}
        [[ $cidr == */* ]] || return 1
        UBS24GD3_WG_SOURCE_IP=${cidr%/*}
        wg23_validate_ipv4 "$UBS24GD3_WG_SOURCE_IP" || return 1
        # The local address itself need not be the network address, so validate
        # the prefix independently instead of using the canonical-subnet parser.
        local prefix=${cidr##*/}
        [[ $prefix =~ ^(0|[1-9][0-9]?)$ ]] && (( prefix <= 32 )) || return 1
    done <<< "$raw"
    (( count == 1 ))
}

mvc24gd3_private_ipv4_prefix() {
    (( $# == 1 )) || return 1
    local prefix=$1 network plen
    [[ $prefix != *:* ]] && mvc24c_parse_cidr "$prefix" || return 1
    network=$((UBS24C_CIDR_NET))
    plen=$UBS24C_CIDR_PREFIX
    if (( plen >= 8 )); then
        mvc24c_cidr_contains 10.0.0.0/8 "${prefix%/*}" && return 0
    fi
    if (( plen >= 12 )); then
        mvc24c_cidr_contains 172.16.0.0/12 "${prefix%/*}" && return 0
    fi
    if (( plen >= 16 )); then
        mvc24c_cidr_contains 192.168.0.0/16 "${prefix%/*}" && return 0
    fi
    return 1
}

mvc24gd3_endpoint_not_captured() {
    (( $# >= 2 )) || return 1
    local endpoint=$1 prefix
    shift
    wg23_validate_ipv4 "$endpoint" || return 1
    for prefix in "$@"; do
        [[ $prefix != *:* ]] && ! mvc24c_cidr_contains "$prefix" "$endpoint" || return 1
    done
}

# Build argv only; do not execute ip. The future live gate may invoke this
# vector exactly once after publishing an immutable intent.
mvc24gd3_prepare_endpoint_route() {
    (( $# == 4 )) || return 1
    local endpoint=$1 underlay=$2 gateway=$3 source=$4
    wg23_validate_ipv4 "$endpoint" && wg23_validate_ipv4 "$source" || return 1
    [[ $underlay =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}$ &&
       $underlay != lo && $underlay != tun-vpnks && $underlay != vpnks-wg ]] || return 1
    [[ $gateway == - ]] || wg23_validate_ipv4 "$gateway" || return 1
    [[ $endpoint != "$source" && ( $gateway == - || $endpoint != "$gateway" ) ]] || return 1
    UBS24GD3_ENDPOINT_IP=$endpoint
    UBS24GD3_UNDERLAY=$underlay
    UBS24GD3_UNDERLAY_SOURCE=$source
    UBS24GD3_UNDERLAY_GATEWAY=$gateway
    if [[ $gateway == - ]]; then
        UBS24GD3_ROUTE_ADD_ARGS=(-4 route add "$endpoint/32" dev "$underlay" src "$source")
    else
        UBS24GD3_ROUTE_ADD_ARGS=(-4 route add "$endpoint/32" via "$gateway" dev "$underlay" src "$source")
    fi
    UBS24GD3_ROUTE_DEL_ARGS=(-4 route del "$endpoint/32" dev "$underlay")
    UBS24GD3_STAGE=endpoint-route-plan-ready-no-authority
}

# Copy source keyfile verbatim except the temporary connection identity,
# interface name/autoconnect, and the single peer endpoint. No secret value is
# parsed, printed, or copied outside the caller-provided root-only output file.
mvc24gd3_write_pinned_profile() {
    (( $# == 8 )) || return 1
    local source=$1 source_uuid=$2 underlay=$3 endpoint_ip=$4 endpoint_port=$5
    local temp_name=$6 temp_uuid=$7 out=$8 source_port
    mvc24gd2_validate_keyfile "$source" "$source_uuid" "$underlay" || return 1
    (( ${#UBS24GD2_ENDPOINT_PORTS[@]} == 1 )) || return 1
    source_port=${UBS24GD2_ENDPOINT_PORTS[0]}
    wg23_validate_ipv4 "$endpoint_ip" || return 1
    [[ $endpoint_port =~ ^[0-9]+$ && $endpoint_port == "$source_port" ]] || return 1
    mvc24gd3_valid_temp_ifname "$temp_name" || return 1
    mvc24_valid_uuid "$temp_uuid" || return 1
    [[ -f $out && ! -L $out && -O $out && ! -s $out &&
       $(stat -c '%a:%h' -- "$out") == 600:1 ]] || return 1
    mvc24gd3_endpoint_not_captured "$endpoint_ip" "${UBS24GD2_ALLOWED_IPS[@]}" || return 1

    awk -v name="$temp_name" -v uuid="$temp_uuid" -v endpoint="$endpoint_ip:$endpoint_port" '
      function finish_connection() {
        if (section=="[connection]") {
          if (!seen_if) print "interface-name=" name
          if (!seen_auto) print "autoconnect=false"
        }
      }
      /^\[/ {
        finish_connection()
        section=$0
        if (section ~ /^\[wireguard-peer\.[^]]+\]$/) peers++
        print
        next
      }
      section=="[connection]" && /^id=/ { print "id=" name; ids++; next }
      section=="[connection]" && /^uuid=/ { print "uuid=" uuid; uuids++; next }
      section=="[connection]" && /^interface-name=/ { print "interface-name=" name; seen_if=1; next }
      section=="[connection]" && /^autoconnect=/ { print "autoconnect=false"; seen_auto=1; next }
      section ~ /^\[wireguard-peer\.[^]]+\]$/ && /^endpoint=/ {
        print "endpoint=" endpoint; endpoints++; next
      }
      { print }
      END {
        finish_connection()
        if (ids!=1 || uuids!=1 || peers!=1 || endpoints!=1) exit 1
      }
    ' "$source" > "$out" || return 1
    chmod 600 -- "$out" || return 1
    UBS24GD3_TEMP_NAME=$temp_name
    UBS24GD3_TEMP_UUID=$temp_uuid
    UBS24GD3_WG_SOURCE=$source
    UBS24GD3_ENDPOINT_IP=$endpoint_ip
    UBS24GD3_ENDPOINT_PORT=$endpoint_port
    mvc24gd3_keyfile_ipv4_source "$out" || return 1
    UBS24GD3_STAGE=pinned-temporary-profile-plan-ready-no-authority
}

mvc24gd3_guard_parameters() {
    (( $# >= 10 )) || return 1
    local underlay=$1 underlay_source=$2 ovpn_ip=$3 ovpn_port=$4
    local ovpn_tunnel=$5 ovpn_source=$6 wg_tunnel=$7 wg_source=$8 wg_ip=$9 wg_port=${10}
    shift 10
    local prefix
    [[ $underlay =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}$ &&
       $underlay != lo && $underlay != "$ovpn_tunnel" && $underlay != "$wg_tunnel" ]] || return 1
    wg23_validate_ipv4 "$underlay_source" && wg23_validate_ipv4 "$ovpn_ip" &&
      wg23_validate_ipv4 "$ovpn_source" && wg23_validate_ipv4 "$wg_source" &&
      wg23_validate_ipv4 "$wg_ip" || return 1
    [[ $ovpn_port =~ ^[0-9]+$ && $wg_port =~ ^[0-9]+$ ]] || return 1
    (( 10#$ovpn_port >= 1 && 10#$ovpn_port <= 65535 && 10#$wg_port >= 1 && 10#$wg_port <= 65535 )) || return 1
    [[ $ovpn_tunnel == tun-vpnks ]] || return 1
    mvc24gd3_valid_temp_ifname "$wg_tunnel" && [[ $wg_tunnel != "$underlay" ]] || return 1
    (( $# >= 1 && $# <= 512 )) || return 1
    mvc24gd2_disjoint_ipv4_prefixes "$@" || return 1
    mvc24gd3_endpoint_not_captured "$ovpn_ip" "$@" || return 1
    mvc24gd3_endpoint_not_captured "$wg_ip" "$@" || return 1
    for prefix in "$@"; do
        mvc24gd3_private_ipv4_prefix "$prefix" || return 1
        ! mvc24c_cidr_contains "$prefix" "$underlay_source" || return 1
    done
}

# Prospective exact batch. OUTPUT gets: loopback, pinned OVPN transport,
# pinned WG transport, unrestricted OpenVPN tunnel egress, and WG egress only
# to the selected profile's AllowedIPs. Netdev gets ARP plus the two pinned
# physical transport endpoints. FORWARD/bridge remain untouched/default-drop.
mvc24gd3_write_parallel_guard_candidate() {
    (( $# >= 11 )) || return 1
    local underlay=$1 underlay_source=$2 ovpn_ip=$3 ovpn_port=$4
    local ovpn_tunnel=$5 ovpn_source=$6 wg_tunnel=$7 wg_source=$8 wg_ip=$9 wg_port=${10} out=${11}
    shift 11
    local prefix
    mvc24gd3_guard_parameters "$underlay" "$underlay_source" "$ovpn_ip" "$ovpn_port" \
      "$ovpn_tunnel" "$ovpn_source" "$wg_tunnel" "$wg_source" "$wg_ip" "$wg_port" "$@" || return 1
    [[ -f $out && ! -L $out && -O $out && ! -s $out &&
       $(stat -c '%a:%h' -- "$out") == 600:1 ]] || return 1
    {
      printf '%s\n' 'flush chain inet mvc_preclone_quarantine output_deny'
      printf '%s\n' 'add rule inet mvc_preclone_quarantine output_deny oifname "lo" accept'
      printf 'add rule inet mvc_preclone_quarantine output_deny oifname "%s" ip protocol udp udp sport 68 udp dport 67 accept\n' "$underlay"
      printf 'add rule inet mvc_preclone_quarantine output_deny oifname "%s" ip saddr %s ip daddr %s tcp dport %s accept\n' \
        "$underlay" "$underlay_source" "$ovpn_ip" "$ovpn_port"
      printf 'add rule inet mvc_preclone_quarantine output_deny oifname "%s" ip saddr %s ip daddr %s udp dport %s accept\n' \
        "$underlay" "$underlay_source" "$wg_ip" "$wg_port"
      printf 'add rule inet mvc_preclone_quarantine output_deny oifname "%s" ip saddr %s accept\n' \
        "$ovpn_tunnel" "$ovpn_source"
      for prefix in "$@"; do
        printf 'add rule inet mvc_preclone_quarantine output_deny oifname "%s" ip saddr %s ip daddr %s accept\n' \
          "$wg_tunnel" "$wg_source" "$prefix"
      done
      printf '%s\n' 'flush chain netdev mvc_preclone_underlay lowerdev_deny'
      printf '%s\n' 'add rule netdev mvc_preclone_underlay lowerdev_deny ether type arp accept'
      printf '%s\n' 'add rule netdev mvc_preclone_underlay lowerdev_deny ether type ip ip protocol udp udp sport 68 udp dport 67 accept'
      printf 'add rule netdev mvc_preclone_underlay lowerdev_deny ip saddr %s ip daddr %s tcp dport %s accept\n' \
        "$underlay_source" "$ovpn_ip" "$ovpn_port"
      printf 'add rule netdev mvc_preclone_underlay lowerdev_deny ip saddr %s ip daddr %s udp dport %s accept\n' \
        "$underlay_source" "$wg_ip" "$wg_port"
    } > "$out"
    UBS24GD3_STAGE=parallel-guard-plan-ready-no-authority
}

mvc24gd3_authorize_activation() { return 1; }
mvc24gd3_authorize_firewall() { return 1; }
mvc24gd3_authorize_routes() { return 1; }
mvc24gd3_authorize_profile_publish() { return 1; }
mvc24gd3_authorize_cleanup() { return 1; }
mvc24gd3_authorize_recovery() { return 1; }
mvc24gd3_authorize_disarm() { return 1; }
