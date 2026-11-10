#!/usr/bin/env bash
# Multi VPN Controller, IPv4 multi-peer parser (derived from v2.3.0): WireGuard multi-peer IPv4 endpoint parser.
# Source this file from Bash. No root or network operations until functions are called.
# No modification to the NetworkManager keyfile, nftables or VPN state.

wg23_error() {
    printf 'WireGuard peer validation: %s\n' "$*" >&2
    return 1
}

wg23_validate_ipv4() {
    local address=$1 octet
    local -a octets
    [[ "$address" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS=. read -r -a octets <<< "$address"
    (( ${#octets[@]} == 4 )) || return 1
    for octet in "${octets[@]}"; do
        # Avoid alternate representations that can be interpreted inconsistently.
        [[ "$octet" == 0 || "$octet" != 0* ]] || return 1
        (( 10#$octet <= 255 )) || return 1
    done
}

wg23_validate_hostname() {
    local hostname=$1 label
    local -a labels
    [[ ${#hostname} -le 253 && "$hostname" == *.* ]] || return 1
    [[ "$hostname" =~ ^[A-Za-z0-9.-]+$ ]] || return 1
    [[ "$hostname" != *..* && "$hostname" != .* && "$hostname" != *. ]] || return 1
    IFS=. read -r -a labels <<< "$hostname"
    (( ${#labels[@]} >= 2 )) || return 1
    for label in "${labels[@]}"; do
        (( ${#label} >= 1 && ${#label} <= 63 )) || return 1
        [[ "$label" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || return 1
    done
}

wg23_split_endpoint() {
    local endpoint=$1 port host
    # IPv6 transport is deliberately deferred to v2.5.0.
    [[ "$endpoint" == *:* && "$endpoint" != *'['* && "$endpoint" != *']'* ]] ||
        { wg23_error 'Endpoint must be hostname-or-IPv4:UDP-port (no IPv6 transport yet).'; return 1; }
    host=${endpoint%:*}
    port=${endpoint##*:}
    [[ "$host" != *:* && -n "$host" ]] || { wg23_error 'Unsupported endpoint address family.'; return 1; }
    [[ "$port" =~ ^[0-9]{1,5}$ ]] || { wg23_error 'Invalid endpoint UDP port.'; return 1; }
    (( 10#$port >= 1 && 10#$port <= 65535 )) || { wg23_error 'Endpoint UDP port outside 1-65535.'; return 1; }
    if [[ "$host" =~ ^[0-9.]+$ ]]; then
        wg23_validate_ipv4 "$host" || { wg23_error 'Malformed numeric IPv4 endpoint.'; return 1; }
    else
        wg23_validate_hostname "$host" || { wg23_error 'Unsupported DNS endpoint hostname.'; return 1; }
    fi
    WG23_PARSED_HOST=$host
    WG23_PARSED_PORT=$((10#$port))
}

# Returns the IPv4 address in WG23_RESOLVED_IP. Follow bounded CNAME chains.
# Query the current name's authoritative server rather than a cached A answer.
# This retains the v2.2.0 DNS strategy and its limitations.
wg23_resolve_hostname() {
    local current=${1,,} zone soa ns response answer alias hop
    for ((hop=0; hop<8; hop++)); do
        zone=$current
        while [[ "$zone" == *.* ]]; do
            soa=$(dig +time=3 +tries=1 "$zone" SOA +noall +answer) ||
                { wg23_error 'SOA lookup failed.'; return 1; }
            if awk -v name="${zone}." '
                tolower($1) == tolower(name) && $4 == "SOA" { found=1 }
                END { exit !found }
            ' <<< "$soa"; then
                break
            fi
            zone=${zone#*.}
        done
        [[ "$zone" == *.* ]] || { wg23_error 'No authoritative DNS zone found.'; return 1; }
        ns=$(dig +time=3 +tries=1 +short NS "$zone" | sed -n '1p') ||
            { wg23_error 'NS lookup failed.'; return 1; }
        [[ -n "$ns" ]] || { wg23_error 'No authoritative nameserver found.'; return 1; }
        response=$(dig +time=3 +tries=1 "@$ns" "$current" A +norecurse +noall +answer +comments) ||
            { wg23_error 'Authoritative A lookup failed.'; return 1; }
        awk '/^;; flags:/ {for(i=1;i<=NF;i++) if ($i == "aa" || $i == "aa;") found=1}
             END {exit !found}' <<< "$response" ||
            { wg23_error 'DNS response is not authoritative.'; return 1; }
        answer=$(awk -v name="${current}." '
            tolower($1) == tolower(name) && $4 == "A" {print $5; exit}
        ' <<< "$response")
        if [[ -n "$answer" ]]; then
            wg23_validate_ipv4 "$answer" || { wg23_error 'Invalid A record IPv4 address.'; return 1; }
            WG23_RESOLVED_IP=$answer
            return 0
        fi
        alias=$(awk -v name="${current}." '
            tolower($1) == tolower(name) && $4 == "CNAME" {print $5; exit}
        ' <<< "$response")
        [[ -n "$alias" ]] || { wg23_error 'No authoritative A record or CNAME.'; return 1; }
        current=${alias%.}
        wg23_validate_hostname "$current" || { wg23_error 'Invalid CNAME target.'; return 1; }
        current=${current,,}
    done
    wg23_error 'CNAME chain exceeds eight hops.'
}

# Parse all peer sections in a saved NetworkManager keyfile. Secrets are
# neither extracted nor printed. AWK buffers results until structural checks
# pass, avoiding partial success when a later peer is malformed.
wg23_read_peer_endpoints() {
    local source=$1
    [[ -r "$source" && -f "$source" ]] || { wg23_error 'Keyfile not readable.'; return 1; }
    awk '
        /^\[/ {
            in_peer=0
            if ($0 ~ /^\[wireguard-peer\./) {
                if ($0 !~ /^\[wireguard-peer\.[^]]+\]$/) bad=1
                if (seen[$0]++) bad=1
                if (++count > 64) bad=1
                in_peer=1
            }
            next
        }
        in_peer && /^endpoint=/ {
            if (++has_endpoint[count] != 1) bad=1
            value[count]=substr($0,10)
        }
        END {
            if (count < 1 || bad) exit 1
            for (i=1; i<=count; i++) {
                if (has_endpoint[i] != 1 || value[i] == "") exit 1
            }
            for (i=1; i<=count; i++) printf "%d\t%s\n", i, value[i]
        }
    ' "$source" || { wg23_error 'Invalid peer sections: missing/duplicate endpoints, duplicate peers or >64 peers.'; return 1; }
}

# Populate arrays indexed by peer order. The temporary keyfile generator will
# later use these positions to update only each matching endpoint= property.
# Mode: resolve (default) or syntax (no network/DNS). In syntax mode, hostname
# entries have an empty WG23_PEER_IPS element; numeric IPv4s are populated.
wg23_parse_profile() {
    local source=$1 mode=${2:-resolve} records index endpoint ip
    # Use staging arrays; do not expose a partial allowlist on a late error.
    local -a parsed_endpoints=() parsed_hosts=() parsed_ports=() parsed_ips=()
    [[ "$mode" == resolve || "$mode" == syntax ]] || { wg23_error 'Unknown parse mode.'; return 1; }
    WG23_PEER_ENDPOINTS=()
    WG23_PEER_HOSTS=()
    WG23_PEER_PORTS=()
    WG23_PEER_IPS=()
    records=$(wg23_read_peer_endpoints "$source") || return 1
    [[ -n "$records" ]] || { wg23_error 'No peers found.'; return 1; }
    while IFS=$'\t' read -r index endpoint; do
        wg23_split_endpoint "$endpoint" || return 1
        ip=''
        if wg23_validate_ipv4 "$WG23_PARSED_HOST"; then
            ip=$WG23_PARSED_HOST
        elif [[ "$mode" == resolve ]]; then
            wg23_resolve_hostname "$WG23_PARSED_HOST" || return 1
            ip=$WG23_RESOLVED_IP
        fi
        parsed_endpoints+=("$endpoint")
        parsed_hosts+=("$WG23_PARSED_HOST")
        parsed_ports+=("$WG23_PARSED_PORT")
        parsed_ips+=("$ip")
    done <<< "$records"
    (( ${#parsed_endpoints[@]} > 0 )) || { wg23_error 'No peer endpoints parsed.'; return 1; }
    WG23_PEER_ENDPOINTS=("${parsed_endpoints[@]}")
    WG23_PEER_HOSTS=("${parsed_hosts[@]}")
    WG23_PEER_PORTS=("${parsed_ports[@]}")
    WG23_PEER_IPS=("${parsed_ips[@]}")
}
