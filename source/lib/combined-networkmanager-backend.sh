#!/usr/bin/env bash
# UBS VPN Controller v2.4.0 Phase C - NetworkManager profile backend.
# DEVELOPMENT COMPONENT ONLY: Never load/install on production networking.
# Source after dual-session.sh and combined-preflight.sh.
# The caller is responsible for root privileges, exclusive flock, phase-order
# verification, guarded DNS resolution, and failure-safe recovery.
# This module NEVER unhooks nftables or changes IP routes.

ubs24n_error() { printf 'MVC NetworkManager backend: %s\n' "$*" >&2; return 1; }

ubs24n_safe_path() {
    local path=${1:-}
    [[ -n "$path" && "$path" == /* && "$path" != *$'\n'* && "$path" != *$'\r'* ]]
}

# Validate sections and keys whose duplication or presence would undermine
# the expected routing or activation behaviour. Never print source secrets.
# mode: wg|ovpn
ubs24n_validate_source() {
    (( $# == 2 )) || return 1
    local mode=$1 path=$2
    [[ "$mode" == wg || "$mode" == ovpn ]] || return 1
    [[ -f "$path" && ! -L "$path" && -r "$path" ]] || return 1
    awk -v mode="$mode" '
        /\r/ { bad=1 }
        /^\[/ {
            if ($0 !~ /^\[[A-Za-z0-9_.-]+\]$/ && $0 !~ /^\[wireguard-peer\.[^]]+\]$/) bad=1
            section=$0
            if (section=="[connection]") c++
            if (section=="[vpn]") v++
            if (section=="[wireguard]") w++
            if (section ~ /^\[wireguard-peer\./) {
                if (section !~ /^\[wireguard-peer\.[^]]+\]$/ || peers++ >= 64) bad=1
                if (seenpeer[section]++) bad=1
            }
            next
        }
        section=="[connection]" {
            if ($0 ~ /^(id|uuid|type|autoconnect|interface-name|secondaries)=/) {
                split($0, kv, "="); if (seen[section SUBSEP kv[1]]++) bad=1
                if (kv[1]=="secondaries" && kv[2]!="") bad=1
                if (kv[1]=="type") typ=substr($0,6)
            }
        }
        section=="[vpn]" {
            if ($0 ~ /^(remote|dev|remote-random|proto-tcp|service-type)=/) {
                split($0, kv, "="); if (seen[section SUBSEP kv[1]]++) bad=1
                if (kv[1]=="remote") remotes++
                if (kv[1]=="service-type") service=substr($0,14)
            }
        }
        section=="[wireguard]" {
            if ($0 ~ /^(ip4-auto-default-route|ip6-auto-default-route|peer-routes|fwmark)=/) {
                split($0, kv, "="); if (seen[section SUBSEP kv[1]]++) bad=1
                if (kv[1]=="fwmark" && kv[2]!="0" && kv[2]!="") bad=1
                if (kv[1]=="peer-routes" && kv[2]!="true" && kv[2]!="yes" && kv[2]!="1") bad=1
            }
        }
        section ~ /^\[wireguard-peer\./ && /^endpoint=/ { endpoints++; if (seen[section SUBSEP "endpoint"]++) bad=1 }
        (section=="[ipv4]" || section=="[ipv6]") {
            if ($0 ~ /^(dns|dns-search|ignore-auto-dns|never-default|dns-priority|routes|gateway|route-table)=/) {
                split($0, kv, "="); if (seen[section SUBSEP kv[1]]++) bad=1
                if (mode=="wg" && (kv[1]=="routes" || kv[1]=="gateway")) bad=1
                if (mode=="wg" && kv[1]=="route-table" && kv[2]!="" && kv[2]!="0" && kv[2]!="254") bad=1
            }
        }
        (section=="[ipv4]" || section=="[ipv6]") && mode=="wg" {
            n=index($0,"="); if (n) {
                key=substr($0,1,n-1)
                if (key ~ /^route[0-9]+$/ || key ~ /^routing-rule[0-9]+$/) bad=1
            }
        }
        END {
            if (bad || c!=1 || !seen["[connection]" SUBSEP "id"] ||
                !seen["[connection]" SUBSEP "uuid"]) exit 1
            if (mode=="wg" && (typ!="wireguard" || w!=1 || v!=0 || peers<1 || endpoints!=peers)) exit 1
            if (mode=="ovpn" && (typ!="vpn" || v!=1 || w!=0 || peers!=0 || remotes!=1 || service!="org.freedesktop.NetworkManager.openvpn")) exit 1
        }
    ' "$path"
}

# Securely materialise a rendered profile without replacing any existing
# destination. The caller MUST choose a root-owned private runtime directory.
ubs24n_render_private() {
    (( $# >= 3 )) || return 1
    local mode=$1 source=$2 target=$3 temp
    shift 3
    ubs24n_safe_path "$source" && ubs24n_safe_path "$target" || return 1
    [[ "$mode" == wg || "$mode" == ovpn ]] || return 1
    [[ -d "${target%/*}" && ! -e "$target" && ! -L "$target" ]] || return 1
    ubs24n_validate_source "$mode" "$source" || { ubs24n_error 'Invalid source keyfile structure or conflicting routes.'; return 1; }
    temp=$(mktemp "${target%/*}/.ubs-nm.XXXXXXXX") || return 1
    chmod 600 "$temp" || { rm -f -- "$temp"; return 1; }
    if ! ubs24n_transform "$mode" "$source" "$@" > "$temp"; then
        rm -f -- "$temp"
        return 1
    fi
    # ln (without -f) fails if a concurrent writer created the destination.
    if ! ln -T -- "$temp" "$target"; then
        rm -f -- "$temp"
        return 1
    fi
    rm -f -- "$temp"
    [[ "$(stat -c %a -- "$target")" == 600 ]]
}

# Parameters: wg SOURCE TARGET NEW_UUID PINNED_IP:PORT...
ubs24n_make_wireguard() {
    (( $# >= 4 && $# <= 67 )) || return 1
    local source=$1 target=$2 uuid=$3 ep
    shift 3
    ubs24_valid_uuid "$uuid" || return 1
    for ep in "$@"; do ubs24_valid_endpoint "$ep" || return 1; done
    ubs24n_render_private wg "$source" "$target" "$uuid" "$@"
}

# Parameters: ovpn SOURCE TARGET NEW_UUID PINNED_IP:PORT
ubs24n_make_openvpn() {
    (( $# == 4 )) || return 1
    local source=$1 target=$2 uuid=$3 endpoint=$4
    ubs24_valid_uuid "$uuid" && ubs24_valid_endpoint "$endpoint" || return 1
    ubs24n_render_private ovpn "$source" "$target" "$uuid" "$endpoint"
}

# Internal renderer. No eval/source of keyfile data. The only allowed
# modifications are explicit profile identity, pinned endpoints, routing/DNS
# suppression for WG, and DNS precedence for OpenVPN.
ubs24n_transform() {
    local mode=$1 source=$2 uuid=$3
    shift 3
    local pins='' endpoint
    if [[ "$mode" == wg ]]; then
        for endpoint in "$@"; do pins+="$endpoint"$'\n'; done
        pins=${pins%$'\n'}
    else
        pins=$1
    fi
    awk -v mode="$mode" -v newuuid="$uuid" -v pins="$pins" '
        BEGIN {
            id=(mode=="wg" ? "vpnks-wg" : "vpnks-ovpn")
            count=split(pins,pinned,"\n")
            if (count<1 || count>64) exit 1
        }
        function emit_missing() {
            if (section=="[connection]") {
                if (!saw[section SUBSEP "autoconnect"]) print "autoconnect=false"
                if (mode=="wg" && !saw[section SUBSEP "interface-name"]) print "interface-name=vpnks-wg"
            }
            if (section=="[vpn]" && mode=="ovpn") {
                if (!saw[section SUBSEP "dev"]) print "dev=tun-vpnks"
                if (!saw[section SUBSEP "remote-random"]) print "remote-random=no"
            }
            if (section=="[wireguard]" && mode=="wg") {
                if (!saw[section SUBSEP "ip4-auto-default-route"]) print "ip4-auto-default-route=false"
                if (!saw[section SUBSEP "ip6-auto-default-route"]) print "ip6-auto-default-route=false"
                if (!saw[section SUBSEP "peer-routes"]) print "peer-routes=true"
            }
            if (section=="[ipv4]" || section=="[ipv6]") {
                if (mode=="ovpn") {
                    if (!saw[section SUBSEP "dns-priority"]) print "dns-priority=-1000"
                } else {
                    if (!saw[section SUBSEP "ignore-auto-dns"]) print "ignore-auto-dns=true"
                    if (!saw[section SUBSEP "never-default"]) print "never-default=true"
                }
            }
        }
        /^\[/ {
            emit_missing()
            section=$0
            if (section=="[ipv4]") have4=1
            if (section=="[ipv6]") have6=1
            if (section ~ /^\[wireguard-peer\./) peer++
            print
            next
        }
        {
            n=index($0,"=")
            if (!n) { print; next }
            key=substr($0,1,n-1)
            saw[section SUBSEP key]=1
            if (section=="[connection]") {
                if (key=="id") { print "id=" id; next }
                if (key=="uuid") { print "uuid=" newuuid; next }
                if (key=="autoconnect") { print "autoconnect=false"; next }
                if (key=="interface-name" && mode=="wg") { print "interface-name=vpnks-wg"; next }
            }
            if (section=="[vpn]" && mode=="ovpn") {
                if (key=="remote") { print "remote=" pins; remotes++; next }
                if (key=="dev") { print "dev=tun-vpnks"; next }
                if (key=="remote-random") { print "remote-random=no"; next }
            }
            if (section=="[wireguard]" && mode=="wg") {
                if (key=="ip4-auto-default-route" || key=="ip6-auto-default-route") { print key "=false"; next }
                if (key=="peer-routes") { print "peer-routes=true"; next }
            }
            if (section ~ /^\[wireguard-peer\./ && mode=="wg" && key=="endpoint") {
                if (++changed>count) exit 1
                print "endpoint=" pinned[changed]
                next
            }
            if (section=="[ipv4]" || section=="[ipv6]") {
                if (mode=="ovpn" && key=="dns-priority") { print "dns-priority=-1000"; next }
                if (mode=="wg") {
                    if (key=="dns" || key=="dns-search") next
                    if (key=="ignore-auto-dns") { print "ignore-auto-dns=true"; next }
                    if (key=="never-default") { print "never-default=true"; next }
                }
            }
            print
        }
        END {
            emit_missing()
            if (!have4) {
                print "[ipv4]"
                if (mode=="wg") { print "ignore-auto-dns=true"; print "never-default=true" }
                else print "dns-priority=-1000"
            }
            if (!have6) {
                print "[ipv6]"
                if (mode=="wg") { print "ignore-auto-dns=true"; print "never-default=true" }
                else print "dns-priority=-1000"
            }
            if ((mode=="wg" && changed!=count) || (mode=="ovpn" && remotes!=1)) exit 1
        }
    ' "$source"
}

# NetworkManager operations are deliberately separate from rendering so that
# the controller can prepare the guard BEFORE bringing either VPN up.
ubs24n_verify_profile() {
    (( $# == 3 )) || return 1
    local uuid=$1 expected_type=$2 expected_id=$3 actual
    ubs24_valid_uuid "$uuid" || return 1
    [[ "$expected_type" == wireguard || "$expected_type" == vpn ]] || return 1
    [[ "$expected_id" == vpnks-wg || "$expected_id" == vpnks-ovpn ]] || return 1
    [[ "$expected_type:$expected_id" == wireguard:vpnks-wg ||
       "$expected_type:$expected_id" == vpn:vpnks-ovpn ]] || return 1
    actual=$(nmcli -g connection.uuid connection show uuid "$uuid") || return 1
    [[ "$actual" == "$uuid" ]] || return 1
    actual=$(nmcli -g connection.type connection show uuid "$uuid") || return 1
    [[ "$actual" == "$expected_type" ]] || return 1
    actual=$(nmcli -g connection.id connection show uuid "$uuid") || return 1
    [[ "$actual" == "$expected_id" ]]
}

ubs24n_load_profile() {
    (( $# == 4 )) || return 1
    local file=$1 uuid=$2 type=$3 id=$4
    [[ -f "$file" && ! -L "$file" && "$(stat -c %a -- "$file")" == 600 ]] || return 1
    # Never import over a pre-existing NM connection, nor use a reserved
    # temporary name already owned by another session.
    if nmcli -g connection.uuid connection show uuid "$uuid" >/dev/null 2>&1 ||
       nmcli -g connection.uuid connection show id "$id" >/dev/null 2>&1; then
        ubs24n_error 'Temporary UUID or profile name already exists.'
        return 1
    fi
    nmcli connection load "$file" || return 1
    ubs24n_verify_profile "$uuid" "$type" "$id" ||
        ubs24n_error 'Loaded connection does not match expected UUID/type/id.'
}

ubs24n_is_active() {
    (( $# == 1 )) || return 1
    local uuid=$1 list
    ubs24_valid_uuid "$uuid" || return 1
    list=$(nmcli -e no -t -f UUID connection show --active) || return 1
    grep -Fxq -- "$uuid" <<< "$list"
}

ubs24n_activate() {
    (( $# == 2 )) || return 1
    local uuid=$1 expected_type=$2 id
    [[ "$expected_type" == wireguard || "$expected_type" == vpn ]] || return 1
    id=$([[ "$expected_type" == wireguard ]] && printf vpnks-wg || printf vpnks-ovpn)
    ubs24n_verify_profile "$uuid" "$expected_type" "$id" || return 1
    ! ubs24n_is_active "$uuid" || return 1
    # Caller MUST have previously verified the relevant active nftables guard.
    nmcli -w 60 connection up uuid "$uuid" || return 1
    ubs24n_is_active "$uuid" || ubs24n_error 'nmcli up returned success but the temporary UUID is not active.'
}
