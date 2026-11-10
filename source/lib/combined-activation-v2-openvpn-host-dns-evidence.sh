#!/usr/bin/env bash
# Multi VPN Controller 2.4.x — direct glibc host DNS evidence.
# OFFLINE / READ ONLY.  Not loaded by mvc.  This is a bounded OPTIONAL
# observation; it does NOT authorise ovpn_active, reconnect, or disarm.
#
# Supported contracts: strict hosts: files dns, or an exact Arch NSS rule
# where nss-resolve is observed unavailable on both sides of the socket proof.
# This alternative proves only a bounded observation, NOT permanent resolver
# isolation. Reject active systemd-resolved, local DNS stubs, mDNS, IPv6
# nameservers or unknown NSS modules. Browser DoH, process env,
# and private application resolvers are OUTSIDE this glibc-only observation.
# The caller must use /etc/resolv.conf and /etc/nsswitch.conf in any eventual
# live integration; configurable paths below exist only for offline fixtures.

mvc24ag2d_parse_direct_resolv() {
    MVC24AG2D_SERVERS=()
    (( $# == 1 )) || return 1
    local file=$1 line token count=0
    local -a words=() servers=()
    [[ $file == /* && -f $file && -r $file ]] || return 1
    while IFS= read -r line || [[ -n $line ]]; do
        (( ++count <= 128 )) || return 1
        (( ${#line} <= 2048 )) && [[ $line != *$'\r'* ]] || return 1
        line=${line%%#*}; line=${line%%;*}
        read -r -a words <<< "$line"
        (( ${#words[@]} )) || continue
        token=${words[0]}
        case $token in
          nameserver)
            (( ${#words[@]} == 2 && ${#servers[@]} < 3 )) || return 1
            declare -F wg23_validate_ipv4 >/dev/null || return 1
            wg23_validate_ipv4 "${words[1]}" || return 1
            [[ ${words[1]} != 0.* && ${words[1]} != 127.* &&
               ${words[1]} != 169.254.* ]] || return 1
            local other
            for other in "${servers[@]}"; do [[ $other != "${words[1]}" ]] || return 1; done
            servers+=("${words[1]}") ;;
          search|domain|options|sortlist)
            (( ${#words[@]} >= 2 )) || return 1 ;;
          *) return 1 ;;
        esac
    done < "$file"
    (( ${#servers[@]} >= 1 )) || return 1
    MVC24AG2D_SERVERS=("${servers[@]}")
}

# Read-only, init-system-neutral evidence for the Arch NSS conditional rule.
# NameHasOwner never activates the destination. This proves only a transient
# absence of a running resolved service; it does NOT prevent later activation.
mvc24ag2d_resolve_unavailable() {
    (( $# == 0 )) || return 1
    [[ ! -S /run/systemd/resolve/io.systemd.Resolve ]] || return 1
    local raw
    command -v gdbus >/dev/null 2>&1 || return 1
    raw=$(LC_ALL=C gdbus call --system --timeout 5 \
      --dest org.freedesktop.DBus --object-path /org/freedesktop/DBus \
      --method org.freedesktop.DBus.NameHasOwner org.freedesktop.resolve1 \
      2>/dev/null) || return 1
    [[ $raw == '(false,)' ]]
}

mvc24ag2d_parse_hosts_nss() {
    (( $# == 1 )) || return 1
    MVC24AG2D_NSS_MODE=''
    local file=$1 line count=0 hosts=0
    local -a words=()
    [[ $file == /* && -f $file && -r $file ]] || return 1
    while IFS= read -r line || [[ -n $line ]]; do
        (( ++count <= 256 && ${#line} <= 2048 )) || return 1
        [[ $line != *$'\r'* ]] || return 1
        line=${line%%#*}
        read -r -a words <<< "$line"
        (( ${#words[@]} )) || continue
        [[ ${words[0]} == hosts: ]] || continue
        (( ++hosts == 1 )) || return 1
        if (( ${#words[@]} == 3 )) &&
           [[ ${words[1]} == files && ${words[2]} == dns ]]; then
            MVC24AG2D_NSS_MODE=strict-direct
        elif (( ${#words[@]} == 7 )) &&
             [[ ${words[1]} == mymachines && ${words[2]} == resolve &&
                ${words[3]} == '[!UNAVAIL=return]' && ${words[4]} == files &&
                ${words[5]} == myhostname && ${words[6]} == dns ]]; then
            MVC24AG2D_NSS_MODE=arch-conditional
        else
            return 1
        fi
    done < "$file"
    (( hosts == 1 )) && [[ -n $MVC24AG2D_NSS_MODE ]]
}

# Bind both content and resolved filesystem object identity, catching symlink
# retargeting even if the replacement has identical contents.  No writes.
mvc24ag2d_file_identity() {
    MVC24AG2D_FILE_ID=''
    (( $# == 1 )) || return 1
    local file=$1 real metadata digest
    [[ $file == /* && -f $file && -r $file ]] || return 1
    real=$(realpath -e -- "$file") || return 1
    [[ $real == /* && -f $real && ! -L $real ]] || return 1
    metadata=$(stat -Lc '%d:%i:%u:%g:%a:%s:%Y' -- "$file") || return 1
    digest=$(sha256sum -- "$file") || return 1
    digest=${digest%% *}
    [[ $digest =~ ^[0-9a-f]{64}$ ]] || return 1
    MVC24AG2D_FILE_ID="$real|$metadata|$digest"
}

mvc24ag2d_capture_host_dns() {
    MVC24AG2D_CAPTURE=''
    MVC24AG2D_DETAIL_STAGE=argument-check
    (( $# == 2 )) || return 1
    local resolv=$1 nss=$2 rbefore rafter nbefore nafter server
    local -a expected=() observed=()
    MVC24AG2D_DETAIL_STAGE=dependency-check
    for server in wg23_validate_ipv4 mvc24d_get_vpn_resolver mvc24d_tunnel_source_for; do
        declare -F -- "$server" >/dev/null || return 1
    done
    MVC24AG2D_DETAIL_STAGE=resolv-identity-before
    mvc24ag2d_file_identity "$resolv" || return 1; rbefore=$MVC24AG2D_FILE_ID
    MVC24AG2D_DETAIL_STAGE=nss-identity-before
    mvc24ag2d_file_identity "$nss" || return 1; nbefore=$MVC24AG2D_FILE_ID
    MVC24AG2D_DETAIL_STAGE=nss-parse
    mvc24ag2d_parse_hosts_nss "$nss" || return 1
    local mode=$MVC24AG2D_NSS_MODE
    if [[ $mode == arch-conditional ]]; then
        MVC24AG2D_DETAIL_STAGE=resolved-unavailable-before
        mvc24ag2d_resolve_unavailable || return 1
    fi
    MVC24AG2D_DETAIL_STAGE=resolv-parse
    mvc24ag2d_parse_direct_resolv "$resolv" || return 1
    observed=("${MVC24AG2D_SERVERS[@]}")
    MVC24AG2D_DETAIL_STAGE=vpn-dns-discovery
    mvc24d_get_vpn_resolver || return 1
    expected=("${MVC24D_VPN_DNS[@]}")
    MVC24AG2D_DETAIL_STAGE=dns-count-match
    (( ${#expected[@]} >= 1 && ${#expected[@]} <= 3 &&
       ${#observed[@]} == ${#expected[@]} )) || return 1
    for ((server=0; server<${#expected[@]}; server++)); do
        MVC24AG2D_DETAIL_STAGE="dns-value-match-$((server + 1))"
        [[ ${expected[server]} == "${observed[server]}" ]] || return 1
        MVC24AG2D_DETAIL_STAGE="dns-route-verify-$((server + 1))"
        mvc24d_tunnel_source_for "${expected[server]}" || return 1
    done
    MVC24AG2D_DETAIL_STAGE=resolv-identity-after
    mvc24ag2d_file_identity "$resolv" || return 1; rafter=$MVC24AG2D_FILE_ID
    MVC24AG2D_DETAIL_STAGE=nss-identity-after
    mvc24ag2d_file_identity "$nss" || return 1; nafter=$MVC24AG2D_FILE_ID
    if [[ $mode == arch-conditional ]]; then
        MVC24AG2D_DETAIL_STAGE=resolved-unavailable-after
        mvc24ag2d_resolve_unavailable || return 1
    fi
    MVC24AG2D_DETAIL_STAGE=file-identity-stability
    [[ $rbefore == "$rafter" && $nbefore == "$nafter" ]] || return 1
    MVC24AG2D_DETAIL_STAGE=complete
    MVC24AG2D_CAPTURE="$rbefore|$nbefore|$mode|${expected[*]}"
}

mvc24ag2d_observe_host_dns_impl() {
    (( $# == 8 )) || return 1
    local session=$1 state=$2 captures=$3 proc=$4 plugin=$5 openvpn=$6 resolv=$7 nss=$8
    local before state_before owner_before manifest_before
    [[ ${MVC24S_LOCK_HELD:-} == 1 && $session == /* && $state == /* &&
       $captures == /* && $proc == /* && $plugin == /* && $openvpn == /* &&
       $resolv == /* && $nss == /* ]] || return 1
    declare -F mvc24ag2s_observe_openvpn_socket_locked >/dev/null || return 1
    # This augments, and NEVER substitutes for, the owned-socket NM/route/
    # firewall observation. Host DNS is snapshotted on BOTH sides of it.
    state_before=$(sha256sum -- "$state") || return 1
    owner_before=$(sha256sum -- "$session/ownership") || return 1
    manifest_before=$(sha256sum -- "$session/ovpn-effective.json") || return 1
    mvc24ag2d_capture_host_dns "$resolv" "$nss" || return 1
    before=$MVC24AG2D_CAPTURE
    mvc24ag2s_observe_openvpn_socket_locked "$session" "$state" "$captures" "$proc" "$plugin" "$openvpn" || return 1
    [[ ${MVC24AG2S_OBSERVED:-} == partial-openvpn-udp-socket-and-nm-route-dns-only ]] || return 1
    mvc24ag2d_capture_host_dns "$resolv" "$nss" || return 1
    [[ $MVC24AG2D_CAPTURE == "$before" ]] || return 1
    [[ $(sha256sum -- "$state") == "$state_before" &&
       $(sha256sum -- "$session/ownership") == "$owner_before" &&
       $(sha256sum -- "$session/ovpn-effective.json") == "$manifest_before" ]] || return 1
    # The conditional mode is deliberately distinguishable from the strict
    # glibc-only path and NEVER provides activation authority.
    if [[ $MVC24AG2D_NSS_MODE == arch-conditional ]]; then
        MVC24AG2D_OBSERVED=partial-conditional-arch-nss-and-openvpn-udp-socket-only
    else
        MVC24AG2D_OBSERVED=partial-direct-glibc-dns-and-openvpn-udp-socket-only
    fi
}

mvc24ag2d_observe_host_dns_files_locked() {
    MVC24AG2D_OBSERVED=''
    MVC24AG2D_CAPTURE=''
    MVC24AG2D_SERVERS=()
    MVC24AG2D_NSS_MODE=''
    if mvc24ag2d_observe_host_dns_impl "$@"; then return 0; fi
    MVC24AG2D_OBSERVED=''
    MVC24AG2D_CAPTURE=''
    MVC24AG2D_SERVERS=()
    MVC24AG2D_NSS_MODE=''
    MVC24AG2S_OBSERVED=''
    MVC24AG2P_OBSERVED=''
    MVC24AG2_OBSERVED=''
    return 1
}

# Pinned real-host entry point for eventual read-only runtime observation;
# still NOT called by mvc or any activation-authority callback.
mvc24ag2d_observe_host_dns_locked() {
    (( $# == 6 )) || return 1
    mvc24ag2d_observe_host_dns_files_locked "$@" /etc/resolv.conf /etc/nsswitch.conf
}
