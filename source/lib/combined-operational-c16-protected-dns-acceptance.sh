#!/usr/bin/env bash
# C16: read-only, same-boot DNS readiness evidence for the C13 host-output
# transition. Requires C3/C6/C7/C11/C13 and the inherited, already-tested
# glibc/NM DNS reader. NO writes to NetworkManager, resolv.conf, nftables or
# any VPN. No real-host entry point imports this private module.
#
# A positive result is a bounded observation, not permanent DNS isolation,
# proof that arbitrary applications avoid DoH, or permission to release traffic.

mvc24gc16_reset() {
    MVC24GC16_STAGE=unverified-dns-not-admitted
    MVC24GC16_AUTHORITY=none
}
mvc24gc16_authorize_activation() { return 1; }
mvc24gc16_authorize_traffic() { return 1; }
mvc24gc16_authorize_dns_change() { return 1; }
mvc24gc16_authorize_disarm() { return 1; }
mvc24gc16_authorize_cleanup() { return 1; }
mvc24gc16_authorize_retry() { return 1; }
mvc24gc16_authorize_secret_export() { return 1; }

# Fixed root files: callers cannot pass an alternative resolv.conf or NSS file
# and pretend it describes the physical host. Old module fixtures are *not*
# accepted here. Never use this while C13's outcome is ambiguous.
mvc24gc16_dns_capture() {
    MVC24GC16_DNS_DETAIL_STAGE=argument-check
    (( $# == 0 )) || return 1
    MVC24GC16_DNS_DETAIL_STAGE=host-dns-capture
    mvc24ag2d_capture_host_dns /etc/resolv.conf /etc/nsswitch.conf || return 1
    MVC24GC16_DNS_DETAIL_STAGE=tunnel-source-and-mode-contract
    [[ ${MVC24D_TUN_SOURCE:-} == "${MVC24GC11_TUNNEL_SOURCE:-}" &&
       ${#MVC24AG2D_SERVERS[@]} -ge 1 && ${#MVC24AG2D_SERVERS[@]} -le 3 &&
       ( ${MVC24AG2D_NSS_MODE:-} == strict-direct ||
         ${MVC24AG2D_NSS_MODE:-} == arch-conditional ) ]] || return 1
    MVC24GC16_DNS_DETAIL_STAGE=complete
}

mvc24gc16_observe_locked() {
    mvc24gc16_reset
    (( $# == 0 )) || return 1
    [[ ${MVC24GC13_STAGE:-} == atomic-ipv4-tunnel-output-observed-dns-unverified &&
       ${MVC24GC13_AUTHORITY:-} == none &&
       ${MVC24GC9_STAGE:-} == active-nm-ipv4-observed-endpoint-only-guard &&
       ${MVC24GC9_AUTHORITY:-} == none &&
       ${MVC24GC7_STAGE:-} == active-nm-and-ipv4-observed-bootstrap-only &&
       ${MVC24GC7_AUTHORITY:-} == none ]] || return 1
    [[ ${MVC24GC11_TUNNEL:-} == tun-vpnks &&
       -n ${MVC24GC11_TUNNEL_SOURCE:-} ]] || return 1
    mvc24gb2_root_scope && mvc24gb2_lock_valid &&
        mvc24gc3_transition_records_valid && mvc24gc13_intent_valid || return 1
    local nm1 nm2 route1 route2 expected_route dns1 dns2 mode
    local scratch first second result=1
    nm1=$(mvc24gc6_nm_ipv4_snapshot "$MVC24GC7_CLONE_UUID" "$MVC24GC7_NM_OWNER") || return 1
    route1=$(mvc24gc6_kernel_ipv4_snapshot "$MVC24GC3_IFACE" "$MVC24GC3_SOURCE" "$MVC24GC3_REMOTE") || return 1
    expected_route="$MVC24GC3_IFACE|$MVC24GC3_SOURCE|$MVC24GC11_TUNNEL|$MVC24GC11_TUNNEL_SOURCE"
    [[ -n $nm1 && $nm1 == "${MVC24GC6_NM_SNAPSHOT:-}" &&
       $route1 == "$expected_route" &&
       $route1 == "${MVC24GC6_ROUTE_SNAPSHOT:-}" ]] || return 1
    [[ $(stat -f -c %T /dev/shm) == tmpfs ]] || return 1
    scratch=$(umask 077; mktemp -d /dev/shm/ubs-v240-c16.XXXXXXXX) || return 1
    [[ -d $scratch && ! -L $scratch && -O $scratch &&
       $(stat -c '%a:%h' -- "$scratch") == 700:2 ]] || return 1
    first=$scratch/first.json second=$scratch/second.json
    if mvc24gc16_dns_capture; then
        dns1=$MVC24AG2D_CAPTURE
        mode=$MVC24AG2D_NSS_MODE
        if mvc24gb1_capture_nft "$first" &&
           mvc24gb1_capture_nft "$second" &&
           mvc24gc13_observe_postcommit "$first" "$second" &&
           mvc24gc16_dns_capture; then
            dns2=$MVC24AG2D_CAPTURE
            if [[ -n $dns1 && $dns1 == "$dns2" &&
                  $mode == "$MVC24AG2D_NSS_MODE" ]]; then
                nm2=$(mvc24gc6_nm_ipv4_snapshot "$MVC24GC7_CLONE_UUID" "$MVC24GC7_NM_OWNER") || nm2=''
                route2=$(mvc24gc6_kernel_ipv4_snapshot "$MVC24GC3_IFACE" "$MVC24GC3_SOURCE" "$MVC24GC3_REMOTE") || route2=''
                [[ -n $nm2 && $nm1 == "$nm2" && $route1 == "$route2" ]] &&
                    mvc24gc13_intent_valid && mvc24gb2_lock_valid &&
                    mvc24gc3_transition_records_valid && result=0
            fi
        fi
    fi
    rm -f -- "$first" "$second" || result=1
    rmdir -- "$scratch" || result=1
    if (( result == 0 )); then
        if [[ $mode == strict-direct ]]; then
            MVC24GC16_STAGE=direct-glibc-vpn-dns-observed-no-traffic-authority
        else
            MVC24GC16_STAGE=conditional-arch-nss-vpn-dns-observed-no-traffic-authority
        fi
        MVC24GC16_AUTHORITY=none
        return 0
    fi
    return 1
}
