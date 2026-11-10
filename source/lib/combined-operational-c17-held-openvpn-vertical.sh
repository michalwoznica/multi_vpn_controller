#!/usr/bin/env bash
# C17: PRIVATE, DEFAULT-DENY C9 -> C13(C18 DNS precheck) -> C16 slice.
# NOT imported by any production/public tool. Bash-only, systemd-independent.
# No second attempt, no cleanup/disarm, no secrets, no user-interactive fallback.
# Source B2, C3-C9, C11, C13-C16 libraries before this file.
# The first C9 failure may leave a live restrictive C1 firewall; C13 may leave
# an uncertain commit. Do NOT automatically roll back or invoke a second run.
# Even success does NOT prove prompt-free auth, authenticated peer, unrestricted
# safe DNS, FORWARD/WG support or permission for production application traffic.

mvc24gc17_reset() {
    MVC24GC17_ATTEMPTED=no
    MVC24GC17_STAGE=unverified
    MVC24GC17_AUTHORITY=none
}
mvc24gc17_admission_witness() { return 1; }
mvc24gc17_authorize_public_activation() { return 1; }
mvc24gc17_authorize_retry() { return 1; }
mvc24gc17_authorize_disarm() { return 1; }
mvc24gc17_authorize_cleanup() { return 1; }
mvc24gc17_authorize_traffic() { return 1; }
mvc24gc17_authorize_dns_change() { return 1; }
mvc24gc17_authorize_secret_export() { return 1; }

mvc24gc17_execute_once() {
    (( $# == 2 )) || return 1
    [[ ${MVC24GC17_ATTEMPTED:-no} == no ]] || return 1
    MVC24GC17_ATTEMPTED=yes
    MVC24GC17_STAGE=refused-before-activation
    MVC24GC17_AUTHORITY=none
    local source_uuid=$1 underlay=$2

    # Intentional non-admission: a real host cannot invoke the mutation path.
    # In isolated tests this callback is replaced; it MUST NOT be overridden
    # by public CLI flags, arguments, environment values, or read-only status.
    mvc24gc17_admission_witness || return 1
    mvc24ga_uuid_valid "$source_uuid" && mvc24gb1_valid_ifname "$underlay" &&
        mvc24gb2_root_scope || return 1
    # The B2 flock is ACQUIRED BY C3 inside C9. It must not be required
    # before the cold-start sequence begins.
    [[ ${MVC24GC9_ATTEMPTED:-no} == no &&
       ${MVC24GC13_ATTEMPTED:-no} == no &&
       ! -e /run/mvc-activation && ! -L /run/mvc-activation &&
       ! -e /run/mvc-output-transition && ! -L /run/mvc-output-transition ]] || return 1

    # The same held B2 flock and process context span all three operations.
    # No controller crash or failed stage triggers a retry or firewall release.
    MVC24GC17_STAGE=bootstrap-or-activation-outcome-uncertain
    mvc24gc9_execute_once "$source_uuid" "$underlay" || return 1
    [[ ${MVC24GC9_STAGE:-} == active-nm-ipv4-observed-endpoint-only-guard &&
       ${MVC24GC9_AUTHORITY:-} == none &&
       ${MVC24GC7_STAGE:-} == active-nm-and-ipv4-observed-bootstrap-only &&
       ${MVC24GC7_AUTHORITY:-} == none ]] || return 1
    mvc24gb2_root_scope && mvc24gb2_lock_valid &&
        mvc24gc3_transition_records_valid && mvc24gc7_read_intent || return 1

    MVC24GC17_STAGE=firewall-transition-outcome-uncertain
    mvc24gc13_execute_once || return 1
    [[ ${MVC24GC13_STAGE:-} == atomic-ipv4-tunnel-output-observed-dns-unverified &&
       ${MVC24GC13_AUTHORITY:-} == none &&
       ${MVC24GC18_STAGE:-} == precommit-dns-rechecked-under-c1-no-authority &&
       ${MVC24GC18_AUTHORITY:-} == none ]] || return 1
    mvc24gb2_root_scope && mvc24gb2_lock_valid &&
        mvc24gc3_transition_records_valid && mvc24gc13_intent_valid || return 1

    MVC24GC17_STAGE=dns-observation-unverified
    mvc24gc16_observe_locked || return 1
    case ${MVC24GC16_STAGE:-} in
        direct-glibc-vpn-dns-observed-no-traffic-authority| \
        conditional-arch-nss-vpn-dns-observed-no-traffic-authority) ;;
        *) return 1 ;;
    esac
    [[ ${MVC24GC16_AUTHORITY:-} == none ]] || return 1
    mvc24gb2_root_scope && mvc24gb2_lock_valid &&
        mvc24gc3_transition_records_valid && mvc24gc13_intent_valid || return 1

    MVC24GC17_STAGE=protected-ovpn-stages-observed-no-operational-authority
    MVC24GC17_AUTHORITY=none
    return 0
}
