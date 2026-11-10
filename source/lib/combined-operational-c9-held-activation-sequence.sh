#!/usr/bin/env bash
# Gate C9: PRIVATE, NON-ADMITTING C3 -> C8 -> C14 -> C7 integration sequence.
# Requires C3, C5, C6, C7, C8 and C14 to be sourced first. This module is NOT
# imported by a host or public entry point. All admission/traffic/cleanup
# witnesses deny by default. The original C3 B2 lock remains held through
# credential metadata reobservation and the journalled NM attempt.
#
# A result is NOT prompt-free credential proof, authenticated remote peer,
# DNS safety, application traffic permission or recoverable normal teardown.

mvc24gc9_reset() {
    MVC24GC9_ATTEMPTED=no
    MVC24GC9_STAGE=unverified
    MVC24GC9_AUTHORITY=none
}

mvc24gc9_admission_witness() { return 1; }
mvc24gc9_authorize_public_activation() { return 1; }
mvc24gc9_authorize_retry() { return 1; }
mvc24gc9_authorize_cleanup() { return 1; }
mvc24gc9_authorize_disarm() { return 1; }
mvc24gc9_authorize_traffic() { return 1; }
mvc24gc9_authorize_secret_export() { return 1; }

# Single uninterrupted root transaction only. Do not stage a second B2/C3
# bootstrap over an existing or partially written C7 activation attempt.
# All errors (including lost replies) are terminal for this invocation.
# Neither failure nor success here changes firewall rules to permit apps.
mvc24gc9_execute_once() {
    (( $# == 2 )) || return 1
    [[ ${MVC24GC9_ATTEMPTED:-no} == no ]] || return 1
    MVC24GC9_ATTEMPTED=yes
    MVC24GC9_STAGE=refused-preflight
    MVC24GC9_AUTHORITY=none
    local source_uuid=$1 underlay=$2

    # C9 is intentionally not admitted on physical hosts. It does not
    # replace C3's distinct admission witness or the C4 local consent gate.
    mvc24gc9_admission_witness || return 1
    mvc24ga_uuid_valid "$source_uuid" && mvc24gb1_valid_ifname "$underlay" &&
        mvc24gb2_root_scope || return 1
    [[ ${MVC24GC3_ATTEMPTED:-no} == no &&
       ${MVC24GC5_ATTEMPTED:-no} == no &&
       ${MVC24GC7_ATTEMPTED:-no} == no &&
       ! -e /run/mvc-activation && ! -L /run/mvc-activation ]] || return 1

    # C3 invokes A3, and A3's typed GDBus GetSettings reader requires the
    # legacy MVC24S_LOCK_HELD indicator. Bind it for C3 as well as C8/C14/C7,
    # not only after C3 returns. The indicator does NOT establish lock ownership:
    # C3 acquires the real B2 flock before A3 and C2 reattests the live guard.
    # The local scope restores the caller's original value on every exit.
    local MVC24S_LOCK_HELD=1
    MVC24GC9_STAGE=firewall-or-profile-preparation-uncertain
    mvc24gc3_execute_once "$source_uuid" "$underlay" || return 1
    [[ ${MVC24GC3_STAGE:-} == pinned-bootstrap-verified-no-vpn-authority &&
       ${MVC24GC3_AUTHORITY:-} == none ]] || return 1
    mvc24gb2_lock_valid && mvc24gc3_transition_records_valid &&
        mvc24gc5_guard_witness || return 1

    # Reuse the same dynamically scoped marker for the C8/C14/C7 readbacks;
    # their separate B2 lock, journal and kernel witnesses remain mandatory.
    MVC24GC9_STAGE=credential-metadata-preflight-unverified
    mvc24gc8_preflight_locked || return 1
    [[ ${MVC24GC8_STAGE:-} == nm-source-clone-metadata-consistent-password-delivery-unproven &&
       ${MVC24GC8_AUTHORITY:-} == none ]] || return 1
    mvc24gb2_lock_valid && mvc24gc3_transition_records_valid &&
        mvc24gc5_guard_witness && mvc24gc5_prepared_profile_witness || return 1

    # C14 verifies the native temporary clone is reported UNSAVED by NM.
    # This protects the original saved source profile; it does NOT claim
    # successful password delivery or suppress independent GUI secret agents.
    MVC24GC9_STAGE=nm-native-temporary-clone-custody-unverified
    mvc24gc14_witness_locked || return 1
    [[ ${MVC24GC14_STAGE:-} == nm-native-temporary-flags-verified-password-unproven &&
       ${MVC24GC14_AUTHORITY:-} == none ]] || return 1
    mvc24gb2_lock_valid && mvc24gc3_transition_records_valid &&
        mvc24gc5_guard_witness && mvc24gc5_prepared_profile_witness || return 1

    # C7 publishes its immutable attempt record BEFORE invoking C5/NM,
    # then verifies only NM/IPv4 observations (still behind the C1 guard).
    MVC24GC9_STAGE=activation-intent-or-outcome-uncertain
    mvc24gc7_attempt_once || return 1
    [[ ${MVC24GC7_STAGE:-} == active-nm-and-ipv4-observed-bootstrap-only &&
       ${MVC24GC7_AUTHORITY:-} == none ]] || return 1
    mvc24gb2_lock_valid && mvc24gc3_transition_records_valid &&
        mvc24gc5_guard_witness && mvc24gc5_prepared_profile_witness || return 1
    MVC24GC9_STAGE=active-nm-ipv4-observed-endpoint-only-guard
    MVC24GC9_AUTHORITY=none
}
