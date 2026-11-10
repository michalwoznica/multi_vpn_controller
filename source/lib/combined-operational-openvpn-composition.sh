#!/usr/bin/env bash
# C23R/C23U — explicit PRIVATE OpenVPN-only composition spine.
#
# Source this file LAST after the reviewed composition manifest. It is NOT
# imported by the public vpn CLI. Default state is deny. C23U adds one private
# local-console live mode whose admission witness is supplied by the dedicated
# C23U private driver; the original offline-integration mode remains available
# only to hermetic tests whose external effects are mocked.
#
# This module intentionally owns the final admission bindings for the real
# C3/C5/C7/C9/C13/C17/C19 gates. That makes admission composition inspectable
# rather than an accidental consequence of unrelated unit-test source order.
#
# Current lifecycle boundary:
#   C17: C9 -> C13 -> C16  (protected OpenVPN running observation)
#   C19: C11-policy -> C1 handback -> NM stop (C1 remains installed)
#   C23T: owned C1 release -> temporary clone deletion -> immutable archive
# The composition remains private and is not imported by the public CLI. C23U
# may enable one explicitly admitted local-console live process; public authority
# remains denied.

ubs24gco_reset() {
    UBS24GCO_MODE=disabled
    UBS24GCO_EXTERNALS_MOCKED=no
    UBS24GCO_ATTEMPTED=no
    UBS24GCO_STAGE=idle
    UBS24GCO_AUTHORITY=none
    UBS24GCO_SOURCE_UUID=
    UBS24GCO_UNDERLAY=
    declare -F ubs24gc23t_reset >/dev/null && ubs24gc23t_reset
}

ubs24gco_enable_offline_integration() {
    (( $# == 0 )) || return 1
    [[ ${UBS24GCO_ATTEMPTED:-no} == no &&
       ${UBS24GCO_STAGE:-idle} == idle &&
       ${UBS24GCO_AUTHORITY:-none} == none ]] || return 1
    # The harness must explicitly state that all external mutating effects
    # are substituted before admission is enabled. This is not a host token.
    [[ ${UBS24GCO_EXTERNALS_MOCKED:-no} == yes ]] || return 1
    UBS24GCO_MODE=offline-integration
}

ubs24gco_offline_enabled() {
    (( $# == 0 )) || return 1
    [[ ${UBS24GCO_MODE:-disabled} == offline-integration &&
       ${UBS24GCO_EXTERNALS_MOCKED:-no} == yes &&
       ${UBS24GCO_AUTHORITY:-none} == none ]]
}

# Default-deny external live-admission hook. The C23U private driver overrides
# this one function only when explicitly sourced after the composition. Keeping
# a local deny stub preserves a closed/offline call graph.
ubs24gcu_live_admission_witness() { return 1; }

ubs24gco_enable_private_live() {
    (( $# == 0 )) || return 1
    [[ ${UBS24GCO_ATTEMPTED:-no} == no &&
       ${UBS24GCO_STAGE:-idle} == idle &&
       ${UBS24GCO_AUTHORITY:-none} == none ]] || return 1
    declare -F ubs24gcu_live_admission_witness >/dev/null || return 1
    ubs24gcu_live_admission_witness || return 1
    UBS24GCO_MODE=private-live-local-console
    UBS24GCO_AUTHORITY=private-local-console
}

ubs24gco_private_live_enabled() {
    (( $# == 0 )) || return 1
    [[ ${UBS24GCO_MODE:-disabled} == private-live-local-console &&
       ${UBS24GCO_AUTHORITY:-none} == private-local-console ]] || return 1
    declare -F ubs24gcu_live_admission_witness >/dev/null || return 1
    ubs24gcu_live_admission_witness
}

ubs24gco_enabled() {
    (( $# == 0 )) || return 1
    ubs24gco_offline_enabled || ubs24gco_private_live_enabled
}

# --- Explicit final admission ownership -----------------------------------
# These names deliberately replace the default-deny witnesses defined by the
# individual gate modules. They remain deny unless the composition is enabled
# either by the hermetic harness or by the C23U local-console driver and the
# exact parent-stage transition matches.

ubs24gc17_admission_witness() {
    (( $# == 0 )) || return 1
    ubs24gco_enabled || return 1
    [[ ${UBS24GCO_ATTEMPTED:-no} == yes &&
       ${UBS24GCO_STAGE:-} == starting &&
       ${UBS24GC17_STAGE:-} == refused-before-activation ]]
}

ubs24gc9_admission_witness() {
    (( $# == 0 )) || return 1
    ubs24gco_enabled || return 1
    [[ ${UBS24GCO_STAGE:-} == starting &&
       ${UBS24GC17_STAGE:-} == bootstrap-or-activation-outcome-uncertain &&
       ${UBS24GC9_STAGE:-} == refused-preflight ]]
}

ubs24gc3_admission_witness() {
    (( $# == 0 )) || return 1
    ubs24gco_enabled || return 1
    [[ ${UBS24GCO_STAGE:-} == starting &&
       ${UBS24GC17_STAGE:-} == bootstrap-or-activation-outcome-uncertain &&
       ${UBS24GC9_STAGE:-} == firewall-or-profile-preparation-uncertain &&
       ${UBS24GC3_STAGE:-} == refused-preflight ]]
}

ubs24gc7_admission_witness() {
    (( $# == 0 )) || return 1
    ubs24gco_enabled || return 1
    [[ ${UBS24GCO_STAGE:-} == starting &&
       ${UBS24GC17_STAGE:-} == bootstrap-or-activation-outcome-uncertain &&
       ${UBS24GC9_STAGE:-} == activation-intent-or-outcome-uncertain ]] &&
        ubs24gb2_lock_valid
}

ubs24gc5_admission_witness() {
    (( $# == 0 )) || return 1
    ubs24gco_enabled || return 1
    [[ ${UBS24GCO_STAGE:-} == starting &&
       ${UBS24GC17_STAGE:-} == bootstrap-or-activation-outcome-uncertain &&
       ${UBS24GC9_STAGE:-} == activation-intent-or-outcome-uncertain ]] &&
        ubs24gb2_lock_valid
}

ubs24gc13_admission_witness() {
    (( $# == 0 )) || return 1
    ubs24gco_enabled || return 1
    [[ ${UBS24GCO_STAGE:-} == starting &&
       ${UBS24GC17_STAGE:-} == firewall-transition-outcome-uncertain &&
       ${UBS24GC9_STAGE:-} == active-nm-ipv4-observed-endpoint-only-guard ]] &&
        ubs24gb2_lock_valid
}

ubs24gc19_admission_witness() {
    (( $# == 0 )) || return 1
    ubs24gco_enabled || return 1
    [[ ${UBS24GCO_STAGE:-} == stopping &&
       ${UBS24GC17_STAGE:-} == protected-ovpn-stages-observed-no-operational-authority &&
       ${UBS24GC19_STAGE:-} == refused-or-unverified ]] &&
        ubs24gb2_lock_valid
}

ubs24gc23t_admission_witness() {
    (( $# == 0 )) || return 1
    ubs24gco_enabled || return 1
    case ${UBS24GCO_STAGE:-} in
      completing|reconciling-completion) ;;
      *) return 1 ;;
    esac
    return 0
}

# --- Real-gate composition entrypoints -----------------------------------
# No C9/C13/C17/C19 stage is stubbed here. Hermetic tests substitute only
# external effects beneath these real gates; C23U invokes the same functions.

ubs24gco_start_once() {
    (( $# == 2 )) || return 1
    [[ ${UBS24GCO_ATTEMPTED:-no} == no ]] || return 1
    ubs24gco_enabled || return 1
    local source_uuid=$1 underlay=$2
    ubs24ga_uuid_valid "$source_uuid" && ubs24gb1_valid_ifname "$underlay" || return 1
    # Refuse a new session while ANY fixed live-session journal root from an
    # interrupted or incomplete prior session remains. Completed archives under
    # /run/mvc-completed are intentionally permitted.
    local live_root
    for live_root in \
        /run/mvc-controller \
        /run/mvc-activation \
        /run/mvc-output-transition \
        /run/mvc-disconnect \
        /run/mvc-completion; do
        [[ ! -e $live_root && ! -L $live_root ]] || return 1
    done
    UBS24GCO_ATTEMPTED=yes
    UBS24GCO_SOURCE_UUID=$source_uuid
    UBS24GCO_UNDERLAY=$underlay
    UBS24GCO_STAGE=starting
    ubs24gc17_execute_once "$source_uuid" "$underlay" || return 1
    [[ ${UBS24GC17_STAGE:-} == protected-ovpn-stages-observed-no-operational-authority &&
       ${UBS24GC17_AUTHORITY:-} == none ]] || return 1
    UBS24GCO_STAGE=protected-openvpn-observed
    return 0
}

ubs24gco_stop_once() {
    (( $# == 0 )) || return 1
    ubs24gco_enabled || return 1
    [[ ${UBS24GCO_ATTEMPTED:-no} == yes &&
       ${UBS24GCO_STAGE:-} == protected-openvpn-observed &&
       ${UBS24GC17_STAGE:-} == protected-ovpn-stages-observed-no-operational-authority ]] || return 1
    UBS24GCO_STAGE=stopping
    ubs24gc19_execute_once || return 1
    [[ ${UBS24GC19_STAGE:-} == openvpn-stopped-c1-guard-retained-no-release-authority &&
       ${UBS24GC19_AUTHORITY:-} == none ]] || return 1
    UBS24GCO_STAGE=protected-stopped-c1-held-finalize-pending
    return 0
}

ubs24gco_complete_once() {
    (( $# == 0 )) || return 1
    ubs24gco_enabled || return 1
    [[ ${UBS24GCO_ATTEMPTED:-no} == yes &&
       ${UBS24GCO_STAGE:-} == protected-stopped-c1-held-finalize-pending &&
       ${UBS24GC19_STAGE:-} == openvpn-stopped-c1-guard-retained-no-release-authority ]] || return 1
    UBS24GCO_STAGE=completing
    ubs24gc23t_execute_once || return 1
    [[ ${UBS24GC23T_STAGE:-} == completed-session-archived-sameboot-ready ]] || return 1
    UBS24GCO_STAGE=completed-session-archived-sameboot-ready
    return 0
}


# Fresh-process continuation for the narrower boundary where C19 completed and
# retained C1, but the original process ended before C23T published any
# completion intent. C23T itself reconstructs and validates C19/C7/C1 before
# issuing the first release intent; this is continuation, not mutation retry.
ubs24gco_resume_completion_once() {
    (( $# == 0 )) || return 1
    ubs24gco_enabled || return 1
    [[ ! -e /run/mvc-completion && ! -L /run/mvc-completion &&
       -f /run/mvc-disconnect/attempt &&
       ! -L /run/mvc-disconnect/attempt ]] || return 1
    UBS24GCO_STAGE=completing
    ubs24gc23t_execute_once || return 1
    [[ ${UBS24GC23T_STAGE:-} == completed-session-archived-sameboot-ready ]] || return 1
    UBS24GCO_STAGE=completed-session-archived-sameboot-ready
    return 0
}

# Fresh-process completion recovery after C23T has already published its fixed
# completion runtime. No start/stop stage is reissued here.
ubs24gco_reconcile_completion_once() {
    (( $# == 0 )) || return 1
    ubs24gco_enabled || return 1
    UBS24GCO_STAGE=reconciling-completion
    ubs24gc23t_reconcile_once || return 1
    [[ ${UBS24GC23T_STAGE:-} == completed-session-archived-sameboot-ready ]] || return 1
    UBS24GCO_STAGE=completed-session-archived-sameboot-ready
    return 0
}

# Public authority remains impossible from this module. Private live authority
# is admitted only through ubs24gco_enable_private_live + the C23U witness.
ubs24gco_authorize_live_host() { ubs24gco_private_live_enabled; }
ubs24gco_authorize_public_activation() { return 1; }
ubs24gco_authorize_public_release() { return 1; }
ubs24gco_authorize_cleanup() { return 1; }
ubs24gco_authorize_disarm() { return 1; }
ubs24gco_authorize_secret_export() { return 1; }
