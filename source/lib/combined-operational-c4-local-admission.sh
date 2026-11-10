#!/usr/bin/env bash
# Gate C4: private operator-reviewed local-root entry for C3 preparation ONLY.
# No OpenVPN activation, no automatic cleanup, no guard release or DNS change.
# Source AFTER C3. Admission is bound to local confirmation, exact source UUID,
# root scope, no existing runtime, no active VPN and installed manual recovery.
# The C3 entry itself remains unimported by the public vpn controller.

mvc24gc4_reset() {
    MVC24GC4_OPERATION=none
    MVC24GC4_APPROVAL=none
    MVC24GC4_ATTEMPTED=no
    MVC24GC4_IFACE=
    MVC24GC4_NM_OWNER=
    MVC24GC4_PREFLIGHT_STAGE=idle
}

mvc24gc4_recovery_installed() {
    (( $# == 0 )) || return 1
    local installed=/root/mvc-emergency-rollback
    local source=${MVC24GC4_SOURCE_ROOT:-}/tools/recover-mvc-host-guard-local.sh
    [[ ${MVC24GC4_SOURCE_ROOT:-} == /* && -f $source && ! -L $source &&
       -f $installed && ! -L $installed && -x $installed ]] || return 1
    [[ $(stat -c '%u:%a:%h' -- "$installed" 2>/dev/null) == '0:700:1' ]] || return 1
    cmp -s -- "$source" "$installed"
}

mvc24gc4_dependencies() {
    (( $# == 0 )) || return 1
    local bin
    for bin in nft jq ip nmcli gdbus flock wg pgrep sha256sum awk cmp stat sleep; do
        command -v "$bin" >/dev/null 2>&1 || return 1
    done
}

# Read-only early eligibility check BEFORE B2 can block connectivity.
# This is a convenience rejection, never a substitute for the guarded A3/C2
# exact readbacks or a claim that NM already holds reusable credentials.
mvc24gc4_source_preview() {
    (( $# == 1 )) || return 1
    local probe=${MVC24GC4_SOURCE_ROOT:-}/tools/check-v240-live-saved-ovpn-readonly.sh
    [[ ${MVC24GC4_SOURCE_ROOT:-} == /* && -f $probe && ! -L $probe && -x $probe ]] || return 1
    "$probe" --preview-derivative "$1" >/dev/null 2>&1
}

mvc24gc4_preflight() {
    (( $# == 1 )) || return 1
    local source_uuid=$1 underlay nm_owner
    MVC24GC4_PREFLIGHT_STAGE=attempt-state
    [[ ${MVC24GC4_ATTEMPTED:-no} == no ]] || return 1
    MVC24GC4_PREFLIGHT_STAGE=source-uuid
    mvc24ga_uuid_valid "$source_uuid" || return 1
    MVC24GC4_PREFLIGHT_STAGE=local-root-scope
    mvc24gb4_scope || return 1
    MVC24GC4_PREFLIGHT_STAGE=no-active-vpn
    mvc24gb4_no_active_vpn || return 1
    MVC24GC4_PREFLIGHT_STAGE=recovery-script-identity
    mvc24gc4_recovery_installed || return 1
    MVC24GC4_PREFLIGHT_STAGE=controller-runtime-absent
    [[ ! -e /run/mvc-controller && ! -L /run/mvc-controller ]] || return 1
    MVC24GC4_PREFLIGHT_STAGE=required-command-inventory
    mvc24gc4_dependencies || return 1
    MVC24GC4_PREFLIGHT_STAGE=saved-openvpn-derivative-preview
    mvc24gc4_source_preview "$source_uuid" || return 1
    MVC24GC4_PREFLIGHT_STAGE=single-underlay
    underlay=$(mvc24gb4_underlay) || return 1
    MVC24GC4_PREFLIGHT_STAGE=networkmanager-owner
    mvc24op_session_nm_identity || return 1
    nm_owner=${MVC24OP_SESSION_NM_IDENTITY:-}
    MVC24GC4_PREFLIGHT_STAGE=networkmanager-owner-root
    [[ $nm_owner == *'|0' && -n $underlay ]] || return 1
    MVC24GC4_IFACE=$underlay
    MVC24GC4_NM_OWNER=$nm_owner
    MVC24GC4_PREFLIGHT_STAGE=ready
}

mvc24gc4_confirm() {
    (( $# == 0 )) || return 1
    [[ -t 0 && -t 1 && -r /dev/tty && -w /dev/tty &&
       -z ${SSH_CONNECTION:-} && -z ${SSH_TTY:-} ]] || return 1
    printf '%s\n' '' \
      'This will change your REAL HOST nftables firewall and NetworkManager.' \
      'The host will enter deny-all quarantine, then permit only one pinned OpenVPN endpoint.' \
      'NO VPN WILL BE ACTIVATED. Internet access will remain blocked for ordinary applications.' \
      'On failure or uncertain commit, the kill switch stays in place; no automatic rollback.' \
      'You must have a separate working local-root recovery terminal, not SSH.' \
      'Emergency rollback DISABLES the kill switch and is a manual decision.' \
      'Type exactly: PREPARE MVC GUARDED OPENVPN' > /dev/tty
    printf '> ' > /dev/tty
    local response=
    IFS= read -r response < /dev/tty || return 1
    [[ $response == 'PREPARE MVC GUARDED OPENVPN' ]]
}

# Override C3 DENY ONLY from this private driver after explicit confirmation.
# Approval is consumed before any B2 write. Neither Bash environment values
# nor raw endpoint arguments can establish permission on their own.
mvc24gc3_admission_witness() {
    (( $# == 0 )) || return 1
    [[ ${MVC24GC4_OPERATION:-none} == prepare &&
       ${MVC24GC4_APPROVAL:-none} == approved-once &&
       ${MVC24GC4_ATTEMPTED:-no} == yes &&
       -n ${MVC24GC4_IFACE:-} && -n ${MVC24GC4_NM_OWNER:-} ]] || return 1
    MVC24GC4_APPROVAL=consumed
    mvc24gb4_scope && mvc24gb4_no_active_vpn &&
      mvc24gc4_recovery_installed || return 1
    [[ ! -e /run/mvc-controller && ! -L /run/mvc-controller ]] || return 1
    local current_iface
    current_iface=$(mvc24gb4_underlay) || return 1
    [[ $current_iface == "$MVC24GC4_IFACE" ]] || return 1
    mvc24op_session_nm_identity || return 1
    [[ ${MVC24OP_SESSION_NM_IDENTITY:-} == "$MVC24GC4_NM_OWNER" ]]
}

mvc24gc4_prepare_once() {
    (( $# == 1 )) || return 1
    [[ ${MVC24GC4_ATTEMPTED:-no} == no ]] || return 1
    # Read-only preflight first; consume the one-shot attempt even on failure.
    if ! mvc24gc4_preflight "$1"; then
        MVC24GC4_ATTEMPTED=yes
        return 1
    fi
    MVC24GC4_ATTEMPTED=yes
    MVC24GC4_OPERATION=prepare
    MVC24GC4_APPROVAL=none
    mvc24gc4_confirm || return 1
    MVC24GC4_APPROVAL=approved-once
    # The typed GDBus settings reader has a legacy boolean API prerequisite.
    # It is NOT permission: C2 reattests the actual exclusive B2 lock, kernel
    # quarantine and NM identity before every A3 readback and C1 transition.
    # Scope it to this one-shot process and never export it to the environment.
    MVC24S_LOCK_HELD=1
    local result=1
    if mvc24gc3_execute_once "$1" "$MVC24GC4_IFACE"; then result=0; fi
    MVC24S_LOCK_HELD=0
    MVC24GC4_APPROVAL=consumed
    (( result == 0 ))
}

mvc24gc4_status_readonly() {
    (( $# == 0 )) || return 1
    mvc24gb2_root_scope && mvc24gc3_reconcile_readonly
}

# C4 preparation is NOT OpenVPN activation, VPN-session recovery or disarm.
mvc24gc4_authorize_activation() { return 1; }
mvc24gc4_authorize_cleanup() { return 1; }
mvc24gc4_authorize_disarm() { return 1; }
mvc24gc4_authorize_secret_export() { return 1; }
mvc24gc4_authorize_recovery() { return 1; }
