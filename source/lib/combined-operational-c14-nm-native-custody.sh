#!/usr/bin/env bash
# Gate C14: private, strictly READ-ONLY NetworkManager native-clone custody
# witness. Requires C8 to have completed under C3/B2 lock. Verifies that
# NetworkManager reports a saved source and an UNSAVED temporary derivative.
#
# This does NOT call GetSecrets, show secret values, inspect user keyrings,
# open keyfiles, start NM, activate VPN, edit profiles or change the firewall.
# UNSAVED (bit 0) alone does NOT prove the derivative has no backing file:
# NM also uses this bit for unsaved edits to backed profiles. The separate
# native `nmcli connection clone --temporary` contract is therefore essential.
# Most importantly: this does NOT prove that libnm obtained a password or
# that an unrelated registered agent will not prompt. No activation authority.

ubs24gc14_reset() {
    UBS24GC14_STAGE=unverified
    UBS24GC14_AUTHORITY=none
}
ubs24gc14_authorize_activation() { return 1; }
ubs24gc14_authorize_secrets() { return 1; }
ubs24gc14_authorize_prompt() { return 1; }
ubs24gc14_authorize_commit() { return 1; }
ubs24gc14_authorize_cleanup() { return 1; }
ubs24gc14_authorize_traffic() { return 1; }
ubs24gc14_authorize_retry() { return 1; }

# Typed Settings.Connection Flags; never GetSecrets. Result is one literal
# decimal integer (NetworkManager's D-Bus `u` value), or failure.
ubs24gc14_connection_flags() {
    (( $# == 1 )) || return 1
    local uuid=$1 raw path flags
    ubs24ga_uuid_valid "$uuid" || return 1
    declare -F ubs24g_call_readonly >/dev/null &&
        declare -F ubs24g_get_property >/dev/null || return 1
    raw=$(ubs24g_call_readonly org.freedesktop.NetworkManager \
        /org/freedesktop/NetworkManager/Settings \
        org.freedesktop.NetworkManager.Settings GetConnectionByUuid s "$uuid" o) || return 1
    [[ $raw =~ ^o\ \"(/org/freedesktop/NetworkManager/Settings/[0-9]+)\"$ ]] || return 1
    path=${BASH_REMATCH[1]}
    raw=$(ubs24g_get_property org.freedesktop.NetworkManager "$path" \
        org.freedesktop.NetworkManager.Settings.Connection Flags u) || return 1
    [[ $raw =~ ^u\ ([0-9]+)$ ]] || return 1
    flags=${BASH_REMATCH[1]}
    [[ ${#flags} -le 10 && ( $flags == 0 || $flags != 0* ) ]] || return 1
    (( 10#$flags <= 4294967295 )) || return 1
    printf '%s|%s\n' "$path" "$flags"
}

ubs24gc14_witness_locked() {
    ubs24gc14_reset
    (( $# == 0 )) || return 1
    [[ ${UBS24GC8_STAGE:-} == nm-source-clone-metadata-consistent-password-delivery-unproven &&
       ${UBS24GC8_AUTHORITY:-} == none &&
       ${UBS24GC3_STAGE:-} == pinned-bootstrap-verified-no-vpn-authority &&
       ${UBS24GC3_AUTHORITY:-} == none &&
       ${UBS24GC5_ATTEMPTED:-no} == no ]] || return 1
    ubs24gb2_root_scope && ubs24gb2_lock_valid &&
        ubs24gc3_transition_records_valid && ubs24gc5_guard_witness &&
        ubs24gc5_prepared_profile_witness || return 1
    local source=${UBS24GA3_PREPARED_SOURCE_UUID:-}
    local clone=${UBS24GA3_PREPARED_CLONE_UUID:-}
    local owner source1 source2 clone1 clone2 fs fc
    ubs24ga_uuid_valid "$source" && ubs24ga_uuid_valid "$clone" &&
        [[ $source != "$clone" ]] || return 1
    ubs24op_session_nm_identity || return 1
    owner=$UBS24OP_SESSION_NM_IDENTITY
    [[ $owner == *'|0' ]] || return 1
    source1=$(ubs24gc14_connection_flags "$source") || return 1
    clone1=$(ubs24gc14_connection_flags "$clone") || return 1
    source2=$(ubs24gc14_connection_flags "$source") || return 1
    clone2=$(ubs24gc14_connection_flags "$clone") || return 1
    [[ $source1 == "$source2" && $clone1 == "$clone2" &&
       ${source1%%|*} != "${clone1%%|*}" ]] || return 1
    fs=${source1##*|} fc=${clone1##*|}
    # Source saved and unchanged (Flags == 0); temporary derivative UNSAVED
    # but not NM_GENERATED (2). VOLATILE (4) is permitted with UNSAVED.
    (( fs == 0 && (fc & 1) == 1 && (fc & 2) == 0 && (fc & ~5) == 0 )) || return 1
    ubs24op_session_nm_identity && [[ $UBS24OP_SESSION_NM_IDENTITY == "$owner" ]] &&
        ubs24gb2_lock_valid && ubs24gc3_transition_records_valid &&
        ubs24gc5_guard_witness && ubs24gc5_prepared_profile_witness || return 1
    UBS24GC14_STAGE=nm-native-temporary-flags-verified-password-unproven
    UBS24GC14_AUTHORITY=none
}
