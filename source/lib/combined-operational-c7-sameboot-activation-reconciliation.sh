#!/usr/bin/env bash
# Gate C7: PRIVATE and NON-ADMITTING same-boot OpenVPN activation intent and
# observation-only reattachment. Source C3, C5 and C6 dependencies first.
# No production driver imports this file. No secret retrieval, NM disconnect,
# retry, firewall release, DNS edit or traffic authority exists here.
# An attempted nmcli operation may have completed despite a lost reply.

mvc24gc7_reset() {
    MVC24GC7_ATTEMPTED=no
    MVC24GC7_STAGE=unverified
    MVC24GC7_AUTHORITY=none
    MVC24GC7_SOURCE_UUID= MVC24GC7_CLONE_UUID=
    MVC24GC7_SOURCE_SHA= MVC24GC7_CLONE_SHA= MVC24GC7_NM_OWNER=
}

mvc24gc7_runtime() { printf '%s\n' /run/mvc-activation; }
mvc24gc7_run_tmpfs() { [[ $(stat -f -c %T /run) == tmpfs ]]; }
mvc24gc7_fixed_b2_runtime() { [[ $(mvc24gb2_runtime) == /run/mvc-controller ]]; }
mvc24gc7_owned_dir() {
    (( $# == 1 )) && [[ -d $1 && ! -L $1 &&
        $(stat -c '%u:%a:%h' -- "$1" 2>/dev/null) == 0:700:2 ]]
}
mvc24gc7_owned_file() {
    (( $# == 1 )) && [[ -f $1 && ! -L $1 &&
        $(stat -c '%u:%a:%h' -- "$1" 2>/dev/null) == 0:400:1 ]]
}
mvc24gc7_admission_witness() { return 1; }
mvc24gc7_authorize_public_activation() { return 1; }
mvc24gc7_authorize_retry() { return 1; }
mvc24gc7_authorize_cleanup() { return 1; }
mvc24gc7_authorize_disarm() { return 1; }
mvc24gc7_authorize_traffic() { return 1; }
mvc24gc7_authorize_secret_export() { return 1; }

mvc24gc7_hash_valid() { (( $# == 1 )) && [[ $1 =~ ^[a-f0-9]{64}$ ]]; }
mvc24gc7_nm_owner_valid() {
    (( $# == 1 )) && [[ $1 =~ ^:[0-9]+\.[0-9]+\|[0-9]+\|0$ ]]
}

# Parse a *fixed* root-owned record. The independent C3 journal and live
# kernel/NM witnesses are always required as well; this record is NOT a grant.
# One immutable record only: an incomplete or duplicate directory is ambiguous.
mvc24gc7_read_intent() {
    (( $# == 0 )) || return 1
    MVC24GC7_SOURCE_UUID= MVC24GC7_CLONE_UUID=
    MVC24GC7_SOURCE_SHA= MVC24GC7_CLONE_SHA= MVC24GC7_NM_OWNER=
    local dir boot userns netns mntns c1hash
    local -a rows=() entries=()
    dir=$(mvc24gc7_runtime) || return 1
    mvc24gc7_owned_dir "$dir" || return 1
    mapfile -d '' -t entries < <(find "$dir" -mindepth 1 -maxdepth 1 -print0) || return 1
    (( ${#entries[@]} == 1 )) && [[ ${entries[0]} == "$dir/attempt" ]] || return 1
    mvc24gc7_owned_file "$dir/attempt" || return 1
    mapfile -t rows < "$dir/attempt" || return 1
    (( ${#rows[@]} == 11 )) || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    userns=$(readlink /proc/self/ns/user) || return 1
    netns=$(readlink /proc/self/ns/net) || return 1
    mntns=$(readlink /proc/self/ns/mnt) || return 1
    c1hash=$(sha256sum "$(mvc24gb2_runtime)/transition-attempt" 2>/dev/null) || return 1
    c1hash=${c1hash%% *}
    [[ ${rows[0]} == mvc-c7-openvpn-attempt-v1 &&
       ${rows[1]} == state=attempt-entered-once-activation-uncertain &&
       ${rows[2]} == "boot=$boot" &&
       ${rows[3]} == "userns=$userns" &&
       ${rows[4]} == "netns=$netns" &&
       ${rows[5]} == "mntns=$mntns" &&
       ${rows[6]} == "c1=$c1hash" &&
       ${rows[7]} == source_uuid=* &&
       ${rows[8]} == clone_uuid=* &&
       ${rows[9]} == source_sha=*'|'clone_sha=* &&
       ${rows[10]} == nm_owner=* ]] || return 1
    local source_uuid=${rows[7]#source_uuid=} clone_uuid=${rows[8]#clone_uuid=}
    local hashes=${rows[9]#source_sha=} source_sha clone_sha
    [[ $hashes == *'|clone_sha='* ]] || return 1
    source_sha=${hashes%%|clone_sha=*}
    clone_sha=${hashes#*|clone_sha=}
    mvc24ga_uuid_valid "$source_uuid" && mvc24ga_uuid_valid "$clone_uuid" &&
       [[ $source_uuid != "$clone_uuid" ]] &&
       mvc24gc7_hash_valid "$source_sha" && mvc24gc7_hash_valid "$clone_sha" &&
       mvc24gc7_nm_owner_valid "${rows[10]#nm_owner=}" || return 1
    MVC24GC7_SOURCE_UUID=$source_uuid
    MVC24GC7_CLONE_UUID=$clone_uuid
    MVC24GC7_SOURCE_SHA=$source_sha
    MVC24GC7_CLONE_SHA=$clone_sha
    MVC24GC7_NM_OWNER=${rows[10]#nm_owner=}
}

# Create the dedicated same-boot intent before invoking NM. Do not extend the
# strictly ten-entry C3 firewall journal or overwrite an existing attempt.
# A crash during directory/file creation leaves an ambiguous, non-retriable
# record. The directory MUST be on /run tmpfs and is never cleaned here.
mvc24gc7_publish_intent() {
    (( $# == 0 )) || return 1
    local dir tmp boot userns netns mntns c1hash
    mvc24gb2_root_scope && mvc24gc7_fixed_b2_runtime &&
       mvc24gc3_transition_records_valid && mvc24gc5_guard_witness && mvc24gc5_prepared_profile_witness || return 1
    mvc24gc7_nm_owner_valid "${MVC24GC5_NM_OWNER:-}" &&
       mvc24ga_uuid_valid "${MVC24GA3_PREPARED_SOURCE_UUID:-}" &&
       mvc24ga_uuid_valid "${MVC24GA3_PREPARED_CLONE_UUID:-}" &&
       mvc24gc7_hash_valid "${MVC24GA3_SOURCE_SHA256:-}" &&
       mvc24gc7_hash_valid "${MVC24GA3_DERIVATIVE_SHA256:-}" || return 1
    mvc24gc7_run_tmpfs || return 1
    dir=$(mvc24gc7_runtime) || return 1
    [[ ! -e $dir && ! -L $dir ]] || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    userns=$(readlink /proc/self/ns/user) || return 1
    netns=$(readlink /proc/self/ns/net) || return 1
    mntns=$(readlink /proc/self/ns/mnt) || return 1
    c1hash=$(sha256sum "$(mvc24gb2_runtime)/transition-attempt") || return 1
    c1hash=${c1hash%% *}
    (umask 077; mkdir -m 700 -- "$dir") || return 1
    tmp=$(umask 077; mktemp "$dir/.attempt.XXXXXXXX") || return 1
    if ! printf '%s\n' \
       'mvc-c7-openvpn-attempt-v1' \
       'state=attempt-entered-once-activation-uncertain' \
       "boot=$boot" "userns=$userns" "netns=$netns" "mntns=$mntns" \
       "c1=$c1hash" \
       "source_uuid=$MVC24GA3_PREPARED_SOURCE_UUID" \
       "clone_uuid=$MVC24GA3_PREPARED_CLONE_UUID" \
       "source_sha=$MVC24GA3_SOURCE_SHA256|clone_sha=$MVC24GA3_DERIVATIVE_SHA256" \
       "nm_owner=$MVC24GC5_NM_OWNER" > "$tmp"; then return 1; fi
    chmod 400 -- "$tmp" || return 1
    [[ ! -e $dir/attempt && ! -L $dir/attempt ]] || return 1
    mv -T -- "$tmp" "$dir/attempt" || return 1
    mvc24gc7_read_intent
}

# A separate coordinator means C5 cannot begin before an attempt is recorded.
# This function remains unreachable from all real-host and public entry points.
mvc24gc7_attempt_once() {
    (( $# == 0 )) || return 1
    [[ ${MVC24GC7_ATTEMPTED:-no} == no ]] || return 1
    MVC24GC7_ATTEMPTED=yes
    MVC24GC7_STAGE=preflight-refused-or-uncertain
    MVC24GC7_AUTHORITY=none
    mvc24gc7_admission_witness || return 1
    [[ ${MVC24GC3_STAGE:-} == pinned-bootstrap-verified-no-vpn-authority &&
       ${MVC24GC3_AUTHORITY:-} == none &&
       ${MVC24GC5_ATTEMPTED:-no} == no ]] || return 1
    # The inherited typed GetSettings reader also requires this legacy flag.
    # Set it only as a dynamically scoped local AFTER verifying the genuine
    # C3 root-held flock; it cannot replace that independent lock witness.
    mvc24gb2_root_scope && mvc24gc3_transition_records_valid || return 1
    local MVC24S_LOCK_HELD=1
    mvc24op_session_nm_identity || return 1
    MVC24GC5_NM_OWNER=$MVC24OP_SESSION_NM_IDENTITY
    mvc24gc7_publish_intent || return 1
    MVC24GC7_STAGE=attempt-journalled-outcome-uncertain
    mvc24gc5_activate_once || return 1
    mvc24gc6_observe_active_once || return 1
    MVC24GC7_STAGE=active-nm-and-ipv4-observed-bootstrap-only
    MVC24GC7_AUTHORITY=none
}

# Standalone fresh-process read-only reattachment. Even a positive result
# merely observes active NM/tun routing behind the still restrictive C1 guard.
# Any bad journal, unknown NM state or missing/partial tunnel observation
# returns DENY, leaving firewall/NM untouched and retaining all evidence.
mvc24gc7_reconcile_readonly() {
    (( $# == 0 )) || return 1
    MVC24GC7_STAGE=unverified-ambiguous-manual-review
    MVC24GC7_AUTHORITY=none
    [[ -z ${MVC24GB2_FD:-} ]] && mvc24gb2_root_scope || return 1
    local fd dir nm1 nm2 route1 route2 result=1
    dir=$(mvc24gb2_runtime) || return 1
    mvc24gc7_fixed_b2_runtime || return 1
    mvc24gb2_runtime_shape || return 1
    exec {fd}< "$dir/controller.lock" || return 1
    if ! flock -n "$fd"; then exec {fd}>&-; return 1; fi
    MVC24GB2_FD=$fd
    if mvc24gc3_transition_records_valid && mvc24gc7_read_intent; then
        # Legacy read-only GDBus setting capture requires this flag. The
        # independently held kernel-verified C3 flock remains mandatory.
        # Bash local dynamic scope restores the caller's value on return.
        local MVC24S_LOCK_HELD=1
        # The saved fingerprints are comparison claims, NOT credential data
        # or substitute for a fresh readback through NetworkManager.
        MVC24GA3_PREPARED_SOURCE_UUID=$MVC24GC7_SOURCE_UUID
        MVC24GA3_PREPARED_CLONE_UUID=$MVC24GC7_CLONE_UUID
        MVC24GA3_SOURCE_SHA256=$MVC24GC7_SOURCE_SHA
        MVC24GA3_DERIVATIVE_SHA256=$MVC24GC7_CLONE_SHA
        MVC24GA_CLONE_UUID=$MVC24GC7_CLONE_UUID
        MVC24GA3_STAGE=prepared-nonsecret-parity-only
        MVC24GA3_AUTHORITY=none
        MVC24GA2_STATE=quarantined-exact-nonsecret-settings-verified
        if mvc24gc5_guard_witness && mvc24gc5_prepared_profile_witness &&
           mvc24op_session_nm_identity &&
           [[ $MVC24OP_SESSION_NM_IDENTITY == "$MVC24GC7_NM_OWNER" ]]; then
            nm1=$(mvc24gc6_nm_ipv4_snapshot "$MVC24GC7_CLONE_UUID" "$MVC24GC7_NM_OWNER") &&
            route1=$(mvc24gc6_kernel_ipv4_snapshot "$MVC24GC3_IFACE" "$MVC24GC3_SOURCE" "$MVC24GC3_REMOTE") &&
            route2=$(mvc24gc6_kernel_ipv4_snapshot "$MVC24GC3_IFACE" "$MVC24GC3_SOURCE" "$MVC24GC3_REMOTE") &&
            nm2=$(mvc24gc6_nm_ipv4_snapshot "$MVC24GC7_CLONE_UUID" "$MVC24GC7_NM_OWNER") &&
            [[ -n $nm1 && $nm1 == "$nm2" && -n $route1 && $route1 == "$route2" ]] &&
            mvc24gc5_guard_witness && mvc24gc5_prepared_profile_witness &&
            mvc24gc7_read_intent && result=0
        fi
    fi
    mvc24gb2_close
    if (( result == 0 )); then
        MVC24GC7_STAGE=active-nm-and-ipv4-reobserved-bootstrap-only
        return 0
    fi
    return 1
}
