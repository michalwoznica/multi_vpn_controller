#!/usr/bin/env bash
# C15: PRIVATE, read-only same-boot reconciliation of an interrupted C13
# nftables OUTPUT transition. Source B2/C1/C3/C5/C6/C7/C11/C13 first.
# No host/public tool sources this module. It cannot commit/retry/disarm.

mvc24gc15_reset() {
    UBS24GC15_STAGE=unverified-ambiguous-manual-review
    UBS24GC15_AUTHORITY=none
}
mvc24gc15_authorize_retry() { return 1; }
mvc24gc15_authorize_traffic() { return 1; }
mvc24gc15_authorize_cleanup() { return 1; }
mvc24gc15_authorize_disarm() { return 1; }
mvc24gc15_authorize_activation() { return 1; }
mvc24gc15_authorize_secret_export() { return 1; }

# Recover only the bounded, nonsecret tunnel parameters from C13's immutable
# journal. Then pass those fields back to C13's FULL same-boot/namespace/hash
# validator. Do not interpret a partial or malformed journal as a clean start.
mvc24gc15_load_bound_intent() {
    (( $# == 0 )) || return 1
    local dir row tuple tunnel address owner
    dir=$(mvc24gc13_runtime) || return 1
    [[ $dir == /run/mvc-output-transition &&
       -f $dir/attempt && ! -L $dir/attempt ]] || return 1
    row=$(sed -n '10p' -- "$dir/attempt") || return 1
    [[ $row =~ ^tunnel=(tun[a-zA-Z0-9_.-]*)\|source=([0-9.]+)$ ]] || return 1
    tunnel=${BASH_REMATCH[1]}
    address=${BASH_REMATCH[2]}
    mvc24gc11_valid_tunnel_ifname "$tunnel" &&
       mvc24gc1_ipv4 "$address" || return 1
    UBS24GC11_TUNNEL=$tunnel
    UBS24GC11_TUNNEL_SOURCE=$address
    mvc24gc13_intent_valid || return 1
    owner=$(sed -n '11p' -- "$dir/attempt") || return 1
    [[ $owner == "nm_owner=$UBS24GC7_NM_OWNER" ]] || return 1
}

# Regenerate the four-statement prospective C11 batch and bind its digest
# byte-for-byte to the immutable C13 candidate digest. The original /dev/shm
# candidate may be gone after a crash, so its path is never required.
mvc24gc15_candidate_digest_valid() {
    (( $# == 0 )) || return 1
    local dir scratch batch expected actual result=1
    dir=$(mvc24gc13_runtime) || return 1
    [[ $dir == /run/mvc-output-transition ]] || return 1
    expected=$(sed -n '9p' -- "$dir/attempt") || return 1
    [[ $expected == candidate_sha=* ]] || return 1
    expected=${expected#candidate_sha=}
    mvc24gc13_sha_valid "$expected" || return 1
    [[ $(stat -f -c %T /dev/shm) == tmpfs ]] || return 1
    scratch=$(umask 077; mktemp -d /dev/shm/ubs-v240-c15.XXXXXXXX) || return 1
    [[ -d $scratch && ! -L $scratch && -O $scratch &&
       $(stat -c '%a:%h' -- "$scratch") == 700:2 ]] || return 1
    batch=$scratch/transition.nft
    if (umask 077; set -C; : > "$batch") &&
       [[ $(stat -c '%a:%h' -- "$batch") == 600:1 ]] &&
       mvc24gc11_write_candidate "$UBS24GC3_IFACE" "$UBS24GC3_SOURCE" \
           "$UBS24GC3_REMOTE" "$UBS24GC3_PORT" "$UBS24GC11_TUNNEL" \
           "$UBS24GC11_TUNNEL_SOURCE" "$batch"; then
        actual=$(mvc24gc13_hash_file "$batch") || actual=''
        [[ $actual == "$expected" ]] && result=0
    fi
    rm -f -- "$batch" || result=1
    rmdir -- "$scratch" || result=1
    (( result == 0 ))
}

# A positive result only classifies one of TWO exact guarded states. Retains
# ALL C13 uncertainty evidence; no secret operations, nft writes, disarm or
# network mutations. Caller MUST hold the original B2 lock.
mvc24gc15_reconcile_locked() {
    (( $# == 0 )) || return 1
    mvc24gc15_reset
    mvc24gb2_root_scope && mvc24gb2_lock_valid &&
        mvc24gc3_transition_records_valid && mvc24gc7_read_intent || return 1
    mvc24gc15_load_bound_intent && mvc24gc15_candidate_digest_valid || return 1
    local nm1 nm2 route1 route2 observed expected foreign_before foreign_after
    local scratch first second pre=0 post=0 result=1
    # Restores A3 nonsecret witness inputs only from the C7 bound same-boot
    # record; no credential fields or secret flags are retrieved here.
    UBS24GA3_PREPARED_SOURCE_UUID=$UBS24GC7_SOURCE_UUID
    UBS24GA3_PREPARED_CLONE_UUID=$UBS24GC7_CLONE_UUID
    UBS24GA3_SOURCE_SHA256=$UBS24GC7_SOURCE_SHA
    UBS24GA3_DERIVATIVE_SHA256=$UBS24GC7_CLONE_SHA
    UBS24GA_CLONE_UUID=$UBS24GC7_CLONE_UUID
    UBS24GA3_STAGE=prepared-nonsecret-parity-only
    UBS24GA3_AUTHORITY=none
    UBS24GA2_STATE=quarantined-exact-nonsecret-settings-verified
    local UBS24S_LOCK_HELD=1
    mvc24gc5_prepared_profile_witness &&
       mvc24op_session_nm_identity &&
       [[ $UBS24OP_SESSION_NM_IDENTITY == "$UBS24GC7_NM_OWNER" ]] || return 1
    nm1=$(mvc24gc6_nm_ipv4_snapshot "$UBS24GC7_CLONE_UUID" "$UBS24GC7_NM_OWNER") || return 1
    route1=$(mvc24gc6_kernel_ipv4_snapshot "$UBS24GC3_IFACE" "$UBS24GC3_SOURCE" "$UBS24GC3_REMOTE") || return 1
    expected="$UBS24GC3_IFACE|$UBS24GC3_SOURCE|$UBS24GC11_TUNNEL|$UBS24GC11_TUNNEL_SOURCE"
    [[ -n $nm1 && $route1 == "$expected" ]] || return 1
    scratch=$(umask 077; mktemp -d /dev/shm/ubs-v240-c15-nft.XXXXXXXX) || return 1
    [[ -d $scratch && ! -L $scratch && -O $scratch &&
       $(stat -c '%a:%h' -- "$scratch") == 700:2 ]] || return 1
    first=$scratch/first.json second=$scratch/second.json
    if mvc24gb1_capture_nft "$first" && mvc24gb1_capture_nft "$second" &&
       cmp -s -- "$first" "$second"; then
        # Exactly one of these states may match. Do not use C5's precommit
        # guard witness here: it rejects a correctly committed C11 policy.
        if mvc24gc1_postshape_observation "$first" "$UBS24GC3_IFACE" "$UBS24GC3_SOURCE" "$UBS24GC3_REMOTE" "$UBS24GC3_PORT" &&
           mvc24gc1_postshape_observation "$second" "$UBS24GC3_IFACE" "$UBS24GC3_SOURCE" "$UBS24GC3_REMOTE" "$UBS24GC3_PORT"; then
            pre=1
        fi
        if mvc24gc11_postshape_observation "$first" "$UBS24GC3_IFACE" "$UBS24GC3_SOURCE" "$UBS24GC3_REMOTE" "$UBS24GC3_PORT" "$UBS24GC11_TUNNEL" "$UBS24GC11_TUNNEL_SOURCE" &&
           mvc24gc11_postshape_observation "$second" "$UBS24GC3_IFACE" "$UBS24GC3_SOURCE" "$UBS24GC3_REMOTE" "$UBS24GC3_PORT" "$UBS24GC11_TUNNEL" "$UBS24GC11_TUNNEL_SOURCE"; then
            post=1
        fi
        if (( pre + post == 1 )); then
            if foreign_before=$(mvc24gb2_foreign_projection /run/mvc-controller/prestate.json) &&
               foreign_after=$(mvc24gb2_foreign_projection "$first"); then
                [[ $foreign_before == "$foreign_after" ]] && result=0
            fi
        fi
    fi
    # Repeat independent NM and route witnesses AFTER the kernel snapshots.
    if (( result == 0 )); then
        nm2=$(mvc24gc6_nm_ipv4_snapshot "$UBS24GC7_CLONE_UUID" "$UBS24GC7_NM_OWNER") || result=1
        route2=$(mvc24gc6_kernel_ipv4_snapshot "$UBS24GC3_IFACE" "$UBS24GC3_SOURCE" "$UBS24GC3_REMOTE") || result=1
        [[ ${nm2:-} == "$nm1" && ${route2:-} == "$expected" ]] || result=1
        mvc24gc13_intent_valid && mvc24gb2_lock_valid &&
          mvc24gc3_transition_records_valid || result=1
    fi
    rm -f -- "$first" "$second" || result=1
    rmdir -- "$scratch" || result=1
    if (( result == 0 )); then
        if (( pre == 1 )); then
            UBS24GC15_STAGE=c13-intent-present-bootstrap-policy-reobserved-no-authority
        else
            UBS24GC15_STAGE=c13-intent-present-tunnel-output-policy-reobserved-dns-unverified
        fi
        return 0
    fi
    return 1
}

# Entry for a fresh root process; never use B2's install path or C5's
# precommit guard attestation for recovery. Acquires the existing B2 flock
# only; reads existing state; closes it even on failure.
mvc24gc15_reconcile_readonly() {
    (( $# == 0 )) || return 1
    mvc24gc15_reset
    [[ -z ${UBS24GB2_FD:-} ]] && mvc24gb2_root_scope &&
        mvc24gb2_runtime_shape || return 1
    local dir fd result=1 stage
    dir=$(mvc24gb2_runtime) || return 1
    [[ $dir == /run/mvc-controller ]] || return 1
    exec {fd}< "$dir/controller.lock" || return 1
    if ! flock -n "$fd"; then exec {fd}>&-; return 1; fi
    UBS24GB2_FD=$fd
    if mvc24gc15_reconcile_locked; then result=0; fi
    stage=$UBS24GC15_STAGE
    mvc24gb2_close
    UBS24GC15_STAGE=$stage
    (( result == 0 ))
}
