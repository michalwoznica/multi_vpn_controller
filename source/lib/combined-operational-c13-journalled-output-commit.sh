#!/usr/bin/env bash
# Gate C13: PRIVATE / DEFAULT-DENY journalled atomic C11 OUTPUT transition.
# NOT imported by any host/public entrypoint. Requires C1-C11, B2, C7,
# C16 fixed-path DNS reader and C18 precommit DNS verification.
# Even a verified C13 kernel change is NOT DNS, remote authentication,
# prompt-free credential, FORWARD or application-traffic authorisation.
# No automatic retry, no rollback that could remove the restrictive guard.

mvc24gc13_reset() {
    MVC24GC13_ATTEMPTED=no
    MVC24GC13_STAGE=unverified
    MVC24GC13_DETAIL_STAGE=unverified
    MVC24GC13_AUTHORITY=none
    MVC24GC13_NFT_COMMIT_RC=
    MVC24GC13_DIAGNOSTIC_FILE=
}
mvc24gc13_admission_witness() { return 1; }
mvc24gc13_authorize_public_activation() { return 1; }
mvc24gc13_authorize_traffic() { return 1; }
mvc24gc13_authorize_cleanup() { return 1; }
mvc24gc13_authorize_retry() { return 1; }
mvc24gc13_authorize_disarm() { return 1; }
mvc24gc13_authorize_secret_export() { return 1; }
mvc24gc13_runtime() { printf '%s\n' /run/mvc-output-transition; }
mvc24gc13_sha_valid() { (( $# == 1 )) && [[ $1 =~ ^[a-f0-9]{64}$ ]]; }

# Stage-9 diagnostic evidence is deliberately OUTSIDE every lifecycle root.
# Nothing in admission, cleanup, recovery or disconnect reads this directory.
# A record may explain a failed C13 attempt, but can never grant authority.
mvc24gc13_diagnostic_root() { printf '%s\n' /run/mvc-diagnostics; }

mvc24gc13_diag_hash_value() {
    (( $# == 1 )) || return 1
    [[ -n $1 ]] || { printf '%s\n' -; return 0; }
    printf '%s' "$1" | sha256sum | awk '{print $1}'
}

mvc24gc13_publish_failure_diagnostic() {
    (( $# == 0 )) || return 1
    local root file tmp boot userns netns mntns clone attempt_sha
    local expected_nm observed_nm expected_route observed_route expected_dns observed_dns
    [[ -f /run/mvc-output-transition/attempt && ! -L /run/mvc-output-transition/attempt ]] || return 1
    clone=${MVC24GC7_CLONE_UUID:-}
    mvc24ga_uuid_valid "$clone" || return 1
    root=$(mvc24gc13_diagnostic_root) || return 1
    [[ $root == /* && $(stat -f -c %T /run) == tmpfs ]] || return 1
    if [[ -e $root || -L $root ]]; then
        [[ -d $root && ! -L $root && $(stat -c '%u:%a' -- "$root") == 0:700 ]] || return 1
    else
        (umask 077; mkdir -m 700 -- "$root") || return 1
    fi
    file=$root/c13-$clone
    [[ ! -e $file && ! -L $file ]] || return 1
    tmp=$(umask 077; mktemp "$root/.c13-$clone.XXXXXXXX") || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    userns=$(readlink /proc/self/ns/user) || return 1
    netns=$(readlink /proc/self/ns/net) || return 1
    mntns=$(readlink /proc/self/ns/mnt) || return 1
    attempt_sha=$(mvc24gc13_hash_file /run/mvc-output-transition/attempt) || return 1
    expected_nm=$(mvc24gc13_diag_hash_value "${MVC24GC18_NM_FINGERPRINT:-}") || return 1
    observed_nm=$(mvc24gc13_diag_hash_value "${MVC24GC18_OBS_NM_FINGERPRINT:-}") || return 1
    expected_route=$(mvc24gc13_diag_hash_value "${MVC24GC18_ROUTE_FINGERPRINT:-}") || return 1
    observed_route=$(mvc24gc13_diag_hash_value "${MVC24GC18_OBS_ROUTE_FINGERPRINT:-}") || return 1
    expected_dns=$(mvc24gc13_diag_hash_value "${MVC24GC18_DNS_FINGERPRINT:-}") || return 1
    observed_dns=$(mvc24gc13_diag_hash_value "${MVC24GC18_OBS_DNS_FINGERPRINT:-}") || return 1
    if ! printf '%s\n' \
      mvc-c13-diagnostic-v1 \
      authority=none-non-authoritative-diagnostic-only \
      "boot=$boot" "userns=$userns" "netns=$netns" "mntns=$mntns" \
      "clone_uuid=$clone" "c13_attempt_sha=$attempt_sha" \
      "c13_stage=${MVC24GC13_STAGE:-unknown}" \
      "c13_detail_stage=${MVC24GC13_DETAIL_STAGE:-unknown}" \
      "nft_commit_rc=${MVC24GC13_NFT_COMMIT_RC:--}" \
      "c18_stage=${MVC24GC18_STAGE:-unknown}" \
      "c18_detail_stage=${MVC24GC18_DETAIL_STAGE:-unknown}" \
      "c18_recheck_failure=${MVC24GC18_RECHECK_FAILURE:-none}" \
      "c18_dns_capture_detail=${MVC24GC18_DNS_CAPTURE_DETAIL:--}" \
      "expected_nm_sha=$expected_nm" "observed_nm_sha=$observed_nm" \
      "expected_route_sha=$expected_route" "observed_route_sha=$observed_route" \
      "expected_dns_sha=$expected_dns" "observed_dns_sha=$observed_dns" \
      "expected_nss_mode=${MVC24GC18_NSS_MODE:--}" \
      "observed_nss_mode=${MVC24GC18_OBS_NSS_MODE:--}" > "$tmp"; then
        rm -f -- "$tmp" >/dev/null 2>&1 || :
        return 1
    fi
    chmod 400 -- "$tmp" || { rm -f -- "$tmp" >/dev/null 2>&1 || :; return 1; }
    if ! mv -T -- "$tmp" "$file"; then
        rm -f -- "$tmp" >/dev/null 2>&1 || :
        return 1
    fi
    [[ $(stat -c '%u:%a:%h' -- "$file") == 0:400:1 ]] || return 1
    MVC24GC13_DIAGNOSTIC_FILE=$file
}
mvc24gc13_hash_file() {
    (( $# == 1 )) || return 1
    local hash
    hash=$(sha256sum -- "$1") || return 1
    hash=${hash%% *}
    mvc24gc13_sha_valid "$hash" || return 1
    printf '%s\n' "$hash"
}

# Immutable intent is stamped before nft --file, not after. The explicit
# C7/C1 digests and same-boot namespaces prevent attributing an old intent
# to a new transaction. This is an ambiguity record, never a grant.
mvc24gc13_intent_valid() {
    (( $# == 0 )) || return 1
    local dir boot userns netns mntns c7 c1 candidate
    local -a records=() entries=()
    dir=$(mvc24gc13_runtime) || return 1
    [[ $dir == /run/mvc-output-transition ]] || return 1
    [[ -d $dir && ! -L $dir && $(stat -c '%u:%a:%h' -- "$dir") == 0:700:2 ]] || return 1
    mapfile -d '' -t entries < <(find "$dir" -mindepth 1 -maxdepth 1 -print0) || return 1
    (( ${#entries[@]} == 1 )) && [[ ${entries[0]} == "$dir/attempt" ]] || return 1
    [[ -f $dir/attempt && ! -L $dir/attempt &&
       $(stat -c '%u:%a:%h' -- "$dir/attempt") == 0:400:1 ]] || return 1
    mapfile -t records < "$dir/attempt" || return 1
    (( ${#records[@]} == 11 )) || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    userns=$(readlink /proc/self/ns/user) || return 1
    netns=$(readlink /proc/self/ns/net) || return 1
    mntns=$(readlink /proc/self/ns/mnt) || return 1
    c7=$(mvc24gc13_hash_file /run/mvc-activation/attempt) || return 1
    c1=$(mvc24gc13_hash_file /run/mvc-controller/transition-attempt) || return 1
    [[ ${records[0]} == mvc-c13-output-transition-attempt-v1 &&
       ${records[1]} == state=nft-commit-attempted-outcome-uncertain &&
       ${records[2]} == "boot=$boot" &&
       ${records[3]} == "userns=$userns" &&
       ${records[4]} == "netns=$netns" &&
       ${records[5]} == "mntns=$mntns" &&
       ${records[6]} == "c7=$c7" &&
       ${records[7]} == "c1=$c1" &&
       ${records[8]} == candidate_sha=* &&
       ${records[9]} == "tunnel=${MVC24GC11_TUNNEL:-}|source=${MVC24GC11_TUNNEL_SOURCE:-}" &&
       ${records[10]} == "nm_owner=${MVC24GC7_NM_OWNER:-}" ]] || return 1
    candidate=${records[8]#candidate_sha=}
    mvc24gc13_sha_valid "$candidate" &&
      mvc24gc11_valid_tunnel_ifname "${MVC24GC11_TUNNEL:-}" &&
      mvc24gc1_ipv4 "${MVC24GC11_TUNNEL_SOURCE:-}" &&
      mvc24gc7_nm_owner_valid "${MVC24GC7_NM_OWNER:-}"
}

# Bind the immutable attempt to the exact prospective nft batch immediately
# before invocation; neither a swapped file nor a changed intent can proceed.
mvc24gc13_candidate_matches_intent() {
    (( $# == 1 )) || return 1
    local candidate=$1 hash recorded
    mvc24gc13_intent_valid || return 1
    [[ -f $candidate && ! -L $candidate && -O $candidate &&
       $(stat -c '%a:%h' -- "$candidate") == 600:1 ]] || return 1
    hash=$(mvc24gc13_hash_file "$candidate") || return 1
    recorded=$(sed -n '9p' /run/mvc-output-transition/attempt) || return 1
    [[ $recorded == "candidate_sha=$hash" ]]
}

mvc24gc13_publish_intent() {
    (( $# == 1 )) || return 1
    local candidate=$1 dir tmp boot userns netns mntns c7 c1 hash
    mvc24gb2_root_scope && mvc24gb2_lock_valid &&
      mvc24gc3_transition_records_valid && mvc24gc7_read_intent &&
      mvc24gc5_guard_witness || return 1
    [[ $(stat -f -c %T /run) == tmpfs &&
       -f $candidate && ! -L $candidate && -O $candidate &&
       $(stat -c '%a:%h' -- "$candidate") == 600:1 ]] || return 1
    dir=$(mvc24gc13_runtime) || return 1
    [[ $dir == /run/mvc-output-transition && ! -e $dir && ! -L $dir ]] || return 1
    boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    userns=$(readlink /proc/self/ns/user) || return 1
    netns=$(readlink /proc/self/ns/net) || return 1
    mntns=$(readlink /proc/self/ns/mnt) || return 1
    c7=$(mvc24gc13_hash_file /run/mvc-activation/attempt) || return 1
    c1=$(mvc24gc13_hash_file /run/mvc-controller/transition-attempt) || return 1
    hash=$(mvc24gc13_hash_file "$candidate") || return 1
    (umask 077; mkdir -m 700 -- "$dir") || return 1
    tmp=$(umask 077; mktemp "$dir/.attempt.XXXXXXXX") || return 1
    if ! printf '%s\n' \
        mvc-c13-output-transition-attempt-v1 \
        state=nft-commit-attempted-outcome-uncertain \
        "boot=$boot" "userns=$userns" "netns=$netns" "mntns=$mntns" \
        "c7=$c7" "c1=$c1" "candidate_sha=$hash" \
        "tunnel=$MVC24GC11_TUNNEL|source=$MVC24GC11_TUNNEL_SOURCE" \
        "nm_owner=$MVC24GC7_NM_OWNER" > "$tmp"; then return 1; fi
    chmod 400 -- "$tmp" || return 1
    [[ ! -e $dir/attempt && ! -L $dir/attempt ]] || return 1
    mv -T -- "$tmp" "$dir/attempt" || return 1
    mvc24gc13_intent_valid
}

# Strictly observe TWO kernel snapshots post-commit and the previous foreign
# table projection. Never infer that a successful nft exit implies safety.
mvc24gc13_observe_postcommit() {
    (( $# == 2 )) || return 1
    local first=$1 second=$2 pre foreign1 foreign2
    [[ -f $first && -f $second && ! -L $first && ! -L $second ]] || return 1
    cmp -s -- "$first" "$second" || return 1
    mvc24gc13_intent_valid && mvc24gb2_root_scope && mvc24gb2_lock_valid &&
      mvc24gc3_transition_records_valid || return 1
    mvc24gc11_postshape_observation "$first" "$MVC24GC3_IFACE" "$MVC24GC3_SOURCE" \
      "$MVC24GC3_REMOTE" "$MVC24GC3_PORT" "$MVC24GC11_TUNNEL" "$MVC24GC11_TUNNEL_SOURCE" &&
    mvc24gc11_postshape_observation "$second" "$MVC24GC3_IFACE" "$MVC24GC3_SOURCE" \
      "$MVC24GC3_REMOTE" "$MVC24GC3_PORT" "$MVC24GC11_TUNNEL" "$MVC24GC11_TUNNEL_SOURCE" || return 1
    pre=$(mvc24gb2_runtime) || return 1
    [[ $pre == /run/mvc-controller ]] || return 1
    foreign1=$(mvc24gb2_foreign_projection "$pre/prestate.json") || return 1
    foreign2=$(mvc24gb2_foreign_projection "$first") || return 1
    [[ $foreign1 == "$foreign2" ]] &&
      mvc24gc13_intent_valid && mvc24gb2_lock_valid
}

# Deliberately UNREACHABLE on physical hosts: admission witness always
# returns 1 unless replaced in an isolated unit test. Do not unlock until
# secret custody, prompt controls, DNS and recovery are independently proven.
mvc24gc13_execute_once() {
    (( $# == 0 )) || return 1
    [[ ${MVC24GC13_ATTEMPTED:-no} == no ]] || return 1
    MVC24GC13_ATTEMPTED=yes
    MVC24GC13_STAGE=refused-or-unverified
    MVC24GC13_DETAIL_STAGE=admission-witness
    MVC24GC13_AUTHORITY=none
    mvc24gc13_admission_witness || return 1
    MVC24GC13_DETAIL_STAGE=upstream-stage-contract
    [[ ${MVC24GC9_STAGE:-} == active-nm-ipv4-observed-endpoint-only-guard &&
       ${MVC24GC9_AUTHORITY:-} == none &&
       ${MVC24GC7_STAGE:-} == active-nm-and-ipv4-observed-bootstrap-only &&
       ${MVC24GC7_AUTHORITY:-} == none ]] || return 1
    MVC24GC13_DETAIL_STAGE=controller-and-c1-witness
    mvc24gb2_root_scope && mvc24gb2_lock_valid &&
      mvc24gc3_transition_records_valid && mvc24gc5_guard_witness &&
      mvc24gc7_read_intent || return 1
    MVC24GC13_DETAIL_STAGE=runtime-scratch-prerequisites
    [[ ! -e /run/mvc-output-transition && ! -L /run/mvc-output-transition &&
       -d /dev/shm && $(stat -f -c %T /dev/shm) == tmpfs ]] || return 1
    local scratch batch first second nm_now route_now success=1
    MVC24GC13_DETAIL_STAGE=scratch-create
    scratch=$(umask 077; mktemp -d /dev/shm/mvc-c13.XXXXXXXX) || return 1
    [[ -d $scratch && ! -L $scratch && -O $scratch &&
       $(stat -c %a -- "$scratch") == 700 ]] || return 1
    batch=$scratch/transition.nft first=$scratch/first.json second=$scratch/second.json
    (umask 077; set -C; : > "$batch") || return 1
    chmod 600 -- "$batch" || return 1
    MVC24GC13_DETAIL_STAGE=c11-candidate-generation
    if ! mvc24gc11_candidate_after_c9 "$batch"; then
        success=0
    elif [[ ${MVC24GC11_STAGE:-} != prospective-ipv4-host-tunnel-output-only-no-commit-authority ||
            ${MVC24GC11_AUTHORITY:-} != none ]]; then
        MVC24GC13_DETAIL_STAGE=c11-candidate-contract
        success=0
    else
        MVC24GC13_DETAIL_STAGE=nft-check
        nft --check --file "$batch" >/dev/null 2>&1 || success=0
    fi
    if (( success == 1 )); then
        MVC24GC13_DETAIL_STAGE=c1-guard-revalidate
        mvc24gc5_guard_witness || success=0
    fi
    if (( success == 1 )); then
        MVC24GC13_DETAIL_STAGE=c7-intent-revalidate
        mvc24gc7_read_intent || success=0
    fi
    # Re-read NM and both kernel route selections immediately before intent.
    # An unchanged nft guard does not by itself attest the tunnel still exists.
    if (( success == 1 )); then
        MVC24GC13_DETAIL_STAGE=nm-snapshot-recheck
        nm_now=$(mvc24gc6_nm_ipv4_snapshot "$MVC24GC7_CLONE_UUID" "$MVC24GC7_NM_OWNER") || success=0
    fi
    if (( success == 1 )); then
        MVC24GC13_DETAIL_STAGE=kernel-route-recheck
        route_now=$(mvc24gc6_kernel_ipv4_snapshot "$MVC24GC3_IFACE" "$MVC24GC3_SOURCE" "$MVC24GC3_REMOTE") || success=0
    fi
    if (( success == 1 )); then
        MVC24GC13_DETAIL_STAGE=nm-route-snapshot-compare
        [[ ${nm_now:-} == "${MVC24GC6_NM_SNAPSHOT:-missing}" &&
           ${route_now:-} == "${MVC24GC6_ROUTE_SNAPSHOT:-missing}" ]] || success=0
    fi
    # No unrestricted tunnel-bound OUTPUT until DNS is observed twice
    # under the still-active, endpoint-only C1 guard. This is a read-only
    # witness, not proof that DNS will stay immutable after the commit.
    if (( success == 1 )); then
        MVC24GC13_DETAIL_STAGE=c18-precommit-dns
        mvc24gc18_precommit_locked &&
          [[ ${MVC24GC18_STAGE:-} == precommit-dns-and-c1-quarantine-observed-no-authority &&
             ${MVC24GC18_AUTHORITY:-} == none ]] || success=0
    fi
    if (( success == 1 )); then
        # After this succeeds, a lost nft reply MUST remain ambiguous.
        MVC24GC13_DETAIL_STAGE=publish-intent
        mvc24gc13_publish_intent "$batch" &&
          mvc24gc13_candidate_matches_intent "$batch" || success=0
    fi
    if (( success == 1 )); then
        MVC24GC13_DETAIL_STAGE=c18-post-intent-recheck
        # Recheck the identical DNS/NM/route evidence and C1 guard after
        # intent sealing, immediately before the SINGLE atomic commit.
        mvc24gc18_recheck_locked &&
          [[ ${MVC24GC18_STAGE:-} == precommit-dns-rechecked-under-c1-no-authority &&
             ${MVC24GC18_AUTHORITY:-} == none ]] || success=0
    fi
    if (( success == 1 )); then
        MVC24GC13_DETAIL_STAGE=nft-commit
        MVC24GC13_STAGE=atomic-commit-attempted-uncertain
        if nft --file "$batch" >/dev/null 2>&1; then
            MVC24GC13_NFT_COMMIT_RC=0
        else
            MVC24GC13_NFT_COMMIT_RC=$?
            success=0
        fi
    fi
    if (( success == 1 )); then
        MVC24GC13_DETAIL_STAGE=postcommit-observation
        mvc24gb1_capture_nft "$first" && mvc24gb1_capture_nft "$second" &&
          mvc24gc13_observe_postcommit "$first" "$second" || success=0
    fi
    if ! rm -f -- "$batch" "$first" "$second"; then
        MVC24GC13_DETAIL_STAGE=scratch-cleanup
        success=0
    fi
    if ! rmdir -- "$scratch"; then
        MVC24GC13_DETAIL_STAGE=scratch-cleanup
        success=0
    fi
    if (( success == 1 )); then
        MVC24GC13_DETAIL_STAGE=complete
        MVC24GC13_STAGE=atomic-ipv4-tunnel-output-observed-dns-unverified
        MVC24GC13_AUTHORITY=none
        return 0
    fi
    # Best-effort Stage-9 evidence only. Failure to publish diagnostics MUST
    # NOT alter the C13 result or cleanup/recovery authority.
    mvc24gc13_publish_failure_diagnostic >/dev/null 2>&1 || :
    return 1
}
